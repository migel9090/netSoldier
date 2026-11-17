package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/export"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/guard"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/misp"
	"github.com/migel9090/netSoldier/libs/indicator"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration, refusing to start", "error", err)
		os.Exit(1)
	}

	store, err := openStore(cfg)
	if err != nil {
		slog.Error("indicator store unavailable, refusing to start", "path", cfg.dbPath, "error", err)
		os.Exit(1)
	}
	defer store.Close()

	g := guard.New(store, cfg.volume, cfg.sourceNames(), cfg.storeMax)
	initSourceMetrics(cfg, store.FeedSuccess())
	initGuardMetrics(cfg, g)
	fresh.configure(cfg.freshnessObjectives(), store.FeedSuccess)
	storeCapacity.Set(float64(cfg.storeMax))
	storeSize.Set(float64(store.Len()))

	ready := newReadiness(store)
	if store.Len() > 0 {
		// The last good set is served straight away; feeds refresh it as
		// they answer. A restart during a feed outage no longer empties
		// every consumer's list.
		ready.trust()
		slog.Info("serving persisted indicator set", "indicators", store.Len())
	}
	if len(cfg.sources) == 0 {
		slog.Error("no sources enabled")
	}
	logGuardState(cfg, g)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go newScheduler(cfg, store, g, ready).run(ctx)

	srv := &http.Server{
		Addr:         cfg.listenAddr,
		Handler:      newService(cfg, store, g, ready).routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting threat-intel-sync", "addr", cfg.listenAddr, "sync_interval", cfg.syncInterval,
			"sources", cfg.sourceNames(), "persistent", store.Persistent())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down", "ioc_count", store.Len())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

// service is what the HTTP routes serve from.
type service struct {
	store   *ioc.Store
	ready   *readiness
	guard   *guard.Manager
	adguard *export.AdGuard
	op      *operatorAPI
	sources []string
}

func newService(cfg config, store *ioc.Store, g *guard.Manager, ready *readiness) *service {
	svc := &service{store: store, ready: ready, guard: g, sources: cfg.sourceNames()}
	enabled := make(map[string]bool, len(cfg.sources))
	for _, s := range cfg.sources {
		enabled[s.name] = true
	}
	svc.op = &operatorAPI{key: cfg.apiKey, guard: g, store: store, ready: ready, sources: enabled}
	svc.adguard = export.NewAdGuard(store, export.AdGuardOptions{
		Expires: cfg.syncInterval,
		Status: func() export.AdGuardStatus {
			return export.AdGuardStatus{Quarantined: svc.quarantinedSources(), Stale: fresh.stale()}
		},
	})
	return svc
}

func (svc *service) quarantinedSources() []string {
	var out []string
	for _, h := range svc.guard.Held() {
		out = append(out, h.Feed)
	}
	return out
}

// routes serves the probes, the metrics, the quarantine API and every
// export, the exports behind the readiness gate.
func (svc *service) routes() *http.ServeMux {
	store := svc.store
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", svc.handleReadyz)
	svc.op.register(mux)
	for path, h := range map[string]http.HandlerFunc{
		"/export/adguard":               svc.adguard.ServeHTTP,
		"/export/suricata/domains":      export.HandleSuricataDataset(store, true, ioc.TypeDomain),
		"/export/suricata/ips":          export.HandleSuricataDataset(store, false, ioc.TypeIP),
		"/export/suricata/domains.json": export.HandleSuricataJSONDataset(store, "domain", ioc.TypeDomain),
		"/export/suricata/ips.json":     export.HandleSuricataJSONDataset(store, "ip", ioc.TypeIP),
		"/export/suricata/md5":          export.HandleSuricataDataset(store, false, ioc.TypeMD5),
		"/export/suricata/sha256":       export.HandleSuricataDataset(store, false, ioc.TypeSHA256),
		"/export/zeek/intel.dat":        export.HandleZeekIntel(store),
		"/export/json":                  export.HandleJSON(store),
		"/export/csv":                   export.HandleCSV(store, ioc.TypeDomain, ioc.TypeIP),
	} {
		mux.HandleFunc("GET "+path, requireReady(svc.ready, h))
	}
	mux.Handle("GET /metrics", promhttp.Handler())
	return mux
}

// openStore opens the durable store when INDICATOR_DB_PATH is set, and drops
// what disabled sources asserted: a persisted set must not keep serving a
// feed that has since been switched off (COMMERCIAL_MODE in particular).
func openStore(cfg config) (*ioc.Store, error) {
	opts := []ioc.Option{ioc.WithMaxIndicators(cfg.storeMax)}
	if cfg.dbPath == "" {
		slog.Warn("INDICATOR_DB_PATH not set: indicator store is memory-only; after a restart " +
			"exports answer 503 until a feed has answered")
		storePersistent.Set(0)
		return ioc.NewStore(opts...), nil
	}
	store, ls, err := ioc.OpenStore(cfg.dbPath, opts...)
	if err != nil {
		return nil, err
	}
	storePersistent.Set(1)
	removed := store.RetainFeeds(cfg.sourceNames())
	slog.Info("indicator database loaded", "path", cfg.dbPath, "assertions", ls.Loaded,
		"invalid_deleted", ls.Invalid, "never_block_deleted", ls.NeverBlock, "over_cap_deleted", ls.Dropped,
		"held_fetches", ls.Held, "removed_from_disabled_sources", removed, "indicators", store.Len())
	return store, nil
}

// requireReady answers 503 until there is a set worth serving. Every
// consumer (the Zeek and Vector sidecars with curl -f, the Suricata updater,
// the detection-engine's sync) keeps its previous list on a non-200, so
// "not yet" no longer reads as "the list is empty".
func requireReady(r *readiness, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if ok, reason := r.Ready(); !ok {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "threat intel not ready: "+reason, http.StatusServiceUnavailable)
			return
		}
		next(w, req)
	}
}

// handleHealthz is the liveness probe: the process is up and serving HTTP.
// It deliberately says nothing about the intel; that is /readyz.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// sourceReadiness is one source's line in /readyz.
type sourceReadiness struct {
	sourceFreshness
	Quarantined bool `json:"quarantined"`
}

// handleReadyz is the readiness probe: 200 once exports are served, 503
// before. Its body also reports each source's freshness and quarantine
// state. A stale or quarantined source does not make the service unready:
// the set already being served is still the best there is, and taking the
// exports away would hurt every consumer for one feed's sake.
func (svc *service) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	ok, reason := svc.ready.Ready()
	held := map[string]bool{}
	for _, h := range svc.guard.Held() {
		held[h.Feed] = true
	}
	freshness := fresh.status()
	sources := make(map[string]sourceReadiness, len(svc.sources))
	stale, quarantinedNames := []string{}, []string{}
	for _, name := range svc.sources {
		f, known := freshness[name]
		if !known {
			f = sourceFreshness{Stale: false}
		}
		sources[name] = sourceReadiness{sourceFreshness: f, Quarantined: held[name]}
		if f.Stale {
			stale = append(stale, name)
		}
		if held[name] {
			quarantinedNames = append(quarantinedNames, name)
		}
	}
	sort.Strings(stale)
	sort.Strings(quarantinedNames)
	body := map[string]any{
		"status": "ready", "indicators": svc.store.Len(),
		"sources": sources, "stale_sources": stale, "quarantined_sources": quarantinedNames,
	}
	w.Header().Set("Content-Type", "application/json")
	if !ok {
		body["status"] = "not ready"
		body["reason"] = reason
		if len(quarantinedNames) > 0 {
			body["hint"] = "a source's fetch is held by the volume guard: see GET /quarantine"
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(body)
}

// logGuardState says once, at start-up, what protects the exports.
func logGuardState(cfg config, g *guard.Manager) {
	nb := indicator.NeverBlockList()
	slog.Info("never-block list loaded", "entries", nb.Entries, "snapshot", nb.Snapshot, "by_reason", nb.ByReason)
	l := cfg.volume
	slog.Info("volume guard", "growth_factor", l.GrowthFactor, "shrink_factor", l.ShrinkFactor,
		"min_change", l.MinChange, "first_sync_max", l.FirstSyncMax, "history", guard.HistoryLen)
	for _, src := range cfg.sources {
		base, known := g.Baseline(src.name)
		slog.Info("source", "source", src.name, "endpoint", src.endpoint,
			"freshness_objective", src.maxAge, "volume_baseline", base, "volume_history", known)
	}
	for _, h := range g.Held() {
		slog.Error("QUARANTINE: a fetch held before the restart is still held; the previous set is served",
			"source", h.Feed, "reason", h.Reason, "detail", h.Detail, "size", h.Size, "id", h.ID,
			"held_at", h.HeldAt)
	}
	if cfg.apiKey == "" {
		slog.Warn("THREAT_INTEL_API_KEY not set: the quarantine API answers 403; a held fetch can " +
			"then only be superseded by a passing one, not released or discarded")
	}
}

func mispToIndicators(attrs []misp.Attribute) []ioc.Indicator {
	indicators := make([]ioc.Indicator, 0, len(attrs))
	for _, a := range attrs {
		iocType := mapMISPType(a.Type)
		if iocType == "" {
			continue
		}
		var tags []string
		for _, t := range a.Tags {
			tags = append(tags, t.Name)
		}
		indicators = append(indicators, ioc.Indicator{
			Type:      iocType,
			Value:     a.Value,
			Source:    "misp",
			Threat:    a.Comment,
			FirstSeen: a.Time(),
			Tags:      tags,
		})
	}
	return indicators
}

func mapMISPType(t string) string {
	switch t {
	case misp.TypeDomain, misp.TypeHostname:
		return ioc.TypeDomain
	case misp.TypeIPDst, misp.TypeIPSrc:
		return ioc.TypeIP
	case misp.TypeURL:
		return ioc.TypeURL
	case misp.TypeMD5:
		return ioc.TypeMD5
	case misp.TypeSHA256:
		return ioc.TypeSHA256
	case misp.TypeJA3:
		return ioc.TypeJA3
	case misp.TypeX509SHA1:
		return ioc.TypeCertSHA1
	case misp.TypeX509SHA256:
		return ioc.TypeCertSHA256
	default:
		return ""
	}
}
