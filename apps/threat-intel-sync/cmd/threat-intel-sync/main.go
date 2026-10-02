package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/abusech"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/export"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/misp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/spamhaus"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type source struct {
	name  string
	fetch func(context.Context) ([]ioc.Indicator, error)
}

var (
	// This service had no /metrics endpoint at all, which meant feed health
	// was unobservable: a sync that had been failing for weeks looked
	// exactly like a quiet network. Stale threat intel is a silent
	// detection gap, so it needs to be a number someone can alert on.
	syncLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_last_success_timestamp_seconds",
		Help:      "Unix timestamp of the last successful fetch per source.",
	}, []string{"source"})
	syncFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_failures_total",
		Help:      "Feed fetch failures per source.",
	}, []string{"source"})
	indicatorsFetched = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_indicators",
		Help:      "Indicators accepted from the most recent successful fetch per source.",
	}, []string{"source"})
	indicatorsRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_indicators_rejected_total",
		Help:      "Indicators dropped as unsafe or malformed per source.",
	}, []string{"source"})
	storeSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "store_indicators",
		Help:      "Total unique indicators currently in the store.",
	})
	indicatorsPruned = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "indicators_pruned_total",
		Help:      "Indicators removed because no feed has re-asserted them.",
	})
	cycleLastComplete = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "sync_cycle_last_complete_timestamp_seconds",
		Help:      "Unix timestamp of the last completed sync cycle.",
	})
)

func init() {
	prometheus.MustRegister(syncLastSuccess, syncFailures, indicatorsFetched,
		indicatorsRejected, storeSize, indicatorsPruned, cycleLastComplete)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	store := ioc.NewStore()
	sources := configureSources()

	syncInterval := parseDuration(envOr("SYNC_INTERVAL", "6h"), 6*time.Hour)
	// Indicators a feed has stopped asserting age out. Default 30 days,
	// comfortably more than several sync intervals, so a transient feed
	// outage never drops live intel.
	indicatorTTL := parseDuration(envOr("INDICATOR_TTL", "720h"), 30*24*time.Hour)
	go runSyncLoop(ctx, store, sources, syncInterval, indicatorTTL)

	addr := envOr("LISTEN_ADDR", ":8083")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /export/adguard", export.HandleAdGuard(store))
	mux.HandleFunc("GET /export/suricata/domains", export.HandleSuricataDataset(store, true, ioc.TypeDomain))
	mux.HandleFunc("GET /export/suricata/ips", export.HandleSuricataDataset(store, false, ioc.TypeIP))
	mux.HandleFunc("GET /export/suricata/domains.json", export.HandleSuricataJSONDataset(store, "domain", ioc.TypeDomain))
	mux.HandleFunc("GET /export/suricata/ips.json", export.HandleSuricataJSONDataset(store, "ip", ioc.TypeIP))
	mux.HandleFunc("GET /export/suricata/md5", export.HandleSuricataDataset(store, false, ioc.TypeMD5))
	mux.HandleFunc("GET /export/suricata/sha256", export.HandleSuricataDataset(store, false, ioc.TypeSHA256))
	mux.HandleFunc("GET /export/zeek/intel.dat", export.HandleZeekIntel(store))
	mux.HandleFunc("GET /export/json", export.HandleJSON(store))
	mux.HandleFunc("GET /export/csv", export.HandleCSV(store, ioc.TypeDomain, ioc.TypeIP))
	mux.Handle("GET /metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting threat-intel-sync", "addr", addr, "sync_interval", syncInterval)
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

func configureSources() []source {
	var sources []source

	if mispURL := os.Getenv("MISP_URL"); mispURL != "" {
		key := envOr("MISP_API_KEY", "")
		if key == "" {
			slog.Error("MISP_URL set but MISP_API_KEY is empty")
			os.Exit(1)
		}
		client := misp.NewClient(mispURL, key)
		sources = append(sources, source{
			name: "misp",
			fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
				attrs, err := client.FetchAllAttributes(ctx, misp.SearchRequest{
					Types: []string{
						misp.TypeDomain, misp.TypeHostname,
						misp.TypeIPDst, misp.TypeIPSrc,
						misp.TypeURL, misp.TypeMD5, misp.TypeSHA256, misp.TypeJA3,
						misp.TypeX509SHA1, misp.TypeX509SHA256,
					},
					Published: true,
					Timestamp: envOr("MISP_LOOKBACK", "7d"),
					ToIDs:     true,
				})
				if err != nil {
					return nil, err
				}
				return mispToIndicators(attrs), nil
			},
		})
		slog.Info("source configured", "source", "misp", "url", mispURL)
	}

	// abuse.ch feeds (ThreatFox / URLhaus / Feodo) dropped their CC0
	// dedication in 2025; the current terms of use restrict free access to
	// non-commercial use (commercial use needs a paid Spamhaus subscription).
	// They are ON by default for the project's primary home/non-commercial
	// use, and disabled when COMMERCIAL_MODE=true so a commercial deployment
	// ships clean. See COMPLIANCE.md.
	if commercialModeEnabled() {
		slog.Info("COMMERCIAL_MODE on: abuse.ch feeds (ThreatFox/URLhaus/Feodo) disabled (non-commercial terms)")
	} else {
		slog.Warn("abuse.ch feeds enabled (ThreatFox/URLhaus/Feodo): non-commercial use only — set COMMERCIAL_MODE=true to disable for commercial deployments")

		tfClient := abusech.NewThreatFoxClient()
		tfDays := parseIntOr(envOr("THREATFOX_DAYS", "7"), 7)
		sources = append(sources, source{
			name: "threatfox",
			fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
				return tfClient.Fetch(ctx, tfDays)
			},
		})

		uhClient := abusech.NewURLhausClient()
		uhLimit := parseIntOr(envOr("URLHAUS_LIMIT", "1000"), 1000)
		sources = append(sources, source{
			name: "urlhaus",
			fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
				return uhClient.Fetch(ctx, uhLimit)
			},
		})

		feClient := abusech.NewFeodoClient()
		sources = append(sources, source{
			name: "feodo",
			fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
				return feClient.Fetch(ctx)
			},
		})
	}

	// Spamhaus DROP is free for commercial use too (attribution required,
	// see COMPLIANCE.md), so it stays enabled regardless of COMMERCIAL_MODE.
	spClient := spamhaus.NewClient()
	sources = append(sources, source{
		name: "spamhaus",
		fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
			return spClient.FetchAll(ctx)
		},
	})

	slog.Info("sources ready", "count", len(sources))
	return sources
}

func runSyncLoop(ctx context.Context, store *ioc.Store, sources []source,
	interval, indicatorTTL time.Duration) {
	slog.Info("sync loop started", "interval", interval, "sources", len(sources),
		"indicator_ttl", indicatorTTL)
	syncOnce(ctx, store, sources, indicatorTTL)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce(ctx, store, sources, indicatorTTL)
		}
	}
}

func syncOnce(ctx context.Context, store *ioc.Store, sources []source, indicatorTTL time.Duration) {
	slog.Info("sync cycle starting")
	anySucceeded := false

	for _, src := range sources {
		indicators, err := src.fetch(ctx)
		if err != nil {
			syncFailures.WithLabelValues(src.name).Inc()
			slog.Error("source failed", "source", src.name, "error", err)
			continue
		}

		accepted, rejected := store.UpsertAll(indicators)
		anySucceeded = true
		syncLastSuccess.WithLabelValues(src.name).SetToCurrentTime()
		indicatorsFetched.WithLabelValues(src.name).Set(float64(accepted))
		if rejected > 0 {
			indicatorsRejected.WithLabelValues(src.name).Add(float64(rejected))
			slog.Warn("source returned unusable indicators",
				"source", src.name, "rejected", rejected, "accepted", accepted)
		}
		slog.Info("source synced", "source", src.name, "fetched", len(indicators),
			"accepted", accepted, "rejected", rejected, "store_total", store.Len())
	}

	// Only expire indicators after at least one feed answered. Pruning on a
	// cycle where everything failed would quietly empty the store during an
	// outage — exactly when detection coverage matters most.
	if anySucceeded && indicatorTTL > 0 {
		if n := store.PruneBefore(time.Now().UTC().Add(-indicatorTTL)); n > 0 {
			indicatorsPruned.Add(float64(n))
			slog.Info("pruned stale indicators", "removed", n, "ttl", indicatorTTL)
		}
	}

	storeSize.Set(float64(store.Len()))
	cycleLastComplete.SetToCurrentTime()
	slog.Info("sync cycle complete", "store_total", store.Len(), "any_source_succeeded", anySucceeded)
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

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// commercialModeEnabled reports whether the deployment must exclude data
// sources whose terms forbid commercial use (see COMPLIANCE.md).
func commercialModeEnabled() bool {
	switch strings.ToLower(os.Getenv("COMMERCIAL_MODE")) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

func parseIntOr(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
