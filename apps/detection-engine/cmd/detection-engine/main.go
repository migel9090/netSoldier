package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/composite"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/devices"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/dnscache"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/feedback"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/pipeline"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/tlsheur"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/tracing"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/webhook"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	// defaultDBPath is where the local store lives unless DB_PATH says
	// otherwise; the deployment mounts a volume at its directory.
	defaultDBPath = "/var/lib/detection-engine/detection-engine.db"
	// shutdownFlush bounds how long a clean shutdown keeps delivering the
	// outbox. What is not delivered by then stays on disk.
	shutdownFlush = 5 * time.Second
	// producerStop bounds the wait for pollers to finish their current poll.
	producerStop = 5 * time.Second
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	otelEndpoint := envOr(os.Getenv, "OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector.observability.svc:4317")
	tp, err := tracing.Init(ctx, "detection-engine", otelEndpoint)
	if err != nil {
		slog.Warn("tracing disabled", "error", err)
	} else {
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tp.Shutdown(sctx); err != nil {
				slog.Error("tracer shutdown error", "error", err)
			}
		}()
	}

	if err := run(ctx, os.Getenv, nil); err != nil {
		slog.Error("detection-engine failed", "error", err)
		stop()
		os.Exit(1)
	}
}

// run builds the service from its environment and serves until ctx ends.
// Shutdown stops accepting requests, lets the pollers finish, then flushes
// the outbox for at most shutdownFlush and leaves the rest on disk for the
// next start. onListen, when set, receives the bound address.
func run(ctx context.Context, getenv func(string) string, onListen func(addr string)) error {
	env := func(key, fallback string) string { return envOr(getenv, key, fallback) }

	// Detection ids carry a per-process prefix so they stay unique across
	// restarts. Overridable for deployments that want a stable, readable
	// instance name; it must be alphanumeric.
	if p := getenv("DETECTION_ID_PREFIX"); p != "" {
		if err := detection.SetIDPrefix(p); err != nil {
			slog.Warn("invalid DETECTION_ID_PREFIX, using a generated prefix", "error", err)
		}
	}
	slog.Info("detection id prefix", "prefix", detection.IDPrefix())

	st, err := openStore(getenv)
	if err != nil {
		return err
	}
	defer func() {
		if err := st.Close(); err != nil {
			slog.Error("closing the local store failed", "error", err)
		}
	}()
	alerts := st.Alerts(parseDuration(env("ALERT_RETENTION", "720h"), store.DefaultAlertRetention), 0)

	// One ClickHouse client for sensor reads and feedback writes.
	var ch *clickhouse.Client
	if cfg, ok := clickhouse.ConfigFromEnv(getenv); ok {
		if ch, err = clickhouse.New(cfg); err != nil {
			slog.Error("ClickHouse disabled: sensor ingest and the feedback history copy are off", "error", err)
		} else {
			if !ch.Authenticated() {
				slog.Warn("CLICKHOUSE_USER is not set: ClickHouse will treat this service as its " +
					"`default` user, which the deployment grants nothing to")
			}
			slog.Info("clickhouse configured", "endpoint", ch.String())
		}
	}

	agClient := adguard.NewClient(
		env("ADGUARD_URL", "http://adguard-web.dns.svc:3000"),
		env("ADGUARD_USER", "admin"),
		env("ADGUARD_PASSWORD", "changeme"),
	)

	matcher := iocmatch.New()
	tlPath := env("THREATLIST_PATH", "/etc/detection-engine/domains.txt")
	if staticIoCs, err := iocmatch.LoadDomainsFromFile(tlPath); err != nil {
		slog.Warn("static threatlist not loaded", "path", tlPath, "error", err)
	} else {
		added, rejected := matcher.Add(staticIoCs)
		if rejected > 0 {
			slog.Warn("static threatlist had unsafe entries that were dropped",
				"path", tlPath, "rejected", rejected)
		}
		slog.Info("static threatlist loaded", "path", tlPath,
			"domains", added, "rejected", rejected)
	}

	// Producers: everything that turns observations into detections. They
	// stop on ctx; shutdown waits for them before the final outbox flush.
	var producers sync.WaitGroup
	goProduce := func(f func()) {
		producers.Add(1)
		go func() { defer producers.Done(); f() }()
	}

	if tiURL := getenv("THREAT_INTEL_URL"); tiURL != "" {
		syncInterval := parseDuration(env("IOC_SYNC_INTERVAL", "5m"), 5*time.Minute)
		goProduce(func() { iocmatch.SyncLoop(ctx, matcher, tiURL, syncInterval) })
	}

	// Where each input resumes after a restart, and how far back it may
	// reach: without a stored position, or with one older than this, reading
	// starts this far back rather than at "now".
	cursors := st.Cursors()
	lookback := parseDuration(env("INGEST_LOOKBACK", "1h"), detection.DefaultLookback)
	records := st.Records(lookback + time.Hour)

	pollInterval := parseDuration(env("POLL_INTERVAL", "30s"), 30*time.Second)
	engine := detection.New(agClient, matcher, pollInterval)
	engine.Cursors = cursors
	engine.Lookback = lookback
	engine.MaxPages = parseInt(env("QUERYLOG_MAX_PAGES", ""), detection.DefaultQueryLogMaxPages)
	engine.Overlap = parseDuration(env("QUERYLOG_OVERLAP", "15s"), detection.DefaultQueryLogOverlap)

	// Which name each client resolved to which address, for the TLS
	// heuristics.
	resolved := dnscache.New(0)
	engine.OnDNSAnswer = resolved.Set

	// Every detection is enriched with the device holding the client
	// address: the killswitch allowlist and composite correlation both key
	// on the MAC.
	devURL := env("DEVICE_INVENTORY_URL", "http://device-inventory:8081")
	devKey := getenv("DEVICE_API_KEY")
	if devKey == "" {
		slog.Warn("DEVICE_API_KEY is not set: an inventory that requires its key will refuse every " +
			"lookup, and detections will carry no client MAC")
	}
	resolver := devices.New(devURL, devKey, parseDuration(env("DEVICE_LOOKUP_TTL", "60s"), devices.DefaultTTL))
	engine.ResolveClient = resolver.Resolve
	slog.Info("client identity from device-inventory", "url", devURL, "authenticated", devKey != "")

	// False-positive feedback loop (step 118): suppressions gate what
	// reaches the killswitch. The verdicts are kept in the local store; with
	// ClickHouse, a copy of each goes there too.
	journal := st.Feedback()
	var forwarder *feedback.Forwarder
	if ch != nil {
		forwarder = feedback.NewForwarder(journal, feedback.NewCHSink(ch))
	}
	fbOpts := feedback.Options{
		TTL:         parseDuration(env("FEEDBACK_SUPPRESSION_TTL", "720h"), feedback.DefaultSuppressionTTL),
		AlertLookup: alerts.ByID,
		Forwarding:  forwarder != nil,
	}
	if forwarder != nil {
		fbOpts.Notify = forwarder.Notify
	}
	feedbackStore := feedback.NewWithOptions(journal, fbOpts)
	{
		// Before any producer starts, so the first detections after a
		// restart are already judged against the analysts' verdicts.
		var history feedback.Querier
		if ch != nil {
			history = ch
		}
		lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		res, err := feedbackStore.Restore(lctx, history)
		cancel()
		if err != nil {
			slog.Warn("feedback restore failed: suppressions start from what could be read", "error", err)
		}
		slog.Info("feedback suppressions restored", "replayed", res.Replayed,
			"imported_from_clickhouse", res.Imported, "active", len(feedbackStore.Active()),
			"durable", journal.Durable())
	}
	forwarderDone := make(chan struct{})
	if forwarder != nil {
		go func() { defer close(forwarderDone); forwarder.Run(ctx) }()
	} else {
		close(forwarderDone)
	}

	// Delivery to the killswitch (or any receiver of the shared contract)
	// through the durable outbox.
	var forward func(detection.Alert)
	var dispatcher *webhook.Dispatcher
	var outbox *store.Outbox
	if webhookURL := getenv("WEBHOOK_URL"); webhookURL != "" {
		window := parseDuration(env("WEBHOOK_AGGREGATION_WINDOW", "10m"), store.DefaultAggregationWindow)
		if outbox, err = st.Outbox(window, 0); err != nil {
			return fmt.Errorf("open outbox: %w", err)
		}
		sender := webhook.NewSender(webhookURL, getenv("WEBHOOK_SECRET"), getenv("WEBHOOK_TOKEN"))
		dispatcher = webhook.NewDispatcher(outbox, sender)
		fw := &pipeline.Forwarder{Outbox: outbox, Notify: dispatcher.Notify}
		forward = fw.Forward
		slog.Info("webhook enabled", "url", webhookURL,
			"signed", getenv("WEBHOOK_SECRET") != "",
			"authenticated", getenv("WEBHOOK_TOKEN") != "",
			"aggregation_window", window, "backlog", outbox.Pending())
	}
	dispatcherDone := make(chan struct{})
	if dispatcher != nil {
		go func() { defer close(dispatcherDone); dispatcher.Run(ctx) }()
	} else {
		close(dispatcherDone)
	}

	// Composite-confidence correlator (step 116): combines corroborating
	// signals per client. The pipeline acts on what it returns.
	compWindow := parseDuration(env("COMPOSITE_WINDOW", "15m"), 15*time.Minute)
	pipe := &pipeline.Pipeline{
		Alerts:    alerts,
		Suppress:  feedbackStore,
		Correlate: composite.New(compWindow, nil),
		Forward:   forward,
		// A record read again — the overlap behind each cursor, the stretch
		// re-read after a restart — is recognised here and not made, or
		// delivered, twice. Kept as long as a record can be re-read.
		Records: records,
	}
	engine.OnAlert = pipe.Handle

	goProduce(func() { engine.Run(ctx) })

	// Unified sensor ingest (step 109): Suricata EVE alerts, Zeek Intel and
	// SSL, RITA beacons and Isolation-Forest anomalies landed in ClickHouse,
	// routed through the same alert path as DNS detections.
	if ch != nil {
		sensorInterval := parseDuration(env("SENSOR_POLL_INTERVAL", "30s"), 30*time.Second)
		emit := func(ev ingest.SensorEvent) {
			engine.Ingest(ingest.ToAlert(ev, matcher))
		}
		cidrs := strings.Split(env("LOCAL_NETWORKS", strings.Join(ingest.DefaultLocalCIDRs, ",")), ",")
		local, bad := ingest.ParseLocalNetworks(cidrs)
		if len(bad) > 0 {
			slog.Warn("LOCAL_NETWORKS entries ignored: not CIDRs", "entries", bad)
		}
		tlsAnalyzer := tlsheur.New(matcher, resolved, cidrs, engine.Ingest)
		opts := ingest.PollerOptions{
			Cursors:  cursors,
			Lookback: lookback,
			MaxPages: parseInt(env("SENSOR_POLL_MAX_PAGES", ""), ingest.DefaultMaxPages),
			Overlap:  parseDuration(env("SENSOR_POLL_OVERLAP", "10s"), ingest.DefaultOverlap),
		}
		pollers := []*ingest.Poller{
			ingest.NewPoller(ch, ingest.NewSuricataAlerts(local), sensorInterval, emit, opts),
			ingest.NewPoller(ch, ingest.NewZeekIntel(), sensorInterval, emit, opts),
			ingest.NewPoller(ch, ingest.NewMLBeacons(), sensorInterval, emit, opts),
			ingest.NewPoller(ch, ingest.NewMLAnomalies(), sensorInterval, emit, opts),
			ingest.NewPoller(ch, ingest.NewZeekSSL(), sensorInterval, tlsAnalyzer.Handle, opts),
		}
		for _, p := range pollers {
			goProduce(func() { p.Run(ctx) })
		}
		slog.Info("unified sensor ingest enabled", "interval", sensorInterval, "lookback", lookback,
			"overlap", opts.Overlap, "max_pages", opts.MaxPages)
	}

	maintained := make(chan struct{})
	go func() { defer close(maintained); maintain(ctx, alerts, outbox, records, feedbackStore) }()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /alerts", alerts.HandleList)
	mux.HandleFunc("POST /feedback", feedbackStore.HandleFeedback)
	mux.HandleFunc("POST /feedback/lift", feedbackStore.HandleLift)
	mux.HandleFunc("GET /feedback", feedbackStore.HandleList)
	mux.Handle("GET /metrics", promhttp.Handler())

	apiKey := getenv("DETECTION_API_KEY")
	if apiKey == "" {
		slog.Error("no DETECTION_API_KEY set — POST /feedback and /feedback/lift are UNAUTHENTICATED. " +
			"A false-positive verdict suppresses detections before they reach the " +
			"killswitch, so an unauthenticated caller can disable enforcement for " +
			"any indicator.")
	}

	addr := env("LISTEN_ADDR", ":8080")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	if onListen != nil {
		onListen(ln.Addr().String())
	}
	srv := &http.Server{
		Handler:      otelhttp.NewHandler(authMiddleware(apiKey, mux), "detection-engine"),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("starting detection-engine", "addr", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	var failure error
	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err := <-serveErr:
		failure = fmt.Errorf("http server: %w", err)
	}

	// 1. Stop accepting requests.
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Shutdown(sctx); err != nil {
		slog.Error("http shutdown error", "error", err)
	}
	cancel()

	// 2. Let the producers finish what they are doing; nothing new is
	// produced after this.
	if !waitTimeout(&producers, producerStop) {
		slog.Warn("pollers did not stop in time; a detection they make after the store closes is lost",
			"waited", producerStop)
	}
	<-maintained
	// The forwarder stops on ctx; what it has not copied stays in the
	// journal for the next start.
	<-forwarderDone

	// 3. Deliver what can be delivered quickly; the rest stays on disk.
	<-dispatcherDone
	if dispatcher != nil {
		fctx, cancel := context.WithTimeout(context.Background(), shutdownFlush)
		delivered, left := dispatcher.Flush(fctx)
		cancel()
		if left > 0 {
			slog.Warn("undelivered detections left in the outbox",
				"delivered_at_shutdown", delivered, "left", left, "durable", st.Durable(), "path", st.Path())
		} else {
			slog.Info("outbox flushed", "delivered_at_shutdown", delivered)
		}
	}
	return failure
}

// openStore opens the local store. An explicitly configured DB_PATH that
// cannot be opened is a configuration error. Without DB_PATH, an unusable
// default directory degrades to memory — detection keeps working, but the
// history and the undelivered detections are lost on restart, which is said
// loudly and exported as detection_engine_store_durable 0.
func openStore(getenv func(string) string) (*store.Store, error) {
	if p := getenv("DB_PATH"); p != "" {
		st, err := store.Open(p)
		if err != nil {
			return nil, fmt.Errorf("DB_PATH %s: %w", p, err)
		}
		slog.Info("local store opened", "path", p)
		return st, nil
	}
	st, err := store.Open(defaultDBPath)
	if err == nil {
		slog.Info("local store opened", "path", defaultDBPath)
		return st, nil
	}
	slog.Error("no writable data directory: alerts, undelivered detections and analyst verdicts are kept in memory "+
		"and LOST on restart; mount a volume at the default path's directory or set DB_PATH",
		"path", defaultDBPath, "error", err)
	return store.OpenMemory()
}

// maintain applies retention to the alert history and the analysts'
// verdicts, forgets delivered events once they can no longer absorb
// repeats, and handled records once they can no longer be read again.
func maintain(ctx context.Context, alerts *store.Alerts, outbox *store.Outbox, records *store.Records,
	verdicts *feedback.Store) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := alerts.Prune(); err != nil {
				slog.Warn("alert retention failed", "error", err)
			}
			if outbox != nil {
				if _, err := outbox.Purge(); err != nil {
					slog.Warn("outbox purge failed", "error", err)
				}
			}
			if _, err := records.Prune(); err != nil {
				slog.Warn("handled-record retention failed", "error", err)
			}
			verdicts.Maintain()
		}
	}
}

func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// authMiddleware protects mutating endpoints with a bearer token.
//
// GET endpoints stay open for the UI and Prometheus, but note that /alerts
// discloses which domains each device resolved — NetworkPolicy is what keeps
// that private, so it has to be in place.
func authMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || apiKey == "" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(apiKey)) != 1 {
			slog.Warn("rejected unauthenticated request",
				"path", r.URL.Path, "method", r.Method, "remote", r.RemoteAddr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// parseInt reads a positive integer setting.
func parseInt(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
