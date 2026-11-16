package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/agent"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/api"
	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// allProtocols is the default set of captures device-inventory expects the
// agent to be running (for readiness).
var allProtocols = []string{"dhcp", "arp", "lldp", "mdns", "ssdp"}

type config struct {
	listenAddr       string
	dbPath           string
	apiKey           string
	allowUnauth      bool
	netagentToken    string
	expectCapture    []string
	heartbeatTimeout time.Duration
	arpScanSubnet    string
	arpScanInterval  time.Duration
	retention        time.Duration
	store            store.Options
	clickhouseURL    string
	clickhouseDB     string
	clickhouseUser   string
	clickhousePasswd string
}

// loadConfig reads the environment. It fails closed: without DEVICE_API_KEY
// the service only starts when DEVICE_API_ALLOW_UNAUTHENTICATED=true says so
// explicitly. device-inventory no longer captures: it ingests frames from
// netagent (ADR-0004), so it opens no raw socket and needs no capability.
func loadConfig(getenv func(string) string) (config, error) {
	or := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	c := config{
		listenAddr:       or("LISTEN_ADDR", ":8081"),
		dbPath:           or("DB_PATH", "/data/devices.db"),
		apiKey:           getenv("DEVICE_API_KEY"),
		netagentToken:    getenv("NETAGENT_TOKEN"),
		arpScanSubnet:    getenv("ARP_SCAN_SUBNET"),
		clickhouseURL:    getenv("CLICKHOUSE_URL"),
		clickhouseDB:     or("CLICKHOUSE_DATABASE", "netsoldier"),
		clickhouseUser:   getenv("CLICKHOUSE_USER"),
		clickhousePasswd: getenv("CLICKHOUSE_PASSWORD"),
	}
	var errs []error

	switch v := strings.ToLower(getenv("DEVICE_API_ALLOW_UNAUTHENTICATED")); v {
	case "", "false", "0":
	case "true", "1":
		c.allowUnauth = true
	default:
		errs = append(errs, fmt.Errorf("DEVICE_API_ALLOW_UNAUTHENTICATED=%q: want true or false", v))
	}
	if c.apiKey == "" && !c.allowUnauth {
		errs = append(errs, errors.New("DEVICE_API_KEY is not set; refusing to serve the inventory unauthenticated "+
			"(set DEVICE_API_ALLOW_UNAUTHENTICATED=true to do so deliberately)"))
	}

	// NETAGENT_EXPECT_CAPTURE names the protocols the agent is expected to
	// capture (for readiness). DISCOVERY_LISTENERS is still accepted as the
	// old name; "none" means no agent is required (readiness ignores the
	// heartbeat), which is what the e2e suite relies on.
	seen := map[string]bool{}
	raw := getenv("NETAGENT_EXPECT_CAPTURE")
	if raw == "" {
		raw = getenv("DISCOVERY_LISTENERS")
	}
	if raw == "" {
		raw = strings.Join(allProtocols, ",")
	}
	if strings.TrimSpace(raw) != "none" {
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			switch {
			case name == "" || seen[name]:
			case !contains(allProtocols, name):
				errs = append(errs, fmt.Errorf("NETAGENT_EXPECT_CAPTURE: unknown protocol %q (known: %s)", name, strings.Join(allProtocols, ",")))
			default:
				seen[name] = true
				c.expectCapture = append(c.expectCapture, name)
			}
		}
	}
	if len(c.expectCapture) > 0 && c.netagentToken == "" {
		errs = append(errs, errors.New("NETAGENT_EXPECT_CAPTURE names captures but NETAGENT_TOKEN is not set; "+
			"the agent could not authenticate to post frames (set it to none to run without an agent)"))
	}

	dur := func(key string, def time.Duration) time.Duration {
		v := getenv(key)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s=%q: want a positive duration", key, v))
			return def
		}
		return d
	}
	c.heartbeatTimeout = dur("NETAGENT_HEARTBEAT_TIMEOUT", 15*time.Second)
	c.arpScanInterval = dur("ARP_SCAN_INTERVAL", 5*time.Minute)
	c.retention = dur("DEVICE_RETENTION", 30*24*time.Hour)
	c.store.BindingTTL = dur("BINDING_TTL", time.Hour)
	if v := getenv("DEVICE_MAX_ROWS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("DEVICE_MAX_ROWS=%q: want a positive integer", v))
		}
		c.store.MaxDevices = n
	}
	if c.arpScanSubnet != "" {
		if err := agent.ValidateProbeSubnet(c.arpScanSubnet); err != nil {
			errs = append(errs, fmt.Errorf("ARP_SCAN_SUBNET=%q: %w", c.arpScanSubnet, err))
		}
		if c.netagentToken == "" {
			errs = append(errs, errors.New("ARP_SCAN_SUBNET is set but NETAGENT_TOKEN is not; "+
				"device-inventory cannot deliver arp_probe commands without the agent endpoint"))
		}
	}
	return c, errors.Join(errs...)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}
	if cfg.apiKey == "" {
		slog.Warn("DEVICE_API_ALLOW_UNAUTHENTICATED=true: the inventory API is open to anyone who can reach it")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	db, err := store.OpenWithOptions(cfg.dbPath, cfg.store)
	if err != nil {
		slog.Error("database open failed", "path", cfg.dbPath, "error", err)
		os.Exit(1)
	}
	defer db.Close()
	metrics.KnownDevices.Set(float64(db.Count()))

	var chClient *ch.Client
	if cfg.clickhouseURL != "" {
		if cfg.clickhouseUser == "" {
			slog.Warn("CLICKHOUSE_USER is not set; writing to ClickHouse as user \"default\"")
		}
		chClient = ch.NewClient(cfg.clickhouseURL, cfg.clickhouseDB, cfg.clickhouseUser, cfg.clickhousePasswd)
		go checkClickHouse(ctx, chClient)
	}

	writer := newCHWriter(chClient, 1024)
	writerDone := make(chan struct{})
	if chClient != nil {
		go func() { writer.Run(ctx); close(writerDone) }()
	} else {
		close(writerDone)
	}

	go runDevicePrune(ctx, db, cfg.retention)

	// Ingestion path: netagent posts captured frames, device-inventory parses
	// them here and updates the store. No socket, no capability.
	hb := agent.NewHeartbeat(cfg.heartbeatTimeout, cfg.expectCapture)
	cmds := agent.NewCommandQueue()
	ingest := agent.NewIngestor(cfg.netagentToken, func(s discovery.Sighting) { handleSighting(db, writer, s) }, hb, cmds)

	if cfg.arpScanSubnet != "" {
		if err := cmds.RunProbeScheduler(ctx, cfg.arpScanSubnet, cfg.arpScanInterval); err != nil {
			slog.Error("arp probe scheduler failed to start", "error", err)
			os.Exit(1)
		}
	}

	handler := api.NewHandler(db, chClient)
	handler.OnLabels = writer.device
	mux := http.NewServeMux()
	handler.Register(mux)
	mux.Handle("GET /topology", api.NewTopologyHandler(db, chClient))
	if cfg.netagentToken != "" {
		ingest.Register(mux) // POST /agent/v1/frames, authenticated with NETAGENT_TOKEN
	}
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", readyzHandler(hb, len(cfg.expectCapture) > 0))
	mux.Handle("GET /metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           authMiddleware(cfg.apiKey, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	go func() {
		slog.Info("starting device-inventory", "addr", cfg.listenAddr, "expect_capture", strings.Join(cfg.expectCapture, ","),
			"agent_ingest", cfg.netagentToken != "")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	select { // the writer's last flush is bounded by its own insert timeout
	case <-writerDone:
	case <-shutdownCtx.Done():
	}
}

// handleHealthz is liveness only: the process is up and serving HTTP.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// readyzHandler reports readiness from the agent's heartbeat (contract 8.1).
// When no captures are expected (NETAGENT_EXPECT_CAPTURE=none) there is no
// agent to wait for, so the service is ready as soon as it serves.
func readyzHandler(hb *agent.Heartbeat, requireAgent bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		st := hb.Status()
		ready := st.Ready || !requireAgent
		code, word := http.StatusOK, "ready"
		if !ready {
			code, word = http.StatusServiceUnavailable, "not ready"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": word, "agent": st})
	}
}

// authMiddleware requires the bearer token on everything except the probe,
// metrics and agent-ingest endpoints, reads included. The ingest endpoint
// authenticates itself with the separate agent token (a leaked read key must
// not be usable to inject frames). An empty key means the operator
// explicitly allowed unauthenticated access (loadConfig enforces that).
func authMiddleware(apiKey string, next http.Handler) http.Handler {
	open := map[string]bool{"/healthz": true, "/readyz": true, "/metrics": true, "/agent/v1/frames": true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiKey == "" || open[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(apiKey)) != 1 {
			slog.Warn("rejected unauthenticated request", "path", r.URL.Path, "method", r.Method)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("WWW-Authenticate", `Bearer realm="device-inventory"`)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func runDevicePrune(ctx context.Context, db *store.Store, maxAge time.Duration) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := db.Prune(maxAge); err != nil {
				slog.Warn("device prune failed", "error", err)
			} else if n > 0 {
				metrics.DevicesPruned.Add(float64(n))
				metrics.KnownDevices.Set(float64(db.Count()))
			}
		}
	}
}

func checkClickHouse(ctx context.Context, client *ch.Client) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.CheckSchema(cctx, "devices", "device_events"); err != nil {
		metrics.ClickHouseErrors.WithLabelValues("check", "schema").Inc()
		slog.Warn("clickhouse not ready; writes will fail until it is", "error", err)
		return
	}
	slog.Info("clickhouse schema present")
}
