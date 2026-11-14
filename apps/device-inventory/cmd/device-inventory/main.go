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

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/api"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/arp"
	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/dhcp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/lldp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/mdns"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/ssdp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/supervise"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// allListeners is the default for DISCOVERY_LISTENERS.
var allListeners = []string{"dhcp", "arp", "lldp", "mdns", "ssdp"}

type config struct {
	listenAddr       string
	dbPath           string
	apiKey           string
	allowUnauth      bool
	iface            string
	listeners        []string
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
// explicitly.
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
		iface:            getenv("DISCOVERY_INTERFACE"),
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

	seen := map[string]bool{}
	listeners := or("DISCOVERY_LISTENERS", strings.Join(allListeners, ","))
	if strings.TrimSpace(listeners) == "none" { // API only (tests; frames from elsewhere later)
		listeners = ""
	}
	for _, name := range strings.Split(listeners, ",") {
		name = strings.TrimSpace(name)
		switch {
		case name == "" || seen[name]:
		case !contains(allListeners, name):
			errs = append(errs, fmt.Errorf("DISCOVERY_LISTENERS: unknown listener %q (known: %s)", name, strings.Join(allListeners, ",")))
		default:
			seen[name] = true
			c.listeners = append(c.listeners, name)
		}
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

	sightings := make(chan discovery.Sighting, 256)
	status := supervise.NewStatus()
	startListeners(ctx, cfg, status, sightings)
	go processSightings(ctx, db, writer, sightings)

	handler := api.NewHandler(db, chClient)
	handler.OnLabels = writer.device
	mux := http.NewServeMux()
	handler.Register(mux)
	mux.Handle("GET /topology", api.NewTopologyHandler(db, chClient))
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /readyz", readyzHandler(status))
	mux.Handle("GET /metrics", promhttp.Handler())

	srv := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           authMiddleware(cfg.apiKey, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	go func() {
		slog.Info("starting device-inventory", "addr", cfg.listenAddr, "listeners", strings.Join(status.Names(), ","),
			"interface", cfg.iface)
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

// readyzHandler reports 200 only while every enabled listener is up, with
// each listener's state in the body either way.
func readyzHandler(status *supervise.Status) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		ready, listeners := status.Ready()
		code, word := http.StatusOK, "ready"
		if !ready {
			code, word = http.StatusServiceUnavailable, "not ready"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": word, "listeners": listeners})
	}
}

func startListeners(ctx context.Context, cfg config, status *supervise.Status, out chan<- discovery.Sighting) {
	run := func(name string, fn supervise.RunFunc) {
		status.Register(name)
		go supervise.Run(ctx, status, name, fn)
	}
	for _, name := range cfg.listeners {
		switch name {
		case "dhcp":
			run(name, dhcp.NewListener(cfg.iface, out).Run)
		case "arp":
			run(name, arp.NewListener(cfg.iface, out).Run)
		case "lldp":
			run(name, lldp.NewListener(cfg.iface, out).Run)
		case "mdns":
			run(name, mdns.NewListener(cfg.iface, out).Run)
		case "ssdp":
			run(name, ssdp.NewListener(cfg.iface, out).Run)
		}
	}
	if cfg.arpScanSubnet != "" {
		run("arp-scan", func(ctx context.Context, up func()) error {
			scanner, err := arp.NewScanner(cfg.arpScanSubnet, cfg.arpScanInterval)
			if err != nil {
				return err
			}
			return scanner.Run(ctx, up)
		})
	}
}

// authMiddleware requires the bearer token on everything except the probe
// and metrics endpoints, reads included. An empty key means the operator
// explicitly allowed unauthenticated access (loadConfig enforces that).
func authMiddleware(apiKey string, next http.Handler) http.Handler {
	open := map[string]bool{"/healthz": true, "/readyz": true, "/metrics": true}
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
