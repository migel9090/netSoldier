package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/api"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/arp"
	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/dhcp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/dhcpfp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/lldp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/mdns"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/oui"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/ssdp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	dhcpPacketsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "device_inventory",
		Name:      "dhcp_packets_total",
		Help:      "Total DHCP client packets processed.",
	})
	knownDevices = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "device_inventory",
		Name:      "known_devices",
		Help:      "Total number of known devices in the inventory.",
	})
	lastDeviceEventTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "device_inventory",
		Name:      "last_device_event_timestamp_seconds",
		Help:      "Unix timestamp of the most recent device event.",
	})
	deviceEventsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "device_inventory",
		Name:      "events_dropped_total",
		Help:      "Device events dropped because the ClickHouse write queue was full.",
	})
	devicesPruned = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "device_inventory",
		Name:      "devices_pruned_total",
		Help:      "Stale unlabelled devices removed by retention.",
	})
)

func init() {
	prometheus.MustRegister(dhcpPacketsTotal, knownDevices, lastDeviceEventTimestamp,
		deviceEventsDropped, devicesPruned)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	dbPath := envOr("DB_PATH", "/data/devices.db")
	db, err := store.Open(dbPath)
	if err != nil {
		slog.Error("database open failed", "path", dbPath, "error", err)
		os.Exit(1)
	}
	defer db.Close()
	refreshDeviceMetrics(db)

	var chClient *ch.Client
	if chURL := os.Getenv("CLICKHOUSE_URL"); chURL != "" {
		chDB := envOr("CLICKHOUSE_DATABASE", "netsoldier")
		chClient = ch.NewClient(chURL, chDB,
			os.Getenv("CLICKHOUSE_USER"), os.Getenv("CLICKHOUSE_PASSWORD"))
		if err := chClient.InitSchema(ctx); err != nil {
			slog.Warn("clickhouse schema init failed (will retry on writes)", "error", err)
		} else {
			slog.Info("clickhouse connected", "url", chURL, "database", chDB)
		}
	}

	writer := newEventWriter(chClient, 1024)
	if chClient != nil {
		go writer.Run(ctx)
	}

	// Retention for the inventory itself: discovery is fed by spoofable LAN
	// protocols, so without pruning the table grows without bound.
	retention := parseDuration(envOr("DEVICE_RETENTION", "720h"), 30*24*time.Hour)
	go runDevicePrune(ctx, db, retention)

	deviceCh := make(chan dhcp.DeviceInfo, 64)
	listener := dhcp.NewListener(deviceCh)
	go func() {
		if err := listener.Run(ctx); err != nil {
			slog.Error("dhcp listener failed", "error", err)
		}
	}()

	go func() {
		for {
			select {
			case info := <-deviceCh:
				dhcpPacketsTotal.Inc()
				vendor := oui.Lookup(info.MAC)
				var osName, devType string
				if p := dhcpfp.Lookup(info.Fingerprint, info.VendorClass); p != nil {
					osName = p.OS
					devType = p.DeviceType
				}
				if err := db.UpsertFull(info.MAC, info.IP, info.Hostname, info.Fingerprint, info.VendorClass, vendor, osName, devType); err != nil {
					slog.Error("device upsert failed", "mac", info.MAC, "error", err)
				} else {
					slog.Info("device seen", "mac", info.MAC, "ip", info.IP, "hostname", info.Hostname, "os", osName, "type", devType)
					refreshDeviceMetrics(db)
					writer.enqueue(info.MAC, info.IP, info.Hostname, vendor, "dhcp")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	discoveryCh := make(chan discovery.Info, 64)
	startDiscoveryListeners(ctx, discoveryCh)
	go processDiscoveries(ctx, db, writer, discoveryCh)

	handler := api.NewHandler(db, chClient)
	topoHandler := api.NewTopologyHandler(db, chClient)
	apiKey := os.Getenv("DEVICE_API_KEY")
	if apiKey == "" {
		slog.Warn("no DEVICE_API_KEY set — PUT /devices/{mac}/labels is unauthenticated")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices", handler.ListDevices)
	mux.HandleFunc("GET /devices/{mac}", handler.GetDevice)
	mux.HandleFunc("GET /devices/{mac}/connections", handler.DeviceConnections)
	mux.HandleFunc("GET /devices/{mac}/dns", handler.DeviceDNS)
	mux.HandleFunc("GET /devices/{mac}/alerts", handler.DeviceAlerts)
	mux.HandleFunc("PUT /devices/{mac}/labels", handler.SetLabels)
	mux.HandleFunc("GET /topology", topoHandler.ServeHTTP)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())

	addr := envOr("LISTEN_ADDR", ":8081")
	srv := &http.Server{
		Addr:         addr,
		Handler:      authMiddleware(apiKey, mux),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting device-inventory", "addr", addr)
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
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func startDiscoveryListeners(ctx context.Context, ch chan<- discovery.Info) {
	go func() {
		if err := mdns.NewListener(ch).Run(ctx); err != nil {
			slog.Error("mdns listener failed", "error", err)
		}
	}()
	go func() {
		if err := ssdp.NewListener(ch).Run(ctx); err != nil {
			slog.Error("ssdp listener failed", "error", err)
		}
	}()
	go func() {
		if err := lldp.NewListener(ch).Run(ctx); err != nil {
			slog.Error("lldp listener failed", "error", err)
		}
	}()
	go func() {
		if err := arp.NewListener(ch).Run(ctx); err != nil {
			slog.Error("arp listener failed", "error", err)
		}
	}()

	if subnet := os.Getenv("ARP_SCAN_SUBNET"); subnet != "" {
		interval := 5 * time.Minute
		if v := os.Getenv("ARP_SCAN_INTERVAL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil {
				interval = d
			}
		}
		scanner, err := arp.NewScanner(subnet, interval)
		if err != nil {
			slog.Error("arp scanner init failed", "subnet", subnet, "error", err)
		} else {
			go func() {
				if err := scanner.Run(ctx); err != nil {
					slog.Error("arp scanner failed", "error", err)
				}
			}()
		}
	}
}

// authMiddleware protects mutating endpoints with a bearer token. Reads stay
// open for the UI and Prometheus; NetworkPolicy keeps them off the LAN.
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
			slog.Warn("rejected unauthenticated request", "path", r.URL.Path, "method", r.Method)
			w.Header().Set("Content-Type", "application/json")
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
				devicesPruned.Add(float64(n))
				refreshDeviceMetrics(db)
			}
		}
	}
}

func processDiscoveries(ctx context.Context, db *store.Store, writer *eventWriter, dch <-chan discovery.Info) {
	for {
		select {
		case info := <-dch:
			if info.MAC != "" {
				vendor := oui.Lookup(info.MAC)
				if err := db.Upsert(info.MAC, info.IP, info.Hostname, "", "", vendor); err != nil {
					slog.Error("discovery upsert failed", "protocol", info.Protocol, "error", err)
				} else {
					slog.Info("device discovered", "protocol", info.Protocol, "mac", info.MAC, "hostname", info.Hostname)
					refreshDeviceMetrics(db)
					writer.enqueue(info.MAC, info.IP, info.Hostname, vendor, info.Protocol)
				}
			} else if info.IP != "" && info.Hostname != "" {
				if err := db.EnrichByIP(info.IP, info.Hostname); err != nil {
					slog.Error("discovery enrich failed", "protocol", info.Protocol, "error", err)
				} else {
					slog.Debug("device enriched", "protocol", info.Protocol, "ip", info.IP, "hostname", info.Hostname)
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

// eventWriter batches device events to ClickHouse through a bounded queue.
//
// Each sighting used to spawn its own goroutine holding a 5-second HTTP
// request. Discovery is driven by mDNS/SSDP/LLDP/ARP — unauthenticated LAN
// protocols — so a device spraying forged announcements could create
// unbounded goroutines and one HTTP request per packet. On pi-edge that is a
// 128Mi pod. A fixed-size queue with batched inserts drops load instead of
// the process.
type eventWriter struct {
	client *ch.Client
	queue  chan ch.DeviceEvent
}

func newEventWriter(client *ch.Client, depth int) *eventWriter {
	return &eventWriter{client: client, queue: make(chan ch.DeviceEvent, depth)}
}

// enqueue is non-blocking: under a flood the newest events are dropped and
// counted rather than stalling the discovery pipeline.
func (w *eventWriter) enqueue(mac, ip, hostname, vendor, protocol string) {
	if w == nil || w.client == nil {
		return
	}
	event := ch.DeviceEvent{
		Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05.000"),
		MAC:       mac,
		IP:        ip,
		Hostname:  hostname,
		Vendor:    vendor,
		Protocol:  protocol,
		EventType: "seen",
	}
	select {
	case w.queue <- event:
	default:
		deviceEventsDropped.Inc()
	}
}

// Run drains the queue, flushing on a full batch or a timer.
func (w *eventWriter) Run(ctx context.Context) {
	const batchSize = 100
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	batch := make([]any, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		writeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := w.client.Insert(writeCtx, "device_events", batch...); err != nil {
			slog.Warn("clickhouse batch write failed", "events", len(batch), "error", err)
		}
		cancel()
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case ev := <-w.queue:
			batch = append(batch, ev)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func refreshDeviceMetrics(db *store.Store) {
	if n, err := db.Count(); err == nil {
		knownDevices.Set(float64(n))
	}
	lastDeviceEventTimestamp.SetToCurrentTime()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
