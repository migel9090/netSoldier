package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/api"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/arp"
	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/dhcp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/fingerbank"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/lldp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/mdns"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/oui"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/ssdp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var dhcpPacketsTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "device_inventory",
	Name:      "dhcp_packets_total",
	Help:      "Total DHCP client packets processed.",
})

func init() {
	prometheus.MustRegister(dhcpPacketsTotal)
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

	var chClient *ch.Client
	if chURL := os.Getenv("CLICKHOUSE_URL"); chURL != "" {
		chDB := envOr("CLICKHOUSE_DATABASE", "netsoldier")
		chClient = ch.NewClient(chURL, chDB)
		if err := chClient.InitSchema(ctx); err != nil {
			slog.Warn("clickhouse schema init failed (will retry on writes)", "error", err)
		} else {
			slog.Info("clickhouse connected", "url", chURL, "database", chDB)
		}
	}

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
				if p := fingerbank.Lookup(info.Fingerprint, info.VendorClass); p != nil {
					osName = p.OS
					devType = p.DeviceType
				}
				if err := db.UpsertFull(info.MAC, info.IP, info.Hostname, info.Fingerprint, info.VendorClass, vendor, osName, devType); err != nil {
					slog.Error("device upsert failed", "mac", info.MAC, "error", err)
				} else {
					slog.Info("device seen", "mac", info.MAC, "ip", info.IP, "hostname", info.Hostname, "os", osName, "type", devType)
					writeClickHouse(chClient, info.MAC, info.IP, info.Hostname, vendor, "dhcp")
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	discoveryCh := make(chan discovery.Info, 64)
	startDiscoveryListeners(ctx, discoveryCh)
	go processDiscoveries(ctx, db, chClient, discoveryCh)

	handler := api.NewHandler(db)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices", handler.ListDevices)
	mux.HandleFunc("GET /devices/{mac}", handler.GetDevice)
	mux.HandleFunc("PUT /devices/{mac}/labels", handler.SetLabels)
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())

	addr := envOr("LISTEN_ADDR", ":8081")
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
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

func processDiscoveries(ctx context.Context, db *store.Store, chClient *ch.Client, dch <-chan discovery.Info) {
	for {
		select {
		case info := <-dch:
			if info.MAC != "" {
				vendor := oui.Lookup(info.MAC)
				if err := db.Upsert(info.MAC, info.IP, info.Hostname, "", "", vendor); err != nil {
					slog.Error("discovery upsert failed", "protocol", info.Protocol, "error", err)
				} else {
					slog.Info("device discovered", "protocol", info.Protocol, "mac", info.MAC, "hostname", info.Hostname)
					writeClickHouse(chClient, info.MAC, info.IP, info.Hostname, vendor, info.Protocol)
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

func writeClickHouse(client *ch.Client, mac, ip, hostname, vendor, protocol string) {
	if client == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		now := time.Now().UTC().Format("2006-01-02 15:04:05")
		event := ch.DeviceEvent{
			Timestamp: now,
			MAC:       mac,
			IP:        ip,
			Hostname:  hostname,
			Vendor:    vendor,
			Protocol:  protocol,
			EventType: "seen",
		}
		if err := client.Insert(ctx, "device_events", event); err != nil {
			slog.Debug("clickhouse event write failed", "error", err)
		}
	}()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
