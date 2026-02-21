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
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/dhcp"
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
				if err := db.Upsert(info.MAC, info.IP, info.Hostname, info.Fingerprint, info.VendorClass); err != nil {
					slog.Error("device upsert failed", "mac", info.MAC, "error", err)
				} else {
					slog.Info("device seen", "mac", info.MAC, "ip", info.IP, "hostname", info.Hostname)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	handler := api.NewHandler(db)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices", handler.ListDevices)
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

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
