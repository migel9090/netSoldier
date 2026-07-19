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

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/capture"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/correlator"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/tracing"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/webhook"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	otelEndpoint := envOr("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-collector.observability.svc:4317")
	tp, err := tracing.Init(ctx, "detection-engine", otelEndpoint)
	if err != nil {
		slog.Warn("tracing disabled", "error", err)
	} else {
		defer func() {
			if err := tp.Shutdown(context.Background()); err != nil {
				slog.Error("tracer shutdown error", "error", err)
			}
		}()
	}

	agClient := adguard.NewClient(
		envOr("ADGUARD_URL", "http://adguard-web.dns.svc:3000"),
		envOr("ADGUARD_USER", "admin"),
		envOr("ADGUARD_PASSWORD", "changeme"),
	)

	matcher := iocmatch.New()
	tlPath := envOr("THREATLIST_PATH", "/etc/detection-engine/domains.txt")
	if staticIoCs, err := iocmatch.LoadDomainsFromFile(tlPath); err != nil {
		slog.Warn("static threatlist not loaded", "path", tlPath, "error", err)
	} else {
		matcher.Add(staticIoCs)
		slog.Info("static threatlist loaded", "path", tlPath, "domains", len(staticIoCs))
	}

	if tiURL := os.Getenv("THREAT_INTEL_URL"); tiURL != "" {
		syncInterval := parseDuration(envOr("IOC_SYNC_INTERVAL", "5m"), 5*time.Minute)
		go iocmatch.SyncLoop(ctx, matcher, tiURL, syncInterval)
	}

	dnsCache := correlator.NewDNSCache()

	pollInterval := parseDuration(envOr("POLL_INTERVAL", "30s"), 30*time.Second)
	engine := detection.New(agClient, matcher, pollInterval)

	engine.OnDNSAnswer = func(ip, domain string, ttl int) {
		dnsCache.Set(ip, domain, ttl)
	}

	if webhookURL := os.Getenv("WEBHOOK_URL"); webhookURL != "" {
		sender := webhook.NewSender(webhookURL, envOr("WEBHOOK_SECRET", ""), 3)
		go sender.Run(ctx)
		engine.OnAlert = func(a detection.Alert) {
			sender.Send(webhookPayload{
				Event:   "threat_detected",
				Alert:   a,
				Service: "detection-engine",
			})
		}
		slog.Info("webhook enabled", "url", webhookURL)
	}

	go engine.Run(ctx)

	// Unified sensor ingest (step 109): consume Suricata EVE alerts and
	// Zeek Intel hits landed in ClickHouse and route them through the
	// same alert path as DNS detections.
	if chURL := os.Getenv("CLICKHOUSE_URL"); chURL != "" {
		chc := ingest.NewCHClient(chURL, envOr("CLICKHOUSE_DATABASE", "netsoldier"))
		sensorInterval := parseDuration(envOr("SENSOR_POLL_INTERVAL", "30s"), 30*time.Second)
		emit := func(ev ingest.SensorEvent) {
			engine.Ingest(ingest.ToAlert(ev, matcher))
		}
		go ingest.NewPoller(chc, ingest.NewSuricataAlerts(), sensorInterval, emit).Run(ctx)
		go ingest.NewPoller(chc, ingest.NewZeekIntel(), sensorInterval, emit).Run(ctx)
		slog.Info("unified sensor ingest enabled", "interval", sensorInterval)
	}

	if spanIface := os.Getenv("SPAN_INTERFACE"); spanIface != "" {
		flowCh := make(chan capture.FlowRecord, 256)
		idleTimeout := parseDuration(envOr("FLOW_IDLE_TIMEOUT", "30s"), 30*time.Second)
		cap := capture.New(spanIface, flowCh, idleTimeout)
		go func() {
			if err := cap.Run(ctx); err != nil {
				slog.Error("capture failed", "interface", spanIface, "error", err)
			}
		}()

		devURL := envOr("DEVICE_INVENTORY_URL", "http://device-inventory:8081")
		devCache := correlator.NewDeviceCache(devURL)
		go devCache.RefreshLoop(ctx, 30*time.Second)

		var chWriter *correlator.CHWriter
		if chURL := os.Getenv("CLICKHOUSE_URL"); chURL != "" {
			chWriter = correlator.NewCHWriter(chURL, envOr("CLICKHOUSE_DATABASE", "netsoldier"))
		}

		cor := correlator.New(dnsCache, devCache, chWriter, flowCh)
		go cor.Run(ctx)

		slog.Info("capture + correlator enabled", "interface", spanIface, "idle_timeout", idleTimeout)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /alerts", engine.HandleAlerts)
	mux.Handle("GET /metrics", promhttp.Handler())

	addr := envOr("LISTEN_ADDR", ":8080")
	srv := &http.Server{
		Addr:         addr,
		Handler:      otelhttp.NewHandler(mux, "detection-engine"),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting detection-engine", "addr", addr)
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
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
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

type webhookPayload struct {
	Event   string          `json:"event"`
	Alert   detection.Alert `json:"alert"`
	Service string          `json:"service"`
}
