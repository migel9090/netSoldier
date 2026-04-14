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

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	pol := policy.LoadFromEnv()
	slog.Info("policy loaded",
		"auto_confidence", pol.AutoMinConfidence,
		"auto_severity", pol.AutoMinSeverity,
		"pending_confidence", pol.PendMinConfidence,
		"pending_severity", pol.PendMinSeverity,
		"default_ttl", pol.DefaultTTL,
		"default_action", pol.DefaultAction,
		"allowlist_macs", pol.Allowlist.MACs(),
		"allowlist_ips", pol.Allowlist.IPs(),
	)

	addr := envOr("LISTEN_ADDR", ":8084")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /policy", handleGetPolicy(pol))
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol))
	mux.HandleFunc("GET /allowlist", handleGetAllowlist(pol))

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting killswitch-controller", "addr", addr)
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

func handleGetPolicy(pol *policy.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"auto_min_confidence": pol.AutoMinConfidence,
			"auto_min_severity":   pol.AutoMinSeverity,
			"pend_min_confidence": pol.PendMinConfidence,
			"pend_min_severity":   pol.PendMinSeverity,
			"default_ttl":         pol.DefaultTTL,
			"default_action":      pol.DefaultAction,
		})
	}
}

func handleEvaluate(pol *policy.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ev events.DetectionEvent
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}

		decision := pol.Evaluate(ev)

		slog.Info("policy evaluated",
			"detection_id", ev.ID,
			"action", decision.Action,
			"reason", decision.Reason,
		)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(decision)
	}
}

func handleGetAllowlist(pol *policy.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"macs": pol.Allowlist.MACs(),
			"ips":  pol.Allowlist.IPs(),
		})
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
