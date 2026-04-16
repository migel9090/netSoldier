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

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
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
		"default_ttl", pol.DefaultTTL,
		"default_action", pol.DefaultAction,
	)

	var audit actions.AuditWriter
	if chURL := os.Getenv("CLICKHOUSE_URL"); chURL != "" {
		audit = actions.NewCHAuditWriter(chURL, envOr("CLICKHOUSE_DATABASE", "netsoldier"))
		slog.Info("audit log enabled", "clickhouse", chURL)
	} else {
		audit = actions.NopAuditWriter{}
		slog.Warn("audit log disabled (no CLICKHOUSE_URL)")
	}

	store := actions.NewStore(audit)
	go store.RunTTLRevert(ctx)

	addr := envOr("LISTEN_ADDR", ":8084")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /policy", handleGetPolicy(pol))
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store))
	mux.HandleFunc("GET /allowlist", handleGetAllowlist(pol))
	mux.HandleFunc("GET /actions/pending", handleListByState(store, events.StatePending))
	mux.HandleFunc("GET /actions/active", handleListByState(store, events.StateActive))
	mux.HandleFunc("GET /actions/{id}", handleGetAction(store))
	mux.HandleFunc("POST /actions/{id}/approve", handleApprove(store))
	mux.HandleFunc("POST /actions/{id}/reject", handleReject(store))
	mux.HandleFunc("POST /actions/{id}/revert", handleRevert(store))

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

func handleEvaluate(pol *policy.Policy, store *actions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ev events.DetectionEvent
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
			return
		}

		decision := pol.Evaluate(ev)

		var action *events.EnforcementAction
		switch decision.Action {
		case "auto_block":
			action = store.Create(ev.ID, ev.ClientMAC, ev.ClientIP, decision.ActionType, decision.Reason, decision.TTLSeconds, true)
			store.Activate(action.ID)
		case "pending":
			action = store.Create(ev.ID, ev.ClientMAC, ev.ClientIP, decision.ActionType, decision.Reason, decision.TTLSeconds, false)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"decision": decision,
			"action":   action,
		})
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

func handleListByState(store *actions.Store, state string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.ListByState(state))
	}
}

func handleGetAction(store *actions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := store.Get(r.PathValue("id"))
		if a == nil {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(a)
	}
}

func handleApprove(store *actions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ApprovedBy string `json:"approved_by"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.ApprovedBy == "" {
			req.ApprovedBy = "operator"
		}
		id := r.PathValue("id")
		if err := store.Approve(id, req.ApprovedBy); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
			return
		}
		store.Activate(id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.Get(id))
	}
}

func handleReject(store *actions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Reason == "" {
			req.Reason = "rejected by operator"
		}
		if err := store.Reject(r.PathValue("id"), req.Reason); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.Get(r.PathValue("id")))
	}
}

func handleRevert(store *actions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Reason == "" {
			req.Reason = "manual revert"
		}
		if err := store.Revert(r.PathValue("id"), req.Reason); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.Get(r.PathValue("id")))
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
