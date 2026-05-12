package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	pendingActions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "actions_pending",
		Help:      "Number of actions awaiting approval.",
	})
	activeActions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "actions_active",
		Help:      "Number of currently active enforcement actions.",
	})
)

func init() {
	prometheus.MustRegister(pendingActions, activeActions)
}

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
	}

	driverMap := make(map[string]drivers.Driver)

	agURL := envOr("ADGUARD_URL", "http://adguard-web.dns.svc:3000")
	driverMap[events.ActionDNSSinkhole] = drivers.NewSinkholeDriver(agURL, envOr("ADGUARD_USER", "admin"), envOr("ADGUARD_PASSWORD", "changeme"))

	if gwIP := os.Getenv("ARP_GATEWAY_IP"); gwIP != "" {
		if arpDrv, err := drivers.NewARPIsolateDriver(envOr("ARP_INTERFACE", "eth0"), net.ParseIP(gwIP)); err == nil {
			driverMap[events.ActionARPIsolate] = arpDrv
		} else {
			slog.Error("arp-isolate driver failed", "error", err)
		}
	}

	if swURL := os.Getenv("SWITCH_WEBHOOK_URL"); swURL != "" {
		var vlan int
		fmt.Sscanf(envOr("SWITCH_QUARANTINE_VLAN", "0"), "%d", &vlan)
		driverMap[events.ActionSwitchACL] = drivers.NewSwitchPortDriver(swURL, vlan)
	}

	for name := range driverMap {
		slog.Info("driver configured", "driver", name)
	}

	resolve := func(actionType string) drivers.Driver {
		if d, ok := driverMap[actionType]; ok {
			return d
		}
		return driverMap[events.ActionDNSSinkhole]
	}

	store := actions.NewStore(audit)

	go runSafeTTLRevert(ctx, store, resolve)

	apiKey := os.Getenv("KILLSWITCH_API_KEY")
	if apiKey == "" {
		slog.Warn("no KILLSWITCH_API_KEY set — API authentication disabled")
	}

	go refreshKillswitchMetrics(ctx, store)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /policy", handleGetPolicy(pol))
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve))
	mux.HandleFunc("GET /allowlist", handleGetAllowlist(pol))
	mux.HandleFunc("GET /actions/pending", handleListByState(store, events.StatePending))
	mux.HandleFunc("GET /actions/active", handleListByState(store, events.StateActive))
	mux.HandleFunc("GET /actions/{id}", handleGetAction(store))
	mux.HandleFunc("POST /actions/{id}/approve", handleApprove(store, resolve))
	mux.HandleFunc("POST /actions/{id}/reject", handleReject(store))
	mux.HandleFunc("POST /actions/{id}/revert", handleRevert(store, resolve))

	var handler http.Handler = mux
	if apiKey != "" {
		handler = authMiddleware(apiKey, mux)
	}

	addr := envOr("LISTEN_ADDR", ":8084")
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting killswitch-controller", "addr", addr, "auth", apiKey != "")
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

func authMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") || auth[7:] != apiKey {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func runSafeTTLRevert(ctx context.Context, store *actions.Store, resolve func(string) drivers.Driver) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, a := range store.ListExpired() {
				drv := resolve(a.ActionType)
				rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if err := drv.Revert(rctx, &a); err != nil {
					slog.Error("TTL revert driver failed, will retry", "action_id", a.ID, "error", err)
					cancel()
					continue
				}
				cancel()
				store.Revert(a.ID, "TTL expired")
			}
		}
	}
}

func refreshKillswitchMetrics(ctx context.Context, store *actions.Store) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pendingActions.Set(float64(len(store.ListByState(events.StatePending))))
			activeActions.Set(float64(len(store.ListByState(events.StateActive))))
		}
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

func handleEvaluate(pol *policy.Policy, store *actions.Store, resolve func(string) drivers.Driver) http.HandlerFunc {
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
			action = store.Create(ev.ID, ev.ClientMAC, ev.ClientIP, decision.ActionType, decision.Reason, decision.TTLSeconds, true, ev.Domain)
			if err := resolve(decision.ActionType).Apply(r.Context(), action); err != nil {
				slog.Error("driver apply failed", "action_id", action.ID, "error", err)
			} else {
				store.Activate(action.ID)
			}
		case "pending":
			action = store.Create(ev.ID, ev.ClientMAC, ev.ClientIP, decision.ActionType, decision.Reason, decision.TTLSeconds, false, ev.Domain)
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

func handleApprove(store *actions.Store, resolve func(string) drivers.Driver) http.HandlerFunc {
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
		action := store.Get(id)
		if action != nil && action.State == events.StateApproved {
			if err := resolve(action.ActionType).Apply(r.Context(), action); err != nil {
				slog.Error("driver apply failed on approve", "action_id", id, "error", err)
			} else {
				store.Activate(id)
			}
		}
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

func handleRevert(store *actions.Store, resolve func(string) drivers.Driver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Reason == "" {
			req.Reason = "manual revert"
		}
		id := r.PathValue("id")
		action := store.Get(id)
		if action != nil && action.State == events.StateActive {
			if err := resolve(action.ActionType).Revert(r.Context(), action); err != nil {
				slog.Error("driver revert failed", "action_id", id, "error", err)
			}
		}
		if err := store.Revert(id, req.Reason); err != nil {
			http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.Get(id))
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
