package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
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

// maxBodyBytes caps every request body. A detection event is a few hundred
// bytes; without a cap an unauthenticated POST could stream until the pod
// hits its memory limit.
const maxBodyBytes = 1 << 20 // 1 MiB

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
	// allowlistEntries is 0 when nothing is protected. That is the state in
	// which the router itself is quarantinable, so it is worth alerting on.
	allowlistEntries = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "allowlist_entries",
		Help:      "Number of devices protected from enforcement by the allowlist.",
	})
	autoBlockEnabled = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "auto_block_enabled",
		Help:      "1 when automatic enforcement is permitted, 0 when every action needs approval.",
	})
	rejectedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "rejected_requests_total",
		Help:      "Requests rejected by authentication or signature verification.",
	}, []string{"reason"})
	driverFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "driver_failures_total",
		Help:      "Enforcement driver apply/revert failures by operation.",
	}, []string{"operation"})
)

func init() {
	prometheus.MustRegister(pendingActions, activeActions, allowlistEntries,
		autoBlockEnabled, rejectedRequests, driverFailures)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	pol := policy.LoadFromEnv()

	// An empty allowlist means NOTHING is protected — the router, the DNS
	// server and the sensor itself are all quarantinable, and this project's
	// own threat model notes that blocking the router takes the whole network
	// offline. Rather than refuse to start (which would also stop detection,
	// a worse outcome) the controller degrades to pending-only: every action
	// still gets queued and audited, but a human has to approve it.
	autoBlockAllowed := true
	if pol.Allowlist.Len() == 0 {
		if allowEmptyAllowlist() {
			slog.Warn("allowlist is EMPTY and POLICY_ALLOW_EMPTY_ALLOWLIST is set — " +
				"auto-block may target the router, DNS server or the sensor itself")
		} else {
			autoBlockAllowed = false
			slog.Error("allowlist is EMPTY — auto-block disabled, every action requires " +
				"human approval. Set ALLOWLIST_MACS/ALLOWLIST_IPS to protect critical " +
				"devices, or POLICY_ALLOW_EMPTY_ALLOWLIST=true to override.")
		}
	}
	allowlistEntries.Set(float64(pol.Allowlist.Len()))
	autoBlockEnabled.Set(boolGauge(autoBlockAllowed))

	slog.Info("policy loaded",
		"auto_confidence", pol.AutoMinConfidence,
		"auto_severity", pol.AutoMinSeverity,
		"auto_min_signals", pol.AutoMinSignals,
		"auto_require_known_bad", pol.AutoRequireKnownBad,
		"default_ttl", pol.DefaultTTL,
		"default_action", pol.DefaultAction,
		"allowlist_entries", pol.Allowlist.Len(),
		"auto_block_allowed", autoBlockAllowed,
	)

	var audit actions.AuditWriter
	if chURL := os.Getenv("CLICKHOUSE_URL"); chURL != "" {
		audit = actions.NewCHAuditWriter(chURL, envOr("CLICKHOUSE_DATABASE", "netsoldier"),
			os.Getenv("CLICKHOUSE_USER"), os.Getenv("CLICKHOUSE_PASSWORD"))
		slog.Info("audit log enabled", "clickhouse", chURL,
			"authenticated", os.Getenv("CLICKHOUSE_USER") != "")
	} else {
		audit = actions.NopAuditWriter{}
	}

	// Protected endpoints shared by every driver: the policy allowlist is the
	// primary guard, but a driver that can reach the gateway must also refuse
	// it on its own. Defence in depth, because an allowlist entry can be
	// mistyped and a detection can arrive with the gateway's IP.
	var guard drivers.TargetGuard
	if gwIP := os.Getenv("ARP_GATEWAY_IP"); gwIP != "" {
		guard.ProtectIP(gwIP)
	}
	for _, ip := range pol.Allowlist.IPs() {
		guard.ProtectIP(ip)
	}
	for _, mac := range pol.Allowlist.MACs() {
		guard.ProtectMAC(mac)
	}

	driverMap := make(map[string]drivers.Driver)

	agURL := envOr("ADGUARD_URL", "http://adguard-web.dns.svc:3000")
	agUser := os.Getenv("ADGUARD_USER")
	agPass := os.Getenv("ADGUARD_PASSWORD")
	if agUser == "" || agPass == "" {
		slog.Error("ADGUARD_USER/ADGUARD_PASSWORD not set — the DNS sinkhole driver " +
			"cannot authenticate and enforcement will fail")
	}
	driverMap[events.ActionDNSSinkhole] = drivers.NewSinkholeDriver(agURL, agUser, agPass)

	if gwIP := os.Getenv("ARP_GATEWAY_IP"); gwIP != "" {
		arpDrv, err := drivers.NewARPIsolateDriver(envOr("ARP_INTERFACE", "eth0"), net.ParseIP(gwIP), &guard)
		if err != nil {
			// Falling back to the sinkhole here would be worse than not
			// offering the action at all: the operator would be told a
			// device was isolated at layer 2 when only its DNS was blocked.
			slog.Error("arp-isolate driver unavailable — arp_isolate actions will be REFUSED, "+
				"not silently downgraded to a DNS block", "error", err)
		} else {
			driverMap[events.ActionARPIsolate] = arpDrv
		}
	}

	if swURL := os.Getenv("SWITCH_WEBHOOK_URL"); swURL != "" {
		vlan := 0
		if v := os.Getenv("SWITCH_QUARANTINE_VLAN"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 4094 {
				slog.Error("invalid SWITCH_QUARANTINE_VLAN — refusing to guess; "+
					"the driver would silently disable the port instead of moving it", "value", v)
				n = -1
			}
			vlan = n
		}
		if vlan >= 0 {
			driverMap[events.ActionSwitchACL] = drivers.NewSwitchPortDriver(
				swURL, vlan, os.Getenv("SWITCH_WEBHOOK_SECRET"), &guard)
			if os.Getenv("SWITCH_WEBHOOK_SECRET") == "" {
				slog.Warn("SWITCH_WEBHOOK_SECRET not set — switch port operations are unsigned; " +
					"anyone able to reach the webhook can disable ports")
			}
		}
	}

	for name := range driverMap {
		slog.Info("driver configured", "driver", name)
	}

	// resolve returns an error for an unknown or unavailable action type.
	// The previous silent fallback to the DNS sinkhole meant a requested
	// layer-2 isolation could quietly become a DNS-only block, and a revert
	// could be routed to a driver that had never applied anything — then
	// marked reverted anyway.
	resolve := func(actionType string) (drivers.Driver, error) {
		if d, ok := driverMap[actionType]; ok {
			return d, nil
		}
		return nil, fmt.Errorf("no driver configured for action type %q", actionType)
	}

	store := actions.NewStore(audit, actions.StoreOptions{
		MaxActions: envInt("KILLSWITCH_MAX_ACTIONS", 10000),
		IDPrefix:   envOr("KILLSWITCH_ID_PREFIX", instanceIDPrefix()),
	})

	go runSafeTTLRevert(ctx, store, resolve)
	go refreshKillswitchMetrics(ctx, store)

	apiKey := os.Getenv("KILLSWITCH_API_KEY")
	if apiKey == "" {
		slog.Error("no KILLSWITCH_API_KEY set — API authentication is DISABLED; " +
			"anyone able to reach this service can approve or revert enforcement")
	}
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	if webhookSecret == "" {
		slog.Warn("no WEBHOOK_SECRET set — detection events are accepted without " +
			"signature verification; their contents cannot be trusted")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /policy", handleGetPolicy(pol, autoBlockAllowed))
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve, autoBlockAllowed))
	mux.HandleFunc("GET /allowlist", handleGetAllowlist(pol))
	mux.HandleFunc("GET /actions/pending", handleListByState(store, events.StatePending))
	mux.HandleFunc("GET /actions/active", handleListByState(store, events.StateActive))
	mux.HandleFunc("GET /actions/{id}", handleGetAction(store))
	mux.HandleFunc("POST /actions/{id}/approve", handleApprove(store, resolve))
	mux.HandleFunc("POST /actions/{id}/reject", handleReject(store))
	mux.HandleFunc("POST /actions/{id}/revert", handleRevert(store, resolve))

	handler := authMiddleware(apiKey, webhookSecret, mux)

	addr := envOr("LISTEN_ADDR", ":8084")
	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting killswitch-controller", "addr", addr,
			"auth", apiKey != "", "signature_required", webhookSecret != "")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

// authMiddleware authenticates mutating requests and verifies the HMAC on
// signed payloads. GET endpoints stay unauthenticated by design (read-only),
// but note /allowlist and /actions do disclose which devices cannot be
// blocked and what is currently enforced — NetworkPolicy is what keeps them
// private, so it has to be in place.
func authMiddleware(apiKey, webhookSecret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			next.ServeHTTP(w, r)
			return
		}

		if apiKey != "" {
			if !validBearer(r.Header.Get("Authorization"), apiKey) {
				rejectedRequests.WithLabelValues("bad_token").Inc()
				slog.Warn("rejected unauthenticated request",
					"path", r.URL.Path, "remote", r.RemoteAddr)
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
		}

		// Read the body once, under a cap, so the signature covers exactly
		// the bytes the handler will decode.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			rejectedRequests.WithLabelValues("body_too_large").Inc()
			writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		// Only /evaluate carries a signed detection payload; operator
		// actions are authenticated by the bearer token alone.
		if webhookSecret != "" && r.URL.Path == "/evaluate" {
			if err := events.VerifyPayload(webhookSecret, r.Header.Get(events.SignatureHeader), body); err != nil {
				rejectedRequests.WithLabelValues("bad_signature").Inc()
				slog.Warn("rejected detection event with invalid signature",
					"error", err, "remote", r.RemoteAddr)
				writeJSONError(w, http.StatusUnauthorized, "invalid webhook signature")
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// validBearer compares the presented token in constant time so a timing
// side channel cannot be used to recover the key byte by byte.
func validBearer(header, apiKey string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header[len(prefix):]), []byte(apiKey)) == 1
}

func runSafeTTLRevert(ctx context.Context, store *actions.Store, resolve driverResolver) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, a := range store.ListExpired() {
				revertOne(ctx, store, resolve, a, "TTL expired")
			}
		}
	}
}

// revertOne reverts in the only safe order: the driver first, the state only
// after the driver confirms. If the driver fails the action stays active so
// the next tick retries — marking it reverted would tell the operator the
// device is free while the block is still in place.
func revertOne(ctx context.Context, store *actions.Store, resolve driverResolver,
	a events.EnforcementAction, reason string) {
	drv, err := resolve(a.ActionType)
	if err != nil {
		driverFailures.WithLabelValues("revert").Inc()
		slog.Error("cannot revert: no driver for action type; enforcement may still be active",
			"action_id", a.ID, "action_type", a.ActionType, "error", err)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := drv.Revert(rctx, &a); err != nil {
		driverFailures.WithLabelValues("revert").Inc()
		slog.Error("revert driver failed, will retry", "action_id", a.ID, "error", err)
		return
	}
	if err := store.Revert(a.ID, reason); err != nil {
		slog.Error("revert state transition failed", "action_id", a.ID, "error", err)
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

type driverResolver func(string) (drivers.Driver, error)

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleGetPolicy(pol *policy.Policy, autoBlockAllowed bool) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"auto_min_confidence":    pol.AutoMinConfidence,
			"auto_min_severity":      pol.AutoMinSeverity,
			"auto_min_signals":       pol.AutoMinSignals,
			"auto_require_known_bad": pol.AutoRequireKnownBad,
			"pend_min_confidence":    pol.PendMinConfidence,
			"pend_min_severity":      pol.PendMinSeverity,
			"default_ttl":            pol.DefaultTTL,
			"default_action":         pol.DefaultAction,
			"auto_block_allowed":     autoBlockAllowed,
			"allowlist_entries":      pol.Allowlist.Len(),
		})
	}
}

func handleEvaluate(pol *policy.Policy, store *actions.Store, resolve driverResolver,
	autoBlockAllowed bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ev events.DetectionEvent
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid body")
			return
		}

		decision := pol.Evaluate(ev)

		// With no allowlist configured, downgrade auto-block to pending
		// rather than enforce blind.
		if decision.Action == "auto_block" && !autoBlockAllowed {
			decision.Action = "pending"
			decision.Reason = "pending (auto-block disabled: allowlist is empty): " + decision.Reason
		}

		var action *events.EnforcementAction
		switch decision.Action {
		case "auto_block":
			action = store.Create(ev.ID, ev.ClientMAC, ev.ClientIP, decision.ActionType,
				decision.Reason, decision.TTLSeconds, true, ev.Domain)
			applyAction(r.Context(), store, resolve, action)
		case "pending":
			action = store.Create(ev.ID, ev.ClientMAC, ev.ClientIP, decision.ActionType,
				decision.Reason, decision.TTLSeconds, false, ev.Domain)
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"decision": decision,
			"action":   store.Get(actionID(action)),
		})
	}
}

// applyAction runs the driver and only activates the action if it succeeded.
// A failed apply leaves the action in `approved` with a recorded failure, so
// the UI shows "approved but not enforced" rather than claiming the device is
// blocked when it is not.
func applyAction(ctx context.Context, store *actions.Store, resolve driverResolver,
	action *events.EnforcementAction) {
	drv, err := resolve(action.ActionType)
	if err != nil {
		driverFailures.WithLabelValues("apply").Inc()
		slog.Error("cannot apply: no driver for action type", "action_id", action.ID,
			"action_type", action.ActionType, "error", err)
		store.RecordFailure(action.ID, "no driver: "+err.Error())
		return
	}
	if err := drv.Apply(ctx, action); err != nil {
		driverFailures.WithLabelValues("apply").Inc()
		slog.Error("driver apply failed — device is NOT enforced", "action_id", action.ID, "error", err)
		store.RecordFailure(action.ID, err.Error())
		return
	}
	if err := store.Activate(action.ID); err != nil {
		slog.Error("activate transition failed", "action_id", action.ID, "error", err)
	}
}

func handleGetAllowlist(pol *policy.Policy) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"macs": pol.Allowlist.MACs(),
			"ips":  pol.Allowlist.IPs(),
		})
	}
}

func handleListByState(store *actions.Store, state string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, store.ListByState(state))
	}
}

func handleGetAction(store *actions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := store.Get(r.PathValue("id"))
		if a == nil {
			writeJSONError(w, http.StatusNotFound, "not found")
			return
		}
		writeJSON(w, http.StatusOK, a)
	}
}

func handleApprove(store *actions.Store, resolve driverResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ApprovedBy string `json:"approved_by"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.ApprovedBy == "" {
			req.ApprovedBy = "operator"
		}
		id := r.PathValue("id")
		if err := store.Approve(id, req.ApprovedBy); err != nil {
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		if action := store.Get(id); action != nil && action.State == events.StateApproved {
			applyAction(r.Context(), store, resolve, action)
		}
		writeJSON(w, http.StatusOK, store.Get(id))
	}
}

func handleReject(store *actions.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Reason == "" {
			req.Reason = "rejected by operator"
		}
		id := r.PathValue("id")
		if err := store.Reject(id, req.Reason); err != nil {
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, store.Get(id))
	}
}

func handleRevert(store *actions.Store, resolve driverResolver) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Reason == "" {
			req.Reason = "manual revert"
		}
		id := r.PathValue("id")
		action := store.Get(id)
		if action == nil {
			writeJSONError(w, http.StatusNotFound, "not found")
			return
		}

		// Driver first, state second — and if the driver fails, report the
		// failure instead of marking the action reverted. The old order left
		// the block in place in AdGuard while telling the operator it was
		// lifted, which is the one outcome a killswitch must never produce.
		if action.State == events.StateActive {
			drv, err := resolve(action.ActionType)
			if err != nil {
				driverFailures.WithLabelValues("revert").Inc()
				writeJSONError(w, http.StatusServiceUnavailable,
					"no driver for action type; enforcement may still be active")
				return
			}
			if err := drv.Revert(r.Context(), action); err != nil {
				driverFailures.WithLabelValues("revert").Inc()
				slog.Error("driver revert failed — enforcement is STILL ACTIVE",
					"action_id", id, "error", err)
				store.RecordFailure(id, "revert failed: "+err.Error())
				writeJSONError(w, http.StatusBadGateway,
					"revert failed, enforcement still active: "+err.Error())
				return
			}
		}

		if err := store.Revert(id, req.Reason); err != nil {
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, store.Get(id))
	}
}

// writeJSONError builds the body with encoding/json so an error message
// containing a quote cannot produce malformed JSON.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Debug("response encode failed", "error", err)
	}
}

func actionID(a *events.EnforcementAction) string {
	if a == nil {
		return ""
	}
	return a.ID
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func allowEmptyAllowlist() bool {
	switch strings.ToLower(os.Getenv("POLICY_ALLOW_EMPTY_ALLOWLIST")) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// instanceIDPrefix makes action IDs unique across restarts. The old global
// counter restarted at 1 every boot, so ACT-1 in the ClickHouse audit log
// could refer to several different enforcement actions — which defeats the
// point of an audit trail.
func instanceIDPrefix() string {
	if host, err := os.Hostname(); err == nil && host != "" {
		return fmt.Sprintf("ACT-%s-%d", host, time.Now().UTC().Unix())
	}
	return fmt.Sprintf("ACT-%d", time.Now().UTC().Unix())
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
		slog.Warn("invalid integer env, using default", "key", key, "value", v, "default", fallback)
	}
	return fallback
}
