package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/enforce"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

// maxBodyBytes caps every request body. A detection event is a few hundred
// bytes; without a cap an unauthenticated POST could stream until the pod
// hits its memory limit.
const maxBodyBytes = 1 << 20 // 1 MiB

var (
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
	// autoBlockConfigured is the operator's switch. Off is the default and
	// a choice, so an alert on "auto-block disabled" has to be able to ask
	// whether it was switched on and is being held back.
	autoBlockConfigured = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "auto_block_configured",
		Help:      "1 when POLICY_AUTO_BLOCK=on asks for automatic enforcement, 0 when it is off.",
	})
	rejectedRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "rejected_requests_total",
		Help:      "Requests rejected by authentication, signature verification or validation.",
	}, []string{"reason"})
	// duplicateEvents counts deliveries of an already-evaluated event id:
	// sender retries, or replays inside the signature window.
	duplicateEvents = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "duplicate_events_total",
		Help:      "Detection events answered from the idempotency ledger instead of re-evaluated.",
	})
	// autoBlockWithheld counts detections that met every auto-block
	// condition and were queued for a human only because the service runs
	// with auto-block disabled — what a degraded start-up is costing.
	autoBlockWithheld = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "auto_block_withheld_total",
		Help:      "Detections that would have been auto-blocked but were queued because auto-block is disabled, by reason.",
	}, []string{"reason"})
	// protectionEntriesRejected is non-zero only when the service was
	// started with ALLOWLIST_ON_INVALID=pending-only: some device the
	// operator meant to protect is not protected.
	protectionEntriesRejected = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "protection_entries_rejected",
		Help:      "Allowlist / gateway entries rejected at start-up; while non-zero auto-block is disabled.",
	})
)

func init() {
	prometheus.MustRegister(allowlistEntries, autoBlockEnabled, autoBlockConfigured, rejectedRequests, duplicateEvents,
		autoBlockWithheld, protectionEntriesRejected)
	for _, r := range []string{policy.WithheldAutoBlockOff, policy.WithheldEmptyAllowlist, policy.WithheldInvalidProtection} {
		autoBlockWithheld.WithLabelValues(r)
	}
}

// Routes the authentication middleware treats specially. Every other route,
// and any path no route matches, needs the operator token.
const (
	evaluateRoute = "POST /evaluate"
	agentRoute    = "POST /agent/v1/poll"
	healthRoute   = "GET /healthz"
	metricsRoute  = "GET /metrics"
)

// defaultDataDir holds the database unless KILLSWITCH_DB_PATH says
// otherwise. It must be a persistent volume: the database is the only
// record of what is enforced.
const defaultDataDir = "/var/lib/killswitch"

// auditRetention is how long the local audit log keeps an entry (once it
// has been forwarded, when forwarding is configured). It matches the
// ClickHouse table's TTL.
const auditRetention = 180 * 24 * time.Hour

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// A protection entry that does not parse means a device the operator
	// believes is protected is not; that stops the start, and so does a
	// POLICY_AUTO_BLOCK that is neither on nor off (see LoadFromEnv).
	pol, err := policy.LoadFromEnv()
	if err != nil {
		slog.Error("refusing to start: invalid policy configuration", "error", err)
		os.Exit(1)
	}

	// Automation is the operator's decision (POLICY_AUTO_BLOCK), so off is
	// said once, not alarmed about. An empty allowlist means NOTHING the
	// operator chose is protected — the router among them, and this
	// project's own threat model notes that blocking the router takes the
	// whole network offline. Rather than refuse to start (which would also
	// stop detection, a worse outcome) the policy degrades to pending-only:
	// every action still gets queued and audited, but a human has to approve
	// it.
	if !pol.AutoBlock {
		slog.Info("auto-block is OFF (POLICY_AUTO_BLOCK=off): every action requires human approval; " +
			"set POLICY_AUTO_BLOCK=on to let the policy sinkhole attested known-bad domains on its own")
	}
	switch hold, _ := pol.AutoBlockHold(); {
	case len(pol.RejectedEntries) > 0:
		slog.Error("auto-block DISABLED: started with rejected protection entries "+
			"(ALLOWLIST_ON_INVALID=pending-only); every action requires human approval",
			"rejected", pol.RejectedEntries)
	case !pol.AutoBlock:
		// Said above; the allowlist only matters to automation once it is on.
	case hold != "":
		slog.Error("allowlist is EMPTY — auto-block disabled, every action requires " +
			"human approval. Set ALLOWLIST_MACS/ALLOWLIST_IPS to protect critical " +
			"devices, or POLICY_ALLOW_EMPTY_ALLOWLIST=true to override.")
	case pol.Allowlist.Len() == 0:
		slog.Warn("allowlist is EMPTY and POLICY_ALLOW_EMPTY_ALLOWLIST is set — " +
			"auto-block may target devices the operator never listed")
	}
	autoBlockAllowed := pol.AutoBlockEnabled()
	allowlistEntries.Set(float64(pol.Allowlist.Len()))
	autoBlockEnabled.Set(boolGauge(autoBlockAllowed))
	autoBlockConfigured.Set(boolGauge(pol.AutoBlock))
	protectionEntriesRejected.Set(float64(len(pol.RejectedEntries)))

	agURL := envOr("ADGUARD_URL", "http://adguard-web.dns.svc:3000")

	// The sensor's own addresses and the DNS server are protected without
	// anyone having to list them. If they cannot all be determined, the
	// drivers that act on devices are withheld below.
	infraErr := protectInfrastructure(ctx, pol, agURL, resolveHost)
	if infraErr != nil {
		slog.Error("could not determine every infrastructure address to protect — "+
			"arp_isolate and switch_acl will be refused", "error", infraErr)
	}

	slog.Info("policy loaded",
		"auto_confidence", pol.AutoMinConfidence,
		"auto_severity", pol.AutoMinSeverity,
		"auto_min_signals", pol.AutoMinSignals,
		"auto_action", events.ActionDNSSinkhole,
		"default_ttl", pol.DefaultTTL,
		"default_action", pol.DefaultAction,
		"allowlist_entries", pol.Allowlist.Len(),
		"gateway_ip", pol.GatewayIP.String(),
		"gateway_mac", pol.GatewayMAC,
		"infrastructure", append(pol.Infrastructure.IPs(), pol.Infrastructure.MACs()...),
		"auto_block", autoBlockSetting(pol),
		"auto_block_allowed", autoBlockAllowed,
	)

	// Protected endpoints shared by every driver: the policy allowlist is the
	// primary guard, but a driver that can reach the gateway must also refuse
	// it on its own. Defence in depth, because an allowlist entry can be
	// mistyped and a detection can arrive with the gateway's IP.
	guard, err := buildGuard(pol)
	if err != nil {
		slog.Error("refusing to start: protected device not accepted by the target guard", "error", err)
		os.Exit(1)
	}

	tolerance := envDuration("WEBHOOK_SIGNATURE_TOLERANCE", events.DefaultSignatureTolerance)
	creds, verifier, err := loadAuth(tolerance)
	if err != nil {
		slog.Error("refusing to start: authentication is not fully configured", "error", err)
		os.Exit(1)
	}

	// Without its database the service cannot know what it has enforced,
	// so it does not run without one.
	dbPath := envOr("KILLSWITCH_DB_PATH", filepath.Join(envOr("KILLSWITCH_DATA_DIR", defaultDataDir), "killswitch.db"))
	store, err := actions.Open(dbPath, actions.Options{
		MaxTerminal: envInt("KILLSWITCH_MAX_ACTIONS", 10000),
		MaxPending:  envInt("KILLSWITCH_MAX_PENDING", 500),
		PendingTTL:  envDuration("KILLSWITCH_PENDING_TTL", 24*time.Hour),
		IDPrefix:    os.Getenv("KILLSWITCH_ID_PREFIX"),
	})
	if err != nil {
		slog.Error("refusing to start: the action database cannot be opened", "path", dbPath, "error", err)
		os.Exit(1)
	}
	defer store.Close()
	slog.Info("action database open", "path", dbPath, "instance", store.Instance())

	driverMap := buildDrivers(pol, guard, store, agURL, creds, infraErr)
	for name := range driverMap {
		slog.Info("driver configured", "driver", name)
	}

	chURL := os.Getenv("CLICKHOUSE_URL")
	engine := enforce.New(store, driverMap, enforce.Config{
		DriverTimeout:     envDuration("KILLSWITCH_DRIVER_TIMEOUT", 8*time.Second),
		ConfirmTimeout:    envDuration("KILLSWITCH_AGENT_CONFIRM_TIMEOUT", 8*time.Second),
		RetryBase:         envDuration("KILLSWITCH_REVERT_RETRY_BASE", 10*time.Second),
		RetryMax:          envDuration("KILLSWITCH_REVERT_RETRY_MAX", 10*time.Minute),
		ReapInterval:      envDuration("KILLSWITCH_REAPER_INTERVAL", 10*time.Second),
		ReconcileInterval: envDuration("KILLSWITCH_RECONCILE_INTERVAL", 5*time.Minute),
		Prune: actions.PruneOptions{
			EvaluationRetention: ledgerRetention(tolerance),
			MaxEvaluations:      maxLedgerEntries,
			AuditRetention:      auditRetention,
			AuditForwarding:     chURL != "",
			CommandRetention:    24 * time.Hour,
		},
	})
	engine.Recover()
	go engine.Run(ctx)

	var forwarder *actions.Forwarder
	if chURL != "" {
		forwarder = &actions.Forwarder{Store: store, Sink: actions.NewClickHouseSink(chURL,
			envOr("CLICKHOUSE_DATABASE", "netsoldier"), os.Getenv("CLICKHOUSE_USER"), os.Getenv("CLICKHOUSE_PASSWORD"))}
		go forwarder.Run(ctx)
		slog.Info("audit log forwarded to ClickHouse", "clickhouse", chURL,
			"authenticated", os.Getenv("CLICKHOUSE_USER") != "")
	} else {
		slog.Warn("CLICKHOUSE_URL not set: the audit log is kept in the local database only (GET /audit)")
	}

	srv := &server{pol: pol, engine: engine, store: store,
		ledger: newEvaluationLedger(store, ledgerRetention(tolerance)), responseWait: responseWait}
	addr := envOr("LISTEN_ADDR", ":8084")
	httpSrv := &http.Server{
		Addr:        addr,
		Handler:     authMiddleware(creds, verifier, srv.routes()),
		ReadTimeout: 5 * time.Second,
		// Above responseWait, so an approve that waits for its driver can
		// still answer.
		WriteTimeout: responseWait + 5*time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting killswitch-controller", "addr", addr,
			"operator_auth", creds.operator != "", "ingest_auth", creds.ingest != "",
			"agent_interface", creds.agent != "",
			"signature_required", verifier != nil, "signature_tolerance", tolerance)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
	engine.Shutdown(10 * time.Second)
	if forwarder != nil {
		if _, err := forwarder.Flush(shutdownCtx); err != nil {
			slog.Warn("audit entries left in the local outbox at shutdown; forwarded after the next start", "error", err)
		}
	}
}

// buildDrivers configures the enforcement drivers.
func buildDrivers(pol *policy.Policy, guard *drivers.TargetGuard, store *actions.Store, agURL string,
	creds credentials, infraErr error) map[string]drivers.Driver {
	driverMap := make(map[string]drivers.Driver)

	agUser := os.Getenv("ADGUARD_USER")
	agPass := os.Getenv("ADGUARD_PASSWORD")
	if agUser == "" || agPass == "" {
		slog.Error("ADGUARD_USER/ADGUARD_PASSWORD not set — the DNS sinkhole driver " +
			"cannot authenticate and enforcement will fail")
	}
	driverMap[events.ActionDNSSinkhole] = drivers.NewSinkholeDriver(agURL, agUser, agPass, store)

	if v := os.Getenv("ARP_INTERFACE"); v != "" {
		slog.Error("ARP_INTERFACE is no longer read: this service sends no frames. ARP isolation "+
			"goes through the netagent (set NETAGENT_KILLSWITCH_TOKEN and start the agent with "+
			"NETAGENT_ENABLE_ARP_ISOLATION=true)", "value", v)
	}
	if creds.agent != "" {
		// The agent interface stays up even when isolations are not offered
		// here, so isolations already in force can still be released and
		// reconciled.
		notOffered := deviceDriverReady(pol, infraErr)
		if notOffered != nil {
			slog.Error("arp_isolate will be REFUSED (releases still work)", "error", notOffered)
		}
		driverMap[events.ActionARPIsolate] = drivers.NewARPIsolateDriver(store, guard, notOffered)
	}

	swURL := os.Getenv("SWITCH_WEBHOOK_URL")
	if swURL != "" {
		if err := deviceDriverReady(pol, infraErr); err != nil {
			slog.Error("switch driver unavailable — switch_acl actions will be REFUSED", "error", err)
			swURL = ""
		}
	}
	if swURL != "" {
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
				swURL, vlan, os.Getenv("SWITCH_WEBHOOK_SECRET"), guard)
			if os.Getenv("SWITCH_WEBHOOK_SECRET") == "" {
				slog.Warn("SWITCH_WEBHOOK_SECRET not set — switch port operations are unsigned; " +
					"anyone able to reach the webhook can disable ports")
			}
		}
	}
	return driverMap
}

// authMiddleware enforces the three roles. POST /evaluate takes the ingest
// token plus a valid signature (nil verifier: none required); POST
// /agent/v1/poll takes the agent token and does not exist while none is
// configured; every other endpoint except /healthz and /metrics takes the
// operator token — reads included, since /allowlist and /actions disclose
// which devices cannot be blocked and what is currently enforced. An empty
// operator or ingest token means that role is unauthenticated, which
// loadAuth only permits in insecure mode.
//
// The role is decided by the route the mux will actually serve, not by
// comparing the raw path: a spelling the mux maps to /evaluate must not
// escape the ingest checks, and a token must not reach anything the mux
// maps elsewhere.
func authMiddleware(creds credentials, verifier *events.SignatureVerifier, mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, route := mux.Handler(r)
		if route == healthRoute || route == metricsRoute {
			mux.ServeHTTP(w, r)
			return
		}

		want, role := creds.operator, "operator"
		others := []string{creds.ingest, creds.agent}
		switch route {
		case evaluateRoute:
			want, role, others = creds.ingest, "ingest", []string{creds.operator, creds.agent}
		case agentRoute:
			if creds.agent == "" {
				// Never open, not even in insecure mode: an agent result can
				// mark an isolation lifted or confirm one.
				writeJSONError(w, http.StatusNotFound, "the netagent interface is not configured")
				return
			}
			want, role, others = creds.agent, "agent", []string{creds.operator, creds.ingest}
		}
		if header := r.Header.Get("Authorization"); want != "" && !validBearer(header, want) {
			reason := "bad_token"
			for _, other := range others {
				if other != "" && validBearer(header, other) {
					// A genuine token used outside its role: the ingest
					// credential trying to approve, or an operator credential
					// submitting events. Worth telling apart on a dashboard.
					reason = "wrong_role"
				}
			}
			rejectedRequests.WithLabelValues(reason).Inc()
			slog.Warn("rejected request", "reason", reason, "requires", role,
				"path", r.URL.Path, "remote", r.RemoteAddr)
			writeJSONError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			mux.ServeHTTP(w, r)
			return
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
		if verifier != nil && route == evaluateRoute {
			if err := verifier.Verify(r.Header.Get(events.SignatureHeader), body); err != nil {
				reason := "bad_signature"
				if errors.Is(err, events.ErrStaleSignature) {
					// A genuine MAC outside the window: a replay, or the two
					// clocks have drifted apart. Worth telling apart on a
					// dashboard.
					reason = "stale_signature"
				}
				rejectedRequests.WithLabelValues(reason).Inc()
				slog.Warn("rejected detection event with invalid signature",
					"error", err, "remote", r.RemoteAddr)
				writeJSONError(w, http.StatusUnauthorized, "invalid webhook signature: "+err.Error())
				return
			}
		}

		mux.ServeHTTP(w, r)
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

// autoBlockSetting is POLICY_AUTO_BLOCK as it was read.
func autoBlockSetting(pol *policy.Policy) string {
	if pol.AutoBlock {
		return policy.AutoBlockOn
	}
	return policy.AutoBlockOff
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
		slog.Warn("invalid duration env, using default", "key", key, "value", v, "default", fallback)
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
