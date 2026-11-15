package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// evalEnv is the production posture: bearer token, signature v2, a
// populated allowlist, and a driver the test can observe.
type evalEnv struct {
	srv    *httptest.Server
	store  *actions.Store
	key    string
	secret string
}

func newEvalEnv(t *testing.T, drv drivers.Driver) *evalEnv {
	t.Helper()
	pol := policy.DefaultPolicy()
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	return newEvalEnvWith(t, pol, func(string) (drivers.Driver, error) { return drv, nil })
}

func newEvalEnvWith(t *testing.T, pol *policy.Policy, resolve driverResolver) *evalEnv {
	t.Helper()
	store := actions.NewStore(actions.NopAuditWriter{}, actions.StoreOptions{})

	mux := http.NewServeMux()
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve,
		newEvaluationLedger(ledgerRetention(0))))
	// key is the ingest token: these tests only submit events.
	env := &evalEnv{store: store, key: "k", secret: "whsec"}
	env.srv = httptest.NewServer(authMiddleware(credentials{operator: "operator-key", ingest: env.key},
		&events.SignatureVerifier{Secret: env.secret}, mux))
	t.Cleanup(env.srv.Close)
	return env
}

type evalResponse struct {
	status    int
	Decision  policy.Decision           `json:"decision"`
	Action    *events.EnforcementAction `json:"action"`
	Duplicate bool                      `json:"duplicate"`
	Error     string                    `json:"error"`
}

func (e *evalEnv) postBody(t *testing.T, body []byte, sig string) evalResponse {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, e.srv.URL+"/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.key)
	req.Header.Set(events.SignatureHeader, sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /evaluate: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := evalResponse{status: resp.StatusCode}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return out
}

func (e *evalEnv) post(t *testing.T, ev events.DetectionEvent) evalResponse {
	t.Helper()
	body, _ := json.Marshal(ev)
	return e.postBody(t, body, events.SignPayload(e.secret, body))
}

func (e *evalEnv) actionCount() int {
	n := 0
	for _, st := range []string{events.StatePending, events.StateApproved, events.StateActive,
		events.StateFailed, events.StateReverted, events.StateRejected} {
		n += len(e.store.ListByState(st))
	}
	return n
}

// TestReplayedSignedEventCreatesOneAction: the same signed event delivered
// three times used to produce three active actions and three driver calls.
// Inside the signature window a repeat must return the first decision and
// create nothing.
func TestReplayedSignedEventCreatesOneAction(t *testing.T) {
	drv := &recordingDriver{}
	env := newEvalEnv(t, drv)

	body, _ := json.Marshal(criticalIoCEvent())
	sig := events.SignPayload(env.secret, body)

	first := env.postBody(t, body, sig)
	if first.status != http.StatusOK || first.Decision.Action != "auto_block" || first.Action == nil {
		t.Fatalf("first delivery: %+v", first)
	}
	for i := 0; i < 2; i++ {
		again := env.postBody(t, body, sig)
		if again.status != http.StatusOK || !again.Duplicate {
			t.Fatalf("repeat %d: %+v, want 200 marked duplicate", i+1, again)
		}
		if again.Decision != first.Decision || again.Action == nil || again.Action.ID != first.Action.ID {
			t.Fatalf("repeat %d must return the original decision and action, got %+v", i+1, again)
		}
	}
	if n := env.actionCount(); n != 1 {
		t.Errorf("one event, %d actions", n)
	}
	if got := drv.applied.Load(); got != 1 {
		t.Errorf("driver applied %d times, want 1", got)
	}
}

// TestStaleSignedEventRejected: a signed event captured 90 days ago was still
// accepted, because the MAC covered only the body.
func TestStaleSignedEventRejected(t *testing.T) {
	drv := &recordingDriver{}
	env := newEvalEnv(t, drv)

	ev := criticalIoCEvent()
	ev.Timestamp = time.Now().Add(-90 * 24 * time.Hour)
	body, _ := json.Marshal(ev)
	old := events.SignPayloadAt(env.secret, time.Now().Add(-90*24*time.Hour), body)

	got := env.postBody(t, body, old)
	if got.status != http.StatusUnauthorized || !strings.Contains(got.Error, "tolerance") {
		t.Fatalf("a 90-day-old signature must be refused as stale, got %+v", got)
	}
	if n := env.actionCount(); n != 0 || drv.applied.Load() != 0 {
		t.Fatalf("a refused replay created %d actions / %d applies", n, drv.applied.Load())
	}

	// The body-only 1.x scheme must not be a way around the window.
	legacy := env.postBody(t, body, "sha256=00")
	if legacy.status != http.StatusUnauthorized {
		t.Fatalf("legacy signature: %+v", legacy)
	}
}

type slowDriver struct {
	recordingDriver
	delay time.Duration
}

func (d *slowDriver) Apply(ctx context.Context, a *events.EnforcementAction) error {
	time.Sleep(d.delay)
	return d.recordingDriver.Apply(ctx, a)
}

// TestConcurrentDeliveriesOfOneEventCreateOneAction: the sender retries when
// a slow apply outlasts its timeout, so the retry can arrive while the first
// delivery is still being enforced.
func TestConcurrentDeliveriesOfOneEventCreateOneAction(t *testing.T) {
	drv := &slowDriver{delay: 200 * time.Millisecond}
	env := newEvalEnv(t, drv)
	body, _ := json.Marshal(criticalIoCEvent())

	var wg sync.WaitGroup
	var ids sync.Map
	var dup atomic.Int32
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := env.postBody(t, body, events.SignPayload(env.secret, body))
			if got.status != http.StatusOK || got.Action == nil {
				t.Errorf("delivery: %+v", got)
				return
			}
			ids.Store(got.Action.ID, true)
			if got.Duplicate {
				dup.Add(1)
			}
		}()
	}
	wg.Wait()

	distinct := 0
	ids.Range(func(_, _ any) bool { distinct++; return true })
	if distinct != 1 || dup.Load() != 4 || drv.applied.Load() != 1 {
		t.Fatalf("5 concurrent deliveries: %d distinct actions, %d duplicates, %d applies; want 1/4/1",
			distinct, dup.Load(), drv.applied.Load())
	}
}

// TestReusedEventIDWithDifferentContentRefused: a producer that reuses ids
// (the 1.x engine restarted at DET-1 on every boot) would otherwise have a
// different detection silently answered with an old decision.
func TestReusedEventIDWithDifferentContentRefused(t *testing.T) {
	env := newEvalEnv(t, &recordingDriver{})
	ev := testEvent(60, events.SeverityMedium)
	if got := env.post(t, ev); got.status != http.StatusOK {
		t.Fatalf("first: %+v", got)
	}
	other := withDomainTarget(ev, "other.example")
	got := env.post(t, other)
	if got.status != http.StatusConflict || !strings.Contains(got.Error, ev.ID) {
		t.Fatalf("reused id with different content: %+v, want 409", got)
	}
	if n := env.actionCount(); n != 1 {
		t.Errorf("%d actions, want 1", n)
	}
}

// TestInvalidEventRejectedWithReason: /evaluate validated nothing, so an
// event without an id, a summary or any evidence was evaluated anyway.
func TestInvalidEventRejectedWithReason(t *testing.T) {
	drv := &recordingDriver{}
	env := newEvalEnv(t, drv)

	tests := []struct {
		name   string
		mutate func(*events.DetectionEvent)
		want   string
	}{
		{"1.x schema", func(e *events.DetectionEvent) { e.SchemaVersion = "1.0" }, "schema_version"},
		{"restart-prone id", func(e *events.DetectionEvent) { e.ID = "DET-1" }, "id"},
		{"no summary", func(e *events.DetectionEvent) { e.Summary = "" }, "summary"},
		{"no signals", func(e *events.DetectionEvent) { e.Signals = nil }, "signals"},
		{"bad client ip", func(e *events.DetectionEvent) { e.ClientIP = "192.168.1" }, "client_ip"},
		{"decorated domain target", func(e *events.DetectionEvent) {
			e.Target = &events.Target{Type: events.TargetDomain, Value: "cdn.x (→203.0.113.7)"}
		}, "target domain"},
		{"unknown target type", func(e *events.DetectionEvent) {
			e.Target = &events.Target{Type: "mac", Value: "aa:bb:cc:dd:ee:ff"}
		}, "target type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := criticalIoCEvent()
			tt.mutate(&ev)
			got := env.post(t, ev)
			if got.status != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (%+v)", got.status, got)
			}
			if !strings.Contains(got.Error, tt.want) {
				t.Errorf("error %q should say why (%q)", got.Error, tt.want)
			}
		})
	}
	if n := env.actionCount(); n != 0 || drv.applied.Load() != 0 {
		t.Fatalf("invalid events created %d actions / %d applies", n, drv.applied.Load())
	}
}

// miniAdGuard is a stand-in for AdGuard Home's filtering API, so these tests
// run the real sinkhole driver.
type miniAdGuard struct {
	mu     sync.Mutex
	rules  []string
	writes int
	srv    *httptest.Server
}

func newMiniAdGuard(t *testing.T) *miniAdGuard {
	t.Helper()
	f := &miniAdGuard{}
	mux := http.NewServeMux()
	mux.HandleFunc("/control/filtering/status", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"user_rules": append([]string{}, f.rules...)})
	})
	mux.HandleFunc("/control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Rules []string `json:"rules"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.rules, f.writes = body.Rules, f.writes+1
		f.mu.Unlock()
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *miniAdGuard) current() ([]string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.rules...), f.writes
}

// TestDomainTargetIsWhatGetsSinkholed: the rule is built from the target
// (the listed indicator), not from the queried name in `domain`.
func TestDomainTargetIsWhatGetsSinkholed(t *testing.T) {
	ag := newMiniAdGuard(t)
	env := newEvalEnv(t, drivers.NewSinkholeDriver(ag.srv.URL, "u", "p"))

	ev := withDomainTarget(testEvent(95, events.SeverityCritical), "evil.example")
	ev.Domain = "cdn7.a.evil.example"
	ev.ClientName = "kids-tablet"
	got := env.post(t, ev)

	if got.Decision.Action != "auto_block" || got.Action == nil || got.Action.State != events.StateActive {
		t.Fatalf("expected an active auto-block, got %+v", got)
	}
	if got.Action.BlockedDomain != "evil.example" {
		t.Errorf("blocked_domain = %q, want the target", got.Action.BlockedDomain)
	}
	if got.Action.DetectionSummary != ev.Summary || got.Action.ClientName != "kids-tablet" {
		t.Errorf("summary/client name not carried: %+v", got.Action)
	}
	if rules, _ := ag.current(); len(rules) != 1 || rules[0] != "||evil.example^" {
		t.Errorf("AdGuard rules = %v, want only ||evil.example^", rules)
	}
}

// TestIPTargetIsPendingNotSinkholed: an IP-IoC hit was auto-blocked with
// blocked_domain "cdn.legit.example (→203.0.113.7)" and failed in the
// driver; a Zeek Intel address became the rule ||203.0.113.9^.
func TestIPTargetIsPendingNotSinkholed(t *testing.T) {
	ag := newMiniAdGuard(t)
	env := newEvalEnv(t, drivers.NewSinkholeDriver(ag.srv.URL, "u", "p"))

	ev := testEvent(95, events.SeverityCritical)
	ev.Domain = "cdn.legit.example" // the observed name: context only
	ev.MatchedIoC, ev.IoCType = "203.0.113.7", events.IndicatorIP
	ev.Signals[0].Indicator, ev.Signals[0].IndicatorType = "203.0.113.7", events.IndicatorIP
	ev.Target = &events.Target{Type: events.TargetIP, Value: "203.0.113.7"}
	got := env.post(t, ev)

	if got.Decision.Action != "pending" || got.Action == nil || got.Action.State != events.StatePending {
		t.Fatalf("an ip target must be queued for a human, got %+v", got)
	}
	if got.Action.BlockedDomain != "" {
		t.Errorf("blocked_domain = %q, want empty: nothing is a domain here", got.Action.BlockedDomain)
	}
	if !strings.Contains(got.Action.PolicyRule, "only a domain can be blocked automatically") {
		t.Errorf("policy_rule should say why, got %q", got.Action.PolicyRule)
	}
	if rules, writes := ag.current(); len(rules) != 0 || writes != 0 {
		t.Errorf("nothing may reach AdGuard: rules=%v writes=%d", rules, writes)
	}
}

// TestIDSEventWithoutTargetIsPending: the Suricata rule message used to be
// the event's domain and was offered to the sinkhole.
func TestIDSEventWithoutTargetIsPending(t *testing.T) {
	ag := newMiniAdGuard(t)
	env := newEvalEnv(t, drivers.NewSinkholeDriver(ag.srv.URL, "u", "p"))

	ev := testEvent(95, events.SeverityCritical)
	ev.Summary = `IDS signature "ET MALWARE Cobalt Strike Beacon Observed" (192.168.1.100:51544 → 203.0.113.7:443)`
	ev.Domain, ev.MatchedIoC, ev.IoCType = "", "2031999", events.IndicatorSID
	ev.SignalClass = events.SignalIDS
	ev.Signals = []events.Signal{{Class: events.SignalIDS, Confidence: 95, Indicator: "2031999",
		IndicatorType: events.IndicatorSID, Source: "et-open"}}
	ev.Target = nil
	got := env.post(t, ev)

	if got.Decision.Action != "pending" || got.Action == nil {
		t.Fatalf("an event without a target must be queued for a human, got %+v", got)
	}
	if got.Action.BlockedDomain != "" || !strings.Contains(got.Action.PolicyRule, "no enforceable target") {
		t.Errorf("action = %+v", got.Action)
	}
	if got.Action.DetectionSummary != ev.Summary {
		t.Errorf("the summary is what the operator reads, got %q", got.Action.DetectionSummary)
	}
	if _, writes := ag.current(); writes != 0 {
		t.Errorf("nothing may reach AdGuard, got %d writes", writes)
	}
}

func TestLedgerForgetsAfterRetention(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newEvaluationLedger(time.Minute)
	l.now = func() time.Time { return now }
	digest := sha256.Sum256([]byte("x"))

	e, first := l.claim("DET-a-1", digest)
	if !first {
		t.Fatal("first claim")
	}
	if _, again := l.claim("DET-a-1", digest); again {
		t.Fatal("an in-flight id must not be claimed twice")
	}
	l.finish(e, policy.Decision{Action: "ignore"}, "")

	now = now.Add(2 * time.Minute)
	if _, first := l.claim("DET-a-1", digest); !first {
		t.Error("an id past retention is evaluated afresh (the signature window has closed by then)")
	}
}

func TestLedgerKeepsInFlightEntries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := newEvaluationLedger(time.Minute)
	l.now = func() time.Time { return now }
	digest := sha256.Sum256([]byte("x"))

	if _, first := l.claim("DET-a-1", digest); !first {
		t.Fatal("first claim")
	}
	now = now.Add(time.Hour)
	if _, first := l.claim("DET-a-1", digest); first {
		t.Error("an evaluation still in progress must never be forgotten")
	}
}

func TestLedgerAbandonAllowsRetry(t *testing.T) {
	l := newEvaluationLedger(time.Minute)
	digest := sha256.Sum256([]byte("x"))
	e, _ := l.claim("DET-a-1", digest)
	l.abandon("DET-a-1", e)
	if _, _, ok := l.outcome(e); ok {
		t.Error("an abandoned evaluation has no outcome")
	}
	if _, first := l.claim("DET-a-1", digest); !first {
		t.Error("after an abandoned evaluation the next delivery is evaluated")
	}
}

func TestLedgerIsBounded(t *testing.T) {
	l := newEvaluationLedger(time.Hour)
	digest := sha256.Sum256([]byte("x"))
	for i := 0; i < maxLedgerEntries+10; i++ {
		e, _ := l.claim(events.FormatDetectionID("a", uint64(i)), digest)
		l.finish(e, policy.Decision{}, "")
	}
	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n > maxLedgerEntries+1 {
		t.Errorf("ledger holds %d entries, cap %d", n, maxLedgerEntries)
	}
}

func TestLedgerRetentionCoversTheSignatureWindow(t *testing.T) {
	if got := ledgerRetention(5 * time.Minute); got < 10*time.Minute {
		t.Errorf("retention %s is shorter than the replay window (2 × tolerance)", got)
	}
	if ledgerRetention(0) != ledgerRetention(events.DefaultSignatureTolerance) {
		t.Error("zero tolerance should mean the default")
	}
}
