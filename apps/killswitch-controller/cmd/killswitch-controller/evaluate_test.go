package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

// TestReplayedSignedEventCreatesOneAction: the same signed event delivered
// three times used to produce three active actions and three driver calls.
// Inside the signature window a repeat must return the first decision and
// create nothing.
func TestReplayedSignedEventCreatesOneAction(t *testing.T) {
	drv := &recordingDriver{}
	h := newHarness(t, harnessOpts{driver: drv})

	body, _ := json.Marshal(criticalIoCEvent())
	sig := events.SignPayload(testWebhookSecret, body)

	first := h.evaluateRaw(body, sig)
	if first.status != http.StatusOK || first.Decision.Action != "auto_block" || first.Action == nil {
		t.Fatalf("first delivery: %+v", first)
	}
	for i := 0; i < 2; i++ {
		again := h.evaluateRaw(body, sig)
		if again.status != http.StatusOK || !again.Duplicate {
			t.Fatalf("repeat %d: %+v, want 200 marked duplicate", i+1, again)
		}
		if again.Decision != first.Decision || again.Action == nil || again.Action.ID != first.Action.ID {
			t.Fatalf("repeat %d must return the original decision and action, got %+v", i+1, again)
		}
	}
	if n := h.actionCount(); n != 1 {
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
	h := newHarness(t, harnessOpts{driver: drv})

	ev := criticalIoCEvent()
	ev.Timestamp = time.Now().Add(-90 * 24 * time.Hour)
	body, _ := json.Marshal(ev)
	old := events.SignPayloadAt(testWebhookSecret, time.Now().Add(-90*24*time.Hour), body)

	got := h.evaluateRaw(body, old)
	if got.status != http.StatusUnauthorized || !strings.Contains(got.Error, "tolerance") {
		t.Fatalf("a 90-day-old signature must be refused as stale, got %+v", got)
	}
	if n := h.actionCount(); n != 0 || drv.applied.Load() != 0 {
		t.Fatalf("a refused replay created %d actions / %d applies", n, drv.applied.Load())
	}
	// The body-only 1.x scheme must not be a way around the window.
	if legacy := h.evaluateRaw(body, "sha256=00"); legacy.status != http.StatusUnauthorized {
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
	h := newHarness(t, harnessOpts{driver: drv})
	body, _ := json.Marshal(criticalIoCEvent())

	var wg sync.WaitGroup
	var ids sync.Map
	var dup atomic.Int32
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := h.evaluateRaw(body, events.SignPayload(testWebhookSecret, body))
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
	h := newHarness(t, harnessOpts{})
	ev := testEvent(60, events.SeverityMedium)
	if got := h.evaluate(ev); got.status != http.StatusOK {
		t.Fatalf("first: %+v", got)
	}
	got := h.evaluate(withDomainTarget(ev, "other.example"))
	if got.status != http.StatusConflict || !strings.Contains(got.Error, ev.ID) {
		t.Fatalf("reused id with different content: %+v, want 409", got)
	}
	if n := h.actionCount(); n != 1 {
		t.Errorf("%d actions, want 1", n)
	}
}

// TestInvalidEventRejectedWithReason: /evaluate validated nothing, so an
// event without an id, a summary or any evidence was evaluated anyway.
func TestInvalidEventRejectedWithReason(t *testing.T) {
	drv := &recordingDriver{}
	h := newHarness(t, harnessOpts{driver: drv})

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
			got := h.evaluate(ev)
			if got.status != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422 (%+v)", got.status, got)
			}
			if !strings.Contains(got.Error, tt.want) {
				t.Errorf("error %q should say why (%q)", got.Error, tt.want)
			}
		})
	}
	if n := h.actionCount(); n != 0 || drv.applied.Load() != 0 {
		t.Fatalf("invalid events created %d actions / %d applies", n, drv.applied.Load())
	}
}

// miniAdGuard is a stand-in for AdGuard Home's filtering API, so these tests
// run the real sinkhole driver.
type miniAdGuard struct {
	mu       sync.Mutex
	rules    []string
	writes   int
	setDelay time.Duration
	failSets int
	srv      *httptest.Server
}

func newMiniAdGuard(t *testing.T, rules ...string) *miniAdGuard {
	t.Helper()
	f := &miniAdGuard{rules: rules}
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
		if f.failSets > 0 {
			f.failSets--
			f.mu.Unlock()
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		f.rules, f.writes = body.Rules, f.writes+1 // AdGuard has applied the change…
		delay := f.setDelay
		f.mu.Unlock()
		time.Sleep(delay) // …but may be slow to answer
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

func (f *miniAdGuard) set(fn func(f *miniAdGuard)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// sinkHarness runs the real sinkhole driver, owning its rules in the
// harness store.
func sinkHarness(t *testing.T, ag *miniAdGuard, o harnessOpts) *harness {
	t.Helper()
	o.driversFor = func(s *actions.Store) map[string]drivers.Driver {
		return map[string]drivers.Driver{events.ActionDNSSinkhole: drivers.NewSinkholeDriver(ag.srv.URL, "u", "p", s)}
	}
	return newHarness(t, o)
}

// TestDomainTargetIsWhatGetsSinkholed: the rule is built from the target
// (the listed indicator), not from the queried name in `domain`.
func TestDomainTargetIsWhatGetsSinkholed(t *testing.T) {
	ag := newMiniAdGuard(t)
	h := sinkHarness(t, ag, harnessOpts{})

	ev := withDomainTarget(testEvent(95, events.SeverityCritical), "evil.example")
	ev.Domain = "cdn7.a.evil.example"
	ev.ClientName = "kids-tablet"
	got := h.evaluate(ev)

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
	h := sinkHarness(t, ag, harnessOpts{})

	ev := testEvent(95, events.SeverityCritical)
	ev.Domain = "cdn.legit.example" // the observed name: context only
	ev.MatchedIoC, ev.IoCType = "203.0.113.7", events.IndicatorIP
	ev.Signals[0].Indicator, ev.Signals[0].IndicatorType = "203.0.113.7", events.IndicatorIP
	ev.Target = &events.Target{Type: events.TargetIP, Value: "203.0.113.7"}
	got := h.evaluate(ev)

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
	h := sinkHarness(t, ag, harnessOpts{})

	ev := testEvent(95, events.SeverityCritical)
	ev.Summary = `IDS signature "ET MALWARE Cobalt Strike Beacon Observed" (192.168.1.100:51544 → 203.0.113.7:443)`
	ev.Domain, ev.MatchedIoC, ev.IoCType = "", "2031999", events.IndicatorSID
	ev.SignalClass = events.SignalIDS
	ev.Signals = []events.Signal{{Class: events.SignalIDS, Confidence: 95, Indicator: "2031999",
		IndicatorType: events.IndicatorSID, Source: "et-open"}}
	ev.Target = nil
	got := h.evaluate(ev)

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

func ledgerStore(t *testing.T) *actions.Store {
	t.Helper()
	s, err := actions.Open(filepath.Join(t.TempDir(), "ks.db"), actions.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestLedgerForgetsAfterRetention(t *testing.T) {
	now := time.Now()
	l := newEvaluationLedger(ledgerStore(t), time.Minute)
	l.now = func() time.Time { return now }
	digest := sha256.Sum256([]byte("x"))

	e, first, err := l.claim("DET-a-1", digest)
	if err != nil || !first {
		t.Fatal("first claim", err)
	}
	if _, again, _ := l.claim("DET-a-1", digest); again {
		t.Fatal("an in-flight id must not be claimed twice")
	}
	if err := l.finish("DET-a-1", e, digest, policy.Decision{Action: "ignore"}, ""); err != nil {
		t.Fatal(err)
	}
	if past, again, _ := l.claim("DET-a-1", digest); again || past.decision.Action != "ignore" {
		t.Fatal("a finished id is answered from the ledger inside the retention")
	}
	now = now.Add(2 * time.Minute)
	if _, first, _ := l.claim("DET-a-1", digest); !first {
		t.Error("an id past retention is evaluated afresh (the signature window has closed by then)")
	}
}

// TestLedgerSurvivesARestart: idempotency lived in memory, so a restart
// inside the signature window let a replay be evaluated again.
func TestLedgerSurvivesARestart(t *testing.T) {
	s := ledgerStore(t)
	digest := sha256.Sum256([]byte("x"))
	l := newEvaluationLedger(s, time.Hour)
	e, _, _ := l.claim("DET-a-1", digest)
	l.finish("DET-a-1", e, digest, policy.Decision{Action: "pending", Reason: "r"}, "ACT-x-1")

	restarted := newEvaluationLedger(s, time.Hour)
	past, first, err := restarted.claim("DET-a-1", digest)
	if err != nil || first {
		t.Fatalf("after a restart the id must still be known: first=%v err=%v", first, err)
	}
	d, id, ok := restarted.outcome(past)
	if !ok || d.Reason != "r" || id != "ACT-x-1" || past.digest != digest {
		t.Fatalf("outcome after restart: %+v %s %v", d, id, ok)
	}
}

func TestLedgerKeepsInFlightEntries(t *testing.T) {
	now := time.Now()
	l := newEvaluationLedger(ledgerStore(t), time.Minute)
	l.now = func() time.Time { return now }
	digest := sha256.Sum256([]byte("x"))
	if _, first, _ := l.claim("DET-a-1", digest); !first {
		t.Fatal("first claim")
	}
	now = now.Add(time.Hour)
	if _, first, _ := l.claim("DET-a-1", digest); first {
		t.Error("an evaluation still in progress must never be forgotten")
	}
}

func TestLedgerAbandonAllowsRetry(t *testing.T) {
	l := newEvaluationLedger(ledgerStore(t), time.Minute)
	digest := sha256.Sum256([]byte("x"))
	e, _, _ := l.claim("DET-a-1", digest)
	l.abandon("DET-a-1", e)
	if _, _, ok := l.outcome(e); ok {
		t.Error("an abandoned evaluation has no outcome")
	}
	if _, first, _ := l.claim("DET-a-1", digest); !first {
		t.Error("after an abandoned evaluation the next delivery is evaluated")
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
