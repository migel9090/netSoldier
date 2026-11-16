package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/enforce"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

func hasRule(ag *miniAdGuard, rule string) bool {
	rules, _ := ag.current()
	return slices.Contains(rules, rule)
}

// TestRevertFailureStaysEnforced is the auditors' probe A: AdGuard answering
// 502 during a manual revert made the action "failed"; the TTL reaper never
// retried it; a second revert answered "reverted" without calling the
// driver — the block was permanent and the operator was told it was lifted.
func TestRevertFailureStaysEnforced(t *testing.T) {
	ag := newMiniAdGuard(t)
	h := sinkHarness(t, ag, harnessOpts{engine: enforce.Config{RetryBase: 10 * time.Millisecond}})
	got := h.evaluate(criticalIoCEvent())
	if got.Action == nil || got.Action.State != events.StateActive || !hasRule(ag, "||evil.com^") {
		t.Fatalf("setup: %+v", got)
	}
	id := got.Action.ID

	ag.set(func(f *miniAdGuard) { f.failSets = 2 })
	status, a := h.revert(id, "bob")
	if status != http.StatusBadGateway || a.State != events.StateRevertFailed || !strings.Contains(a.Error, "STILL IN FORCE") {
		t.Fatalf("revert during an AdGuard outage: %d %+v", status, a)
	}
	for _, list := range []string{"active", "failed"} {
		if l := h.list(list); len(l) != 1 || l[0].ID != id {
			t.Errorf("/actions/%s must list the still-enforced action: %+v", list, l)
		}
	}
	// A second revert calls the driver again; AdGuard still fails.
	status, a = h.revert(id, "bob")
	if status != http.StatusBadGateway || a.State != events.StateRevertFailed {
		t.Fatalf("second revert: %d %s", status, a.State)
	}
	if !hasRule(ag, "||evil.com^") {
		t.Fatal("setup: the rule must still be there")
	}
	// AdGuard is back: the reaper retries on its own and finishes the job.
	time.Sleep(50 * time.Millisecond)
	h.engine.Reap(context.Background())
	h.idle(id)
	final := h.action(id)
	if final.State != events.StateReverted || final.RevertedBy != actions.ActorTTL || hasRule(ag, "||evil.com^") {
		t.Fatalf("after recovery: %s by %s, rule present=%v", final.State, final.RevertedBy, hasRule(ag, "||evil.com^"))
	}
}

// TestApprovedAfterItsCreationTTLLastsTheFullTTL is probe B: expires_at was
// computed at creation, so an action approved after its TTL was reverted
// by the next reaper tick.
func TestApprovedAfterItsCreationTTLLastsTheFullTTL(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Allowlist.AddIP("192.168.1.1")
	pol.DefaultTTL = 1
	drv := &recordingDriver{}
	h := newHarness(t, harnessOpts{pol: pol, driver: drv})
	got := h.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium), "late.example"))
	id := got.Action.ID

	time.Sleep(1200 * time.Millisecond) // past the TTL, counted from creation
	status, a := h.approve(id, nil)
	if status != 200 || a.State != events.StateActive {
		t.Fatalf("approve: %d %+v", status, a)
	}
	if a.ActivatedAt == nil || a.ExpiresAt == nil || a.ExpiresAt.Sub(*a.ActivatedAt) != time.Second {
		t.Fatalf("expires_at must be activated_at + TTL: %v / %v", a.ActivatedAt, a.ExpiresAt)
	}
	h.engine.Reap(context.Background())
	h.idle(id)
	if st := h.action(id).State; st != events.StateActive || drv.reverted.Load() != 0 {
		t.Fatalf("reverted at once although approved just now: %s", st)
	}
	time.Sleep(1100 * time.Millisecond)
	h.engine.Reap(context.Background())
	h.idle(id)
	if st := h.action(id); st.State != events.StateReverted || st.RevertedBy != actions.ActorTTL {
		t.Fatalf("after its TTL: %s by %s", st.State, st.RevertedBy)
	}
}

// TestCallerGivingUpDoesNotOrphanTheBlock is probe N: the driver ran on the
// request's context; when the caller gave up after AdGuard had accepted
// the rule, the action became failed and the rule stayed for good.
func TestCallerGivingUpDoesNotOrphanTheBlock(t *testing.T) {
	ag := newMiniAdGuard(t)
	ag.set(func(f *miniAdGuard) { f.setDelay = 800 * time.Millisecond })
	h := sinkHarness(t, ag, harnessOpts{})

	body, _ := json.Marshal(criticalIoCEvent())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, h.srv.URL+"/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testIngestToken)
	req.Header.Set(events.SignatureHeader, events.SignPayload(testWebhookSecret, body))
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Fatal("setup: the caller should have timed out")
	}
	deadline := time.Now().Add(5 * time.Second)
	var active []events.EnforcementAction
	for time.Now().Before(deadline) {
		if active = h.list("active"); len(active) == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(active) != 1 || active[0].State != events.StateActive || !hasRule(ag, "||evil.com^") {
		t.Fatalf("the apply must finish on its own deadline: %+v", active)
	}
}

// TestDriverTimeoutIsUndone: an apply that outlives its own deadline may
// have taken effect; it is undone, and the action says nothing is enforced.
//
// Here AdGuard stores each write at once but answers late: the apply times
// out after the rule landed, and so does the undo after the rule was
// removed. Neither answer can be trusted, so the action counts as still
// enforced (revert_failed) until the reaper's retry confirms it is not.
func TestDriverTimeoutIsUndone(t *testing.T) {
	ag := newMiniAdGuard(t)
	ag.set(func(f *miniAdGuard) { f.setDelay = 400 * time.Millisecond })
	h := sinkHarness(t, ag, harnessOpts{engine: enforce.Config{DriverTimeout: 150 * time.Millisecond,
		RetryBase: 10 * time.Millisecond}})
	id := h.evaluate(criticalIoCEvent()).Action.ID
	h.idle(id)
	a := h.action(id)
	if a.State != events.StateRevertFailed || a.ActivatedAt != nil || !strings.Contains(a.FailureReason, "undoing it failed") {
		t.Fatalf("a timed-out apply whose undo timed out: %s %q", a.State, a.FailureReason)
	}
	if hasRule(ag, "||evil.com^") {
		t.Fatal("setup: the undo should have removed the rule before timing out")
	}
	ag.set(func(f *miniAdGuard) { f.setDelay = 0 })
	time.Sleep(20 * time.Millisecond)
	h.engine.Reap(context.Background())
	h.idle(id)
	if a := h.action(id); a.State != events.StateApplyFailed || hasRule(ag, "||evil.com^") {
		t.Fatalf("after the retry: %s, rule present=%v", a.State, hasRule(ag, "||evil.com^"))
	}
}

// TestDoubleApproveOverHTTPAppliesOnce is probe E: two clicks used to run
// the driver twice; the second call's failure flipped the enforced action.
func TestDoubleApproveOverHTTPAppliesOnce(t *testing.T) {
	drv := &flakyDriver{delay: 150 * time.Millisecond, failApplyOn: 2}
	h := newHarness(t, harnessOpts{driver: drv})
	a := h.createPending("02:00:00:00:00:21", "192.168.1.21", "x.example")

	var wg sync.WaitGroup
	states := make([]string, 2)
	for i := range states {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, r := h.approve(a.ID, nil)
			states[i] = r.State
		}()
		time.Sleep(20 * time.Millisecond)
	}
	wg.Wait()
	if n := drv.applies(); n != 1 {
		t.Fatalf("driver applied %d times", n)
	}
	if got := h.action(a.ID); got.State != events.StateActive || states[0] != events.StateActive || states[1] != events.StateActive {
		t.Fatalf("final %s, answers %v", got.State, states)
	}
}

type flakyDriver struct {
	mu          sync.Mutex
	n           int
	delay       time.Duration
	failApplyOn int
}

func (d *flakyDriver) Apply(context.Context, *events.EnforcementAction) error {
	d.mu.Lock()
	d.n++
	n := d.n
	d.mu.Unlock()
	time.Sleep(d.delay)
	if n == d.failApplyOn {
		return drivers.NotApplied(errors.New("webhook 409: already quarantined"))
	}
	return nil
}

func (d *flakyDriver) Revert(context.Context, *events.EnforcementAction) error { return nil }
func (d *flakyDriver) Name() string                                            { return "flaky" }
func (d *flakyDriver) applies() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n
}

// TestSlowDriverAnswers202: an approve whose driver is slower than the
// response wait answers with the action as it stands, and finishes anyway.
func TestSlowDriverAnswers202(t *testing.T) {
	h := newHarness(t, harnessOpts{driver: &slowDriver{delay: 300 * time.Millisecond}, wait: 50 * time.Millisecond})
	a := h.createPending("02:00:00:00:00:22", "192.168.1.22", "x.example")
	status, got := h.approve(a.ID, nil)
	if status != http.StatusAccepted || got.State != events.StateApproved {
		t.Fatalf("approve: %d %s", status, got.State)
	}
	h.idle(a.ID)
	if st := h.action(a.ID).State; st != events.StateActive {
		t.Fatalf("after the driver answered: %s", st)
	}
}

// revertScript is a driver whose reverts fail fast, or answer slowly, as the
// test says.
type revertScript struct {
	recordingDriver
	mu    sync.Mutex
	fail  bool
	delay time.Duration
}

func (d *revertScript) set(fail bool, delay time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fail, d.delay = fail, delay
}

func (d *revertScript) Revert(ctx context.Context, a *events.EnforcementAction) error {
	d.mu.Lock()
	fail, delay := d.fail, d.delay
	d.mu.Unlock()
	time.Sleep(delay)
	if fail {
		return errors.New("adguard 502")
	}
	return d.recordingDriver.Revert(ctx, a)
}

// TestSlowRetryOfAFailedRevertAnswers202: retrying the revert of a
// revert_failed action, with a driver slower than the response wait, was
// answered 502 with the previous attempt's failure, because the answer
// looked at the state (still revert_failed while the retry runs) before
// asking whether the retry had finished. Still running is 202.
func TestSlowRetryOfAFailedRevertAnswers202(t *testing.T) {
	drv := &revertScript{}
	h := newHarness(t, harnessOpts{driver: drv, wait: 50 * time.Millisecond})
	got := h.evaluate(criticalIoCEvent())
	if got.Action == nil || got.Action.State != events.StateActive {
		t.Fatalf("setup: %+v", got)
	}
	id := got.Action.ID

	drv.set(true, 0)
	if status, a := h.revert(id, "bob"); status != http.StatusBadGateway || a.State != events.StateRevertFailed {
		t.Fatalf("setup: a fast failing revert: %d %s", status, a.State)
	}

	drv.set(false, 400*time.Millisecond)
	status, a := h.revert(id, "bob")
	if status != http.StatusAccepted {
		t.Fatalf("a retry still running after the wait answered %d (%q), want 202", status, a.Error)
	}
	if a.State != events.StateRevertFailed || a.Error != "" {
		t.Errorf("in progress: state %s error %q, want the action as it stands and no error", a.State, a.Error)
	}
	h.idle(id)
	if final := h.action(id); final.State != events.StateReverted || final.RevertedBy != "bob" {
		t.Fatalf("after the retry: %s by %s", final.State, final.RevertedBy)
	}

	// A retry that fails within the wait is still a 502.
	h2 := newHarness(t, harnessOpts{driver: &revertScript{fail: true}, wait: time.Second})
	id2 := h2.evaluate(criticalIoCEvent()).Action.ID
	h2.revert(id2, "bob")
	if status, a := h2.revert(id2, "bob"); status != http.StatusBadGateway || a.State != events.StateRevertFailed {
		t.Fatalf("a retry that failed in time: %d %s", status, a.State)
	}
}

// TestPendingRepeatsFoldAndTheQueueIsCapped is probe C.
func TestPendingRepeatsFoldAndTheQueueIsCapped(t *testing.T) {
	h := newHarness(t, harnessOpts{store: actions.Options{MaxPending: 3}})
	var first string
	for i := 0; i < 50; i++ {
		got := h.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium), "dup.example"))
		if first == "" {
			first = got.Action.ID
		}
		if got.Action == nil || got.Action.ID != first {
			t.Fatalf("repeat %d created %+v", i, got.Action)
		}
	}
	for i := 0; i < 10; i++ {
		h.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium), fmt.Sprintf("d%d.example", i)))
	}
	if p := h.list("pending"); len(p) != 3 {
		t.Fatalf("%d pending actions, cap 3", len(p))
	}
	if st := h.action(first).State; st != events.StateExpired {
		t.Errorf("the oldest pending should have been expired to make room: %s", st)
	}
}

// TestOperatorChoosesTheActionType: approve could not pick the enforcement,
// so anything stronger than the sinkhole was unreachable; the choice must
// be one the controller can carry out.
func TestOperatorChoosesTheActionType(t *testing.T) {
	sw := &recordingDriver{}
	h := newHarness(t, harnessOpts{drivers: map[string]drivers.Driver{
		events.ActionDNSSinkhole: &recordingDriver{}, events.ActionSwitchACL: sw}})
	a := h.createPending("02:00:00:00:00:23", "192.168.1.23", "x.example")

	status, got := h.approve(a.ID, map[string]string{"action_type": events.ActionARPIsolate})
	if status != http.StatusUnprocessableEntity || !slices.Equal(got.AvailableActionTypes,
		[]string{events.ActionDNSSinkhole, events.ActionSwitchACL}) {
		t.Fatalf("an unavailable type: %d %+v", status, got)
	}
	if st := h.action(a.ID).State; st != events.StatePending {
		t.Fatalf("a refused approve changed the action: %s", st)
	}
	status, got = h.approve(a.ID, map[string]string{"action_type": events.ActionSwitchACL, "approved_by": "mallory"})
	if status != 200 || got.State != events.StateActive || got.ActionType != events.ActionSwitchACL || sw.applied.Load() != 1 {
		t.Fatalf("approve as switch_acl: %d %+v", status, got)
	}
	if got.ApprovedBy != testActor {
		t.Errorf("approved_by %q came from the body, not the actor header", got.ApprovedBy)
	}
}

// TestAuditTrailIsCompleteAndAttributable: the audit took the approver
// from the body, recorded every reject as "operator" and every revert as
// "system", and lacked the target and the policy rule.
func TestAuditTrailIsCompleteAndAttributable(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.Allowlist.AddIP("192.168.1.1")
	pol.DefaultTTL = 1
	h := newHarness(t, harnessOpts{pol: pol})

	ev := withDomainTarget(testEvent(60, events.SeverityMedium), "audited.example")
	p := h.evaluate(ev).Action
	rej := h.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium), "rejected.example")).Action
	ttl := h.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium), "ttl.example")).Action

	if status, _ := h.operate("/actions/"+p.ID+"/approve", "", nil); status != http.StatusBadRequest {
		t.Fatalf("approve without an actor: %d", status)
	}
	for _, bad := range []string{"ttl", "Auto-Policy", "reconcile", "netagent", "system", strings.Repeat("x", 65), "tab\there"} {
		if status, _ := h.operate("/actions/"+p.ID+"/approve", bad, nil); status != http.StatusBadRequest {
			t.Errorf("actor %q accepted", bad)
		}
	}
	h.operate("/actions/"+p.ID+"/approve", "alice", map[string]string{"approved_by": "mallory"})
	h.operate("/actions/"+p.ID+"/revert", "bob", map[string]string{"reason": "false positive", "reverted_by": "mallory"})
	h.operate("/actions/"+rej.ID+"/reject", "carol", map[string]string{"reason": "noise"})
	h.operate("/actions/"+ttl.ID+"/approve", "dave", nil)
	time.Sleep(1100 * time.Millisecond)
	h.engine.Reap(context.Background())
	h.idle(ttl.ID)

	var entries []actions.AuditEntry
	if status := h.get("/audit?limit=500", &entries); status != 200 {
		t.Fatalf("GET /audit: %d", status)
	}
	trail := map[string][]string{}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		trail[e.ActionID] = append(trail[e.ActionID], fmt.Sprintf("%s>%s:%s", e.FromState, e.ToState, e.Actor))
		if e.DetectionID == "" || e.DetectionSummary == "" || e.TargetIP == "" || e.ActionType == "" ||
			e.BlockedDomain == "" || e.PolicyRule == "" || e.Timestamp.IsZero() {
			t.Errorf("incomplete entry: %+v", e)
		}
		if i > 0 && entries[i-1].Seq <= e.Seq {
			t.Errorf("not newest first")
		}
	}
	want := map[string]string{
		p.ID:   ">pending:auto-policy pending>approved:alice approved>active:alice active>reverted:bob",
		rej.ID: ">pending:auto-policy pending>rejected:carol",
		ttl.ID: ">pending:auto-policy pending>approved:dave approved>active:dave active>reverted:ttl",
	}
	for id, w := range want {
		if got := strings.Join(trail[id], " "); got != w {
			t.Errorf("%s:\n got %s\nwant %s", id, got, w)
		}
	}
	if strings.Contains(fmt.Sprint(trail), "mallory") {
		t.Error("an identity from a request body reached the audit log")
	}
	var one []actions.AuditEntry
	h.get("/audit?action_id="+rej.ID, &one)
	if len(one) != 2 {
		t.Errorf("?action_id=: %d entries", len(one))
	}
	var page []actions.AuditEntry
	h.get(fmt.Sprintf("/audit?limit=2&before=%d", entries[0].Seq), &page)
	if len(page) != 2 || page[0].Seq != entries[1].Seq {
		t.Errorf("paging: %+v", page)
	}
	if a := h.action(p.ID); a.ApprovedBy != "alice" || a.RevertedBy != "bob" || a.Reason != "false positive" {
		t.Errorf("action attribution: %+v", a)
	}
	if a := h.action(rej.ID); a.RejectedBy != "carol" {
		t.Errorf("rejected_by %q", a.RejectedBy)
	}
}

// TestListsKeepTheirOrder is UI-5's backend half: map order made rows swap
// under the operator's cursor.
func TestListsKeepTheirOrder(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var ids []string
	for i := 0; i < 8; i++ {
		ids = append(ids, h.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium),
			fmt.Sprintf("o%d.example", i))).Action.ID)
	}
	for _, id := range ids[4:] {
		h.approve(id, nil)
	}
	for i := 0; i < 5; i++ {
		var pending, active []string
		for _, a := range h.list("pending") {
			pending = append(pending, a.ID)
		}
		for _, a := range h.list("active") {
			active = append(active, a.ID)
		}
		if !slices.Equal(pending, ids[:4]) {
			t.Fatalf("pending must be oldest first: %v", pending)
		}
		want := slices.Clone(ids[4:])
		slices.Reverse(want)
		if !slices.Equal(active, want) {
			t.Fatalf("active must be newest first: %v", active)
		}
	}
}

func TestRevertOfSomethingNotEnforced(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	a := h.createPending("02:00:00:00:00:24", "192.168.1.24", "x.example")
	if status, got := h.revert(a.ID, "bob"); status != http.StatusConflict || got.State != events.StatePending {
		t.Fatalf("revert of a pending action: %d %s", status, got.State)
	}
	h.approve(a.ID, nil)
	h.revert(a.ID, "bob")
	if status, got := h.revert(a.ID, "bob"); status != 200 || got.State != events.StateReverted {
		t.Fatalf("a repeated revert is answered with the action: %d %s", status, got.State)
	}
}
