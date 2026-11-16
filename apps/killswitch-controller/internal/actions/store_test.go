package actions

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func openAt(t *testing.T, path string, o Options) *Store {
	t.Helper()
	s, err := Open(path, o)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newStore(t *testing.T, c *clock) *Store {
	t.Helper()
	return openAt(t, filepath.Join(t.TempDir(), "ks.db"), Options{Now: c.Now})
}

var detSeq atomic.Int64

func event(client, domain string) events.DetectionEvent {
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            fmt.Sprintf("DET-store-%d", detSeq.Add(1)),
		Summary:       "test detection for " + domain,
		ClientIP:      client,
		ClientMAC:     "02:00:00:00:00:01",
		ClientName:    "laptop",
		Severity:      events.SeverityHigh,
		Confidence:    70,
		Target:        &events.Target{Type: events.TargetDomain, Value: domain},
	}
}

func pending(t *testing.T, s *Store, ev events.DetectionEvent) Record {
	t.Helper()
	res, err := s.Submit(Submission{Event: ev, ActionType: events.ActionDNSSinkhole,
		PolicyRule: "pending: confidence=70", TTLSeconds: 3600})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	return res.Record
}

func mustConflict(t *testing.T, err error, state string) {
	t.Helper()
	var c *ConflictError
	if !errors.As(err, &c) {
		t.Fatalf("want a conflict, got %v", err)
	}
	if c.Current.State != state {
		t.Fatalf("conflict reports state %q, want %q", c.Current.State, state)
	}
}

func TestSubmitCreatesPendingWithEverythingTheDialogNeeds(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	ev := event("192.168.1.50", "evil.example")
	r := pending(t, s, ev)

	if r.State != events.StatePending || r.ID == "" || !strings.HasPrefix(r.ID, "ACT-"+s.Instance()+"-") {
		t.Fatalf("unexpected action %+v", r.Action())
	}
	a := r.Action()
	if a.DetectionID != ev.ID || a.DetectionSummary != ev.Summary || a.ClientName != "laptop" ||
		a.BlockedDomain != "evil.example" || a.TargetIP != "192.168.1.50" || a.ExpiresAt != nil {
		t.Errorf("action does not carry the detection: %+v", a)
	}
	if got := r.PendingUntil.Sub(c.Now()); got != 24*time.Hour {
		t.Errorf("pending deadline %s after creation, want the default 24h", got)
	}
	entries, _ := s.Audit(AuditQuery{ActionID: r.ID})
	if len(entries) != 1 || entries[0].Actor != ActorPolicy || entries[0].ToState != events.StatePending ||
		entries[0].BlockedDomain != "evil.example" || entries[0].PolicyRule == "" {
		t.Errorf("creation audit entry: %+v", entries)
	}
}

// TestApproveIsACompareAndSwap: a double-click on approve used to run the
// driver twice, and a failure of the second call flipped an ENFORCED
// action to failed. Only one approve may ever win.
func TestApproveIsACompareAndSwap(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))

	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Approve(r.ID, "alice", "", c.Now().Add(time.Minute)); err == nil {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("%d approvals won, want exactly 1", won.Load())
	}
	got, _ := s.Get(r.ID)
	if got.State != events.StateApproved || got.ApprovedBy != "alice" || got.Op != OpApply {
		t.Fatalf("after approve: %+v op=%q", got.Action(), got.Op)
	}
	_, err := s.Approve(r.ID, "bob", "", c.Now())
	mustConflict(t, err, events.StateApproved)
}

// TestTTLStartsAtActivation: expires_at was computed at creation, so an
// action approved after its TTL was reverted by the next reaper tick.
func TestTTLStartsAtActivation(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))

	c.Advance(61 * time.Minute) // longer than the 3600 s TTL
	if _, err := s.Approve(r.ID, "alice", "", c.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.Advance(2 * time.Second)
	got, err := s.Activate(r.ID, "alice", "applied")
	if err != nil {
		t.Fatal(err)
	}
	if got.ActivatedAt == nil || !got.ActivatedAt.Equal(c.Now()) {
		t.Fatalf("activated_at = %v, want now", got.ActivatedAt)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(c.Now().Add(time.Hour)) {
		t.Fatalf("expires_at = %v, want activation + 1h", got.ExpiresAt)
	}
	if due, _ := s.Due(c.Now()); len(due.Revert) != 0 {
		t.Fatalf("a freshly activated action is due for revert: %+v", due.Revert)
	}
	if due, _ := s.Due(c.Now().Add(time.Hour)); len(due.Revert) != 1 {
		t.Fatalf("the action is not due at activation + TTL")
	}
}

// TestRevertFailedIsStillEnforced: a failed revert used to park the action
// in a terminal "failed" state the reaper never retried, and a second
// revert then reported "reverted" without calling the driver.
func TestRevertFailedIsStillEnforced(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))
	s.Approve(r.ID, "alice", "", c.Now())
	s.Activate(r.ID, "alice", "applied")

	next := c.Now().Add(10 * time.Second)
	got, err := s.RevertFailed(r.ID, "alice", "revert failed: adguard 502", next, true)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != events.StateRevertFailed || got.FailureReason == "" || got.RevertedAt != nil {
		t.Fatalf("after a failed revert: %+v", got.Action())
	}
	enforced, _ := s.ListEnforced()
	failed, _ := s.ListFailed()
	if len(enforced) != 1 || len(failed) != 1 {
		t.Fatalf("revert_failed must be listed as enforced (%d) and as failed (%d)", len(enforced), len(failed))
	}
	if due, _ := s.Due(c.Now()); len(due.Revert) != 0 {
		t.Fatal("retried before its backoff ran out")
	}
	if due, _ := s.Due(next); len(due.Revert) != 1 {
		t.Fatal("the reaper does not own the retry")
	}
	// A reaper retry that fails again is not an audit event; an operator's is.
	s.RevertFailed(r.ID, ActorTTL, "still 502", next.Add(time.Minute), false)
	s.RevertFailed(r.ID, "bob", "still 502", next.Add(time.Minute), true)
	entries, _ := s.Audit(AuditQuery{ActionID: r.ID})
	actors := []string{}
	for _, e := range entries {
		actors = append(actors, e.Actor+":"+e.FromState+">"+e.ToState)
	}
	if strings.Join(actors, ",") != "bob:revert_failed>revert_failed,alice:active>revert_failed,"+
		"alice:approved>active,alice:pending>approved,auto-policy:>pending" {
		t.Errorf("audit trail: %v", actors)
	}

	// It is never evicted however many finished actions pile up.
	s.opts.MaxTerminal = 1
	for i := 0; i < 3; i++ {
		x := pending(t, s, event("192.168.1.60", fmt.Sprintf("x%d.example", i)))
		s.Reject(x.ID, "bob", "no")
	}
	if err := s.Prune(c.Now(), PruneOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(r.ID); err != nil {
		t.Fatalf("a still-enforced action was pruned: %v", err)
	}
	if h, _ := s.ListHistory(10); len(h) != 1 {
		t.Errorf("history keeps %d finished actions, cap 1", len(h))
	}

	got, err = s.Reverted(r.ID, ActorTTL, "retry of a failed revert")
	if err != nil || got.State != events.StateReverted || got.RevertedBy != ActorTTL || got.RevertedAt == nil {
		t.Fatalf("after the retry succeeded: %+v %v", got.Action(), err)
	}
	_, err = s.Reverted(r.ID, ActorTTL, "again")
	mustConflict(t, err, events.StateReverted)
}

// TestFailedApplyThatCouldNotBeUndoneEndsAsApplyFailed: a revert_failed
// action that never became active was a failed apply; once undone, nothing
// was ever in force, and it must not appear as "reverted".
func TestFailedApplyThatCouldNotBeUndoneEndsAsApplyFailed(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))
	s.Approve(r.ID, "alice", "", c.Now())
	if _, err := s.RevertFailed(r.ID, "alice", "apply timed out and undo failed", c.Now(), true); err != nil {
		t.Fatal(err)
	}
	got, err := s.Reverted(r.ID, ActorTTL, "retry")
	if err != nil || got.State != events.StateApplyFailed || got.RevertedAt != nil {
		t.Fatalf("got %+v %v, want apply_failed", got.Action(), err)
	}
	r2 := pending(t, s, event("192.168.1.51", "evil.example"))
	s.Approve(r2.ID, "alice", "", c.Now())
	s.RevertFailed(r2.ID, "alice", "x", c.Now(), true)
	if got, err := s.ApplyFailed(r2.ID, ActorReconcile, "y"); err != nil || got.State != events.StateApplyFailed {
		t.Fatalf("ApplyFailed of a never-active revert_failed: %+v %v", got.Action(), err)
	}
}

func TestTransitionsRefuseTheWrongState(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))

	_, err := s.Activate(r.ID, "x", "")
	mustConflict(t, err, events.StatePending)
	_, err = s.Reverted(r.ID, "x", "")
	mustConflict(t, err, events.StatePending)
	_, err = s.ApplyFailed(r.ID, "x", "")
	mustConflict(t, err, events.StatePending)
	_, err = s.RevertFailed(r.ID, "x", "", c.Now(), true)
	mustConflict(t, err, events.StatePending)
	_, err = s.BeginOp(r.ID, OpRevert, "x", "", c.Now(), events.StateActive)
	mustConflict(t, err, events.StatePending)
	_, err = s.ExtendOp(r.ID, OpApply, c.Now())
	mustConflict(t, err, events.StatePending)

	if _, err := s.Reject(r.ID, "bob", "false positive"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(r.ID)
	if got.State != events.StateRejected || got.RejectedBy != "bob" || got.Reason != "false positive" {
		t.Fatalf("after reject: %+v", got.Action())
	}
	_, err = s.Approve(r.ID, "x", "", c.Now())
	mustConflict(t, err, events.StateRejected)
	_, err = s.Reject(r.ID, "x", "")
	mustConflict(t, err, events.StateRejected)

	if _, err := s.Get("ACT-nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if _, err := s.Approve("ACT-nope", "x", "", c.Now()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

// TestPendingExpires: a pending action used to wait forever.
func TestPendingExpires(t *testing.T) {
	c := newClock()
	s := openAt(t, filepath.Join(t.TempDir(), "ks.db"), Options{Now: c.Now, PendingTTL: time.Hour})
	r := pending(t, s, event("192.168.1.50", "evil.example"))

	c.Advance(59 * time.Minute)
	if due, _ := s.Due(c.Now()); len(due.Expire) != 0 {
		t.Fatal("expired early")
	}
	c.Advance(2 * time.Minute)
	if due, _ := s.Due(c.Now()); len(due.Expire) != 1 {
		t.Fatal("not due for expiry")
	}
	// An approve that arrives after the deadline finds it expired.
	_, err := s.Approve(r.ID, "alice", "", c.Now())
	mustConflict(t, err, events.StateExpired)
	entries, _ := s.Audit(AuditQuery{ActionID: r.ID, Limit: 1})
	if entries[0].Actor != ActorTTL || entries[0].ToState != events.StateExpired {
		t.Errorf("expiry audit: %+v", entries[0])
	}
	if expired, _ := s.ExpireIfDue(r.ID); expired {
		t.Error("expired twice")
	}
}

// TestPendingIsCappedAndDeduplicated: 5000 identical detections used to
// leave 5000 pending actions whatever MaxActions said.
func TestPendingIsCappedAndDeduplicated(t *testing.T) {
	c := newClock()
	s := openAt(t, filepath.Join(t.TempDir(), "ks.db"), Options{Now: c.Now, MaxPending: 3})

	first := pending(t, s, event("192.168.1.50", "evil.example"))
	for i := 0; i < 50; i++ {
		res, err := s.Submit(Submission{Event: event("192.168.1.50", "EVIL.example"),
			ActionType: events.ActionDNSSinkhole, PolicyRule: "pending"})
		if err != nil || res.Outcome != OutcomeFolded || res.Record.ID != first.ID {
			t.Fatalf("repeat %d: %+v %v", i, res, err)
		}
	}
	got, _ := s.Get(first.ID)
	if got.Repeats != 50 || got.LastDetectionID == "" {
		t.Errorf("repeats not counted: %d", got.Repeats)
	}

	// The same detection id is the same action, even after it closed.
	ev := event("192.168.1.51", "other.example")
	r := pending(t, s, ev)
	s.Reject(r.ID, "bob", "no")
	if res, _ := s.Submit(Submission{Event: ev, ActionType: events.ActionDNSSinkhole}); res.Outcome != OutcomeDuplicate || res.Record.ID != r.ID {
		t.Fatalf("same detection id: %+v", res)
	}

	// Distinct detections beyond the cap expire the oldest pending.
	var evicted []Record
	for i := 0; i < 4; i++ {
		res, err := s.Submit(Submission{Event: event("192.168.1.52", fmt.Sprintf("d%d.example", i)),
			ActionType: events.ActionDNSSinkhole})
		if err != nil {
			t.Fatal(err)
		}
		evicted = append(evicted, res.Evicted...)
	}
	if p, _ := s.ListPending(); len(p) != 3 {
		t.Fatalf("%d pending, cap 3", len(p))
	}
	if len(evicted) != 2 || evicted[0].ID != first.ID {
		t.Fatalf("evicted %+v, want the oldest first", evicted)
	}
	if got, _ := s.Get(first.ID); got.State != events.StateExpired {
		t.Errorf("evicted action is %s", got.State)
	}
	entries, _ := s.Audit(AuditQuery{ActionID: first.ID, Limit: 1})
	if entries[0].Actor != ActorSystem || !strings.Contains(entries[0].Reason, "queue full") {
		t.Errorf("eviction audit: %+v", entries[0])
	}
}

// TestAutoDecisionPromotesThePendingAction: the same client and target,
// first pending and then over the auto-block bar, is one action.
func TestAutoDecisionPromotesThePendingAction(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))
	res, err := s.Submit(Submission{Event: event("192.168.1.50", "evil.example"), Auto: true,
		ActionType: events.ActionDNSSinkhole, PolicyRule: "auto: confidence=95", TTLSeconds: 600,
		OpDeadline: c.Now().Add(time.Minute)})
	if err != nil || res.Outcome != OutcomePromoted || res.Record.ID != r.ID {
		t.Fatalf("got %+v %v", res, err)
	}
	got := res.Record
	if got.State != events.StateApproved || got.ApprovedBy != ActorPolicy || !got.AutoApproved ||
		got.TTLSeconds != 600 || got.Op != OpApply || got.PolicyRule != "auto: confidence=95" {
		t.Fatalf("promoted action: %+v op=%s", got.Action(), got.Op)
	}
	// An active one simply absorbs further detections.
	s.Activate(r.ID, ActorPolicy, "applied")
	res, _ = s.Submit(Submission{Event: event("192.168.1.50", "evil.example"), Auto: true,
		ActionType: events.ActionDNSSinkhole})
	if res.Outcome != OutcomeFolded || res.Record.State != events.StateActive {
		t.Fatalf("detection for an active block: %+v", res)
	}
	// A different client is a different action.
	res, _ = s.Submit(Submission{Event: event("192.168.1.99", "evil.example"), Auto: true,
		ActionType: events.ActionDNSSinkhole})
	if res.Outcome != OutcomeCreated || res.Record.ID == r.ID || res.Record.State != events.StateApproved {
		t.Fatalf("other client: %+v", res)
	}
}

func TestDedupeKey(t *testing.T) {
	a := event("192.168.1.50", "Evil.Example")
	b := event("192.168.1.50", "evil.example")
	if DedupeKey(a) != DedupeKey(b) {
		t.Error("the target is compared case-insensitively")
	}
	c := b
	c.ClientIP = "192.168.1.51"
	if DedupeKey(b) == DedupeKey(c) {
		t.Error("different clients share a key")
	}
	noTarget := b
	noTarget.Target, noTarget.MatchedIoC, noTarget.IoCType = nil, "2031999", events.IndicatorSID
	if !strings.Contains(DedupeKey(noTarget), "ioc:sid:2031999") {
		t.Errorf("no target: %s", DedupeKey(noTarget))
	}
	nothing := noTarget
	nothing.MatchedIoC = ""
	if DedupeKey(nothing) != "detection:"+nothing.ID {
		t.Errorf("no indicator at all: %s", DedupeKey(nothing))
	}
}

// TestListsAreOrdered: the lists came back in map order, so rows swapped
// under the operator's cursor.
func TestListsAreOrdered(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	var ids []string
	for i := 0; i < 6; i++ {
		c.Advance(time.Second)
		ids = append(ids, pending(t, s, event("192.168.1.50", fmt.Sprintf("d%d.example", i))).ID)
	}
	// 0,1 active; 2 revert_failed; 3 rejected; 4 apply_failed; 5 pending.
	for _, id := range ids[:3] {
		s.Approve(id, "a", "", c.Now())
		s.Activate(id, "a", "")
	}
	s.RevertFailed(ids[2], "a", "x", c.Now(), true)
	c.Advance(time.Second)
	s.Reject(ids[3], "a", "")
	s.Approve(ids[4], "a", "", c.Now())
	c.Advance(time.Second)
	s.ApplyFailed(ids[4], "a", "x")

	check := func(name string, recs []Record, err error, want ...string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		got := []string{}
		for _, r := range recs {
			got = append(got, r.ID)
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: %v, want %v", name, got, want)
		}
	}
	for i := 0; i < 3; i++ { // same answer on every call
		p, err := s.ListPending()
		check("pending (oldest first)", p, err, ids[5])
		e, err := s.ListEnforced()
		check("active (newest first)", e, err, ids[2], ids[1], ids[0])
		f, err := s.ListFailed()
		check("failed (newest first)", f, err, ids[4], ids[2])
		h, err := s.ListHistory(10)
		check("history (latest outcome first)", h, err, ids[4], ids[3])
	}
	empty := newStore(t, c)
	for _, f := range []func() ([]Record, error){empty.ListPending, empty.ListEnforced, empty.ListFailed} {
		if recs, _ := f(); recs == nil {
			t.Error("an empty list must be [], not null")
		}
	}
	if recs, _ := s.ListStates(); recs == nil || len(recs) != 0 {
		t.Error("ListStates() with no states")
	}
	if recs, _ := s.ListStates(events.StateRejected, events.StatePending); len(recs) != 2 {
		t.Errorf("ListStates: %d", len(recs))
	}
}

// TestEverythingSurvivesARestart: the store was in memory, so a crash lost
// every record of what was enforced.
func TestEverythingSurvivesARestart(t *testing.T) {
	c := newClock()
	path := filepath.Join(t.TempDir(), "ks.db")
	s, err := Open(path, Options{Now: c.Now})
	if err != nil {
		t.Fatal(err)
	}
	instance := s.Instance()
	r := pending(t, s, event("192.168.1.50", "evil.example"))
	s.Approve(r.ID, "alice", "", c.Now().Add(time.Minute))
	s.Activate(r.ID, "alice", "applied")
	s.ClaimSinkholeRule(r.ID, "||evil.example^", true)
	cmd, _ := s.EnqueueCommand(agentIsolate(r.ID))
	s.PutEvaluation(Evaluation{DetectionID: "DET-x-1", Digest: []byte{1, 2}, Decision: []byte(`{"Action":"pending"}`), ActionID: r.ID})
	o := pending(t, s, event("192.168.1.51", "other.example"))
	s.BeginOp(o.ID, OpApply, "bob", "", c.Now().Add(time.Minute), events.StatePending)
	s.Close()

	s = openAt(t, path, Options{Now: c.Now})
	if s.Instance() != instance {
		t.Errorf("instance id changed across a restart: %s → %s", instance, s.Instance())
	}
	got, err := s.Get(r.ID)
	if err != nil || got.State != events.StateActive || got.ExpiresAt == nil || got.ApprovedBy != "alice" {
		t.Fatalf("after restart: %+v %v", got.Action(), err)
	}
	if rule, ok, _ := s.SinkholeRef(r.ID); !ok || rule != "||evil.example^" {
		t.Errorf("rule ownership lost: %q %v", rule, ok)
	}
	if open, _ := s.OpenCommands(); len(open) != 1 || open[0].ID != cmd.ID {
		t.Errorf("command queue lost: %+v", open)
	}
	if e, ok, _ := s.GetEvaluation("DET-x-1"); !ok || e.ActionID != r.ID || string(e.Decision) != `{"Action":"pending"}` {
		t.Errorf("evaluation lost: %+v", e)
	}
	if with, _ := s.WithOp(); len(with) != 1 || with[0].ID != o.ID || with[0].OpActor != "bob" {
		t.Errorf("interrupted operation lost: %+v", with)
	}
	if entries, _ := s.Audit(AuditQuery{}); len(entries) != 4 {
		t.Errorf("audit log has %d entries after restart, want 4", len(entries))
	}
	// New ids continue the sequence instead of reusing old ones.
	if n := pending(t, s, event("192.168.1.52", "third.example")); n.ID == r.ID || n.ID == o.ID {
		t.Errorf("id reused: %s", n.ID)
	}
}

func TestOpenRefusesANewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ks.db")
	s := openAt(t, path, Options{})
	if _, err := s.db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(path, Options{}); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("a newer schema must be refused, got %v", err)
	}
	if _, err := Open(filepath.Join(t.TempDir(), "f", "\x00", "x.db"), Options{}); err == nil {
		t.Error("an unusable path must fail")
	}
}

func TestOpsAreRecordedBeforeTheDriverRuns(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))
	s.Approve(r.ID, "alice", "", c.Now().Add(time.Minute))
	s.Activate(r.ID, "alice", "")

	got, err := s.BeginOp(r.ID, OpRevert, "bob", "fp", c.Now().Add(time.Second), events.StateActive)
	if err != nil || got.Op != OpRevert || got.OpActor != "bob" || got.OpReason != "fp" {
		t.Fatalf("BeginOp: %+v %v", got, err)
	}
	if _, err := s.BeginOp(r.ID, OpApply, "x", "", c.Now(), events.StateActive); err == nil {
		t.Fatal("a second, different operation was allowed")
	}
	if due, _ := s.Due(c.Now().Add(2 * time.Second)); len(due.Overdue) != 1 {
		t.Fatal("an operation past its deadline is not reported overdue")
	}
	if got, _ := s.ExtendOp(r.ID, OpRevert, c.Now().Add(time.Hour)); !got.OpDeadline.Equal(c.Now().Add(time.Hour)) {
		t.Error("deadline not extended")
	}
	if got, _ := s.ClearOp(r.ID); got.Op != OpNone {
		t.Error("op not cleared")
	}
	if entries, _ := s.Audit(AuditQuery{ActionID: r.ID}); len(entries) != 3 {
		t.Errorf("bookkeeping must not be audited as transitions: %d entries", len(entries))
	}
}

func TestEnforcedOnAndInForce(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	ev := event("192.168.1.50", "evil.example")
	ev.ClientMAC = "02:AA:00:00:00:01"
	r := pending(t, s, ev)
	if _, found, _ := s.EnforcedOn(events.ActionDNSSinkhole, "02:aa:00:00:00:01"); found {
		t.Fatal("a pending action is not in force")
	}
	s.Approve(r.ID, "a", "", c.Now())
	if got, found, _ := s.EnforcedOn(events.ActionDNSSinkhole, "02:aa:00:00:00:01"); !found || got.ID != r.ID {
		t.Fatal("EnforcedOn must match the MAC case-insensitively")
	}
	if recs, _ := s.InForce(events.ActionDNSSinkhole); len(recs) != 1 {
		t.Fatalf("InForce: %d", len(recs))
	}
	if counts, _ := s.Counts(); counts[events.StateApproved] != 1 {
		t.Errorf("counts: %v", counts)
	}
}

func TestAuditPaging(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	for i := 0; i < 5; i++ {
		pending(t, s, event("192.168.1.50", fmt.Sprintf("p%d.example", i)))
	}
	page, _ := s.Audit(AuditQuery{Limit: 2})
	if len(page) != 2 || page[0].Seq <= page[1].Seq {
		t.Fatalf("newest first: %+v", page)
	}
	next, _ := s.Audit(AuditQuery{Limit: 10, Before: page[1].Seq})
	if len(next) != 3 || next[0].Seq != page[1].Seq-1 {
		t.Fatalf("second page: %+v", next)
	}
	all, _ := s.Audit(AuditQuery{})
	if len(all) != 5 {
		t.Errorf("default limit: %d", len(all))
	}
}

func TestPrune(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	s.PutEvaluation(Evaluation{DetectionID: "DET-a-1", Digest: []byte{1}, Decision: []byte("{}")})
	c.Advance(time.Hour)
	s.PutEvaluation(Evaluation{DetectionID: "DET-a-2", Digest: []byte{1}, Decision: []byte("{}")})
	s.PutEvaluation(Evaluation{DetectionID: "DET-a-3", Digest: []byte{1}, Decision: []byte("{}")})
	pending(t, s, event("192.168.1.50", "a.example"))
	cmd, _ := s.EnqueueCommand(agentIsolate("ACT-x"))
	s.CompleteCommand(cmd.ID, true, "")

	c.Advance(48 * time.Hour)
	err := s.Prune(c.Now(), PruneOptions{EvaluationRetention: 48*time.Hour + 30*time.Minute, MaxEvaluations: 1,
		AuditRetention: time.Hour, AuditForwarding: true, CommandRetention: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetEvaluation("DET-a-1"); ok {
		t.Error("evaluation past retention kept")
	}
	if _, ok, _ := s.GetEvaluation("DET-a-2"); ok {
		if _, ok3, _ := s.GetEvaluation("DET-a-3"); ok3 {
			t.Error("evaluations beyond the cap kept")
		}
	}
	if e, _ := s.Audit(AuditQuery{}); len(e) != 1 {
		t.Error("an audit entry that was never forwarded must not be pruned")
	}
	s.MarkForwarded(1 << 40)
	s.Prune(c.Now(), PruneOptions{AuditRetention: time.Hour, AuditForwarding: true})
	if e, _ := s.Audit(AuditQuery{}); len(e) != 0 {
		t.Error("a forwarded audit entry past retention is kept")
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM agent_commands").Scan(&n)
	if n != 0 {
		t.Error("finished command past retention kept")
	}
}
