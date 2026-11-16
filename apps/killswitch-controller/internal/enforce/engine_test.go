package enforce

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/libs/events"
)

// scripted is a driver whose answers the test chooses, call by call.
type scripted struct {
	mu         sync.Mutex
	applyErrs  []error
	revertErrs []error
	// revertGate, when set, holds every revert until it is closed.
	revertGate chan struct{}
	applies    atomic.Int32
	reverts    atomic.Int32
	delay      time.Duration
}

func (d *scripted) next(errs *[]error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(*errs) == 0 {
		return nil
	}
	err := (*errs)[0]
	*errs = (*errs)[1:]
	return err
}

func (d *scripted) Apply(ctx context.Context, _ *events.EnforcementAction) error {
	d.applies.Add(1)
	if d.delay > 0 {
		select {
		case <-time.After(d.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return d.next(&d.applyErrs)
}

func (d *scripted) Revert(ctx context.Context, _ *events.EnforcementAction) error {
	d.reverts.Add(1)
	if d.revertGate != nil {
		select {
		case <-d.revertGate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return d.next(&d.revertErrs)
}

func (d *scripted) Name() string { return "scripted" }

type clock struct {
	mu   sync.Mutex
	t    time.Time
	real bool // follow the wall clock (for waits on real deadlines)
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.real {
		return time.Now()
	}
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t      *testing.T
	e      *Engine
	s      *actions.Store
	clk    *clock
	path   string
	drv    *scripted
	cmds   *drivers.ARPIsolateDriver
	cfg    Config
	extras map[string]drivers.Driver
}

func newEnv(t *testing.T, cfg Config, extra map[string]drivers.Driver) *env {
	t.Helper()
	en := &env{t: t, clk: &clock{t: time.Now().UTC().Truncate(time.Millisecond)},
		path: filepath.Join(t.TempDir(), "ks.db"), drv: &scripted{}, cfg: cfg, extras: extra}
	en.open()
	return en
}

func (en *env) open() {
	s, err := actions.Open(en.path, actions.Options{Now: en.clk.Now})
	if err != nil {
		en.t.Fatal(err)
	}
	en.t.Cleanup(func() { s.Close() })
	drvs := map[string]drivers.Driver{events.ActionDNSSinkhole: en.drv}
	for k, v := range en.extras {
		drvs[k] = v
	}
	en.s = s
	en.e = New(s, drvs, en.cfg)
	en.e.now = en.clk.Now
}

// restart simulates a crash: the engine is dropped without shutdown and a
// new one opens the same database.
func (en *env) restart() {
	en.s.Close()
	en.open()
}

func (en *env) idle() {
	en.t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		en.e.mu.Lock()
		n := len(en.e.inflight)
		en.e.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	en.t.Fatal("operations still in flight")
}

func (en *env) get(id string) actions.Record {
	en.t.Helper()
	r, err := en.s.Get(id)
	if err != nil {
		en.t.Fatal(err)
	}
	return r
}

var seq atomic.Int64

func detection(domain string) events.DetectionEvent {
	return events.DetectionEvent{
		ID:        fmt.Sprintf("DET-eng-%d", seq.Add(1)),
		Summary:   "test",
		ClientIP:  "192.168.1.50",
		ClientMAC: "02:00:00:00:00:01",
		Target:    &events.Target{Type: events.TargetDomain, Value: domain},
	}
}

func (en *env) pending(domain string) actions.Record {
	en.t.Helper()
	res, err := en.e.Submit(detection(domain), Decision{ActionType: events.ActionDNSSinkhole, PolicyRule: "pending", TTLSeconds: 60})
	if err != nil {
		en.t.Fatal(err)
	}
	return res.Record
}

func (en *env) active(domain string) actions.Record {
	en.t.Helper()
	r := en.pending(domain)
	if _, err := en.e.Approve(r.ID, "alice", ""); err != nil {
		en.t.Fatal(err)
	}
	en.idle()
	if got := en.get(r.ID); got.State != events.StateActive {
		en.t.Fatalf("setup: %s is %s", r.ID, got.State)
	}
	return en.get(r.ID)
}

func auditTrail(t *testing.T, s *actions.Store, id string) string {
	t.Helper()
	entries, err := s.Audit(actions.AuditQuery{ActionID: id})
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		parts = append(parts, fmt.Sprintf("%s>%s by %s", e.FromState, e.ToState, e.Actor))
	}
	return strings.Join(parts, "; ")
}

// TestDoubleApproveAppliesOnce: a double-click ran the driver twice, and a
// second, failing call turned an enforced action into failed.
func TestDoubleApproveAppliesOnce(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	en.drv.delay = 100 * time.Millisecond
	en.drv.applyErrs = []error{nil, errors.New("webhook 409: already quarantined")}
	r := en.pending("evil.example")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := en.e.Approve(r.ID, "alice", ""); err != nil {
				t.Errorf("approve: %v", err)
			}
			en.e.Wait(context.Background(), r.ID, 5*time.Second)
		}()
	}
	wg.Wait()
	en.idle()
	if n := en.drv.applies.Load(); n != 1 {
		t.Fatalf("driver applied %d times, want 1", n)
	}
	if got := en.get(r.ID); got.State != events.StateActive {
		t.Fatalf("state %s", got.State)
	}
	if trail := auditTrail(t, en.s, r.ID); trail != ">pending by auto-policy; pending>approved by alice; approved>active by alice" {
		t.Errorf("audit: %s", trail)
	}
}

func TestApplyOutcomes(t *testing.T) {
	cases := []struct {
		name        string
		applyErr    error
		revertErr   error
		wantState   string
		wantReverts int32
	}{
		{"definite failure: nothing to undo", drivers.NotApplied(errors.New("guard refused")), nil, events.StateApplyFailed, 0},
		{"ambiguous failure, undone", errors.New("context deadline exceeded"), nil, events.StateApplyFailed, 1},
		{"ambiguous failure, undo failed: still enforced", errors.New("connection reset"), errors.New("adguard 502"), events.StateRevertFailed, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			en := newEnv(t, Config{}, nil)
			en.drv.applyErrs = []error{tc.applyErr}
			en.drv.revertErrs = []error{tc.revertErr}
			r := en.pending("evil.example")
			en.e.Approve(r.ID, "alice", "")
			en.idle()
			got := en.get(r.ID)
			if got.State != tc.wantState || en.drv.reverts.Load() != tc.wantReverts {
				t.Fatalf("state %s reverts %d, want %s/%d (%s)", got.State, en.drv.reverts.Load(),
					tc.wantState, tc.wantReverts, got.FailureReason)
			}
			if got.FailureReason == "" || got.ActivatedAt != nil || got.Op != actions.OpNone {
				t.Errorf("failure not recorded truthfully: %+v op=%s", got.Action(), got.Op)
			}
			if tc.wantState == events.StateRevertFailed {
				// The reaper owns it now: it retries, and the action ends as
				// apply_failed — it was never in force.
				en.clk.Advance(time.Minute)
				en.e.Reap(context.Background())
				en.idle()
				if got := en.get(r.ID); got.State != events.StateApplyFailed {
					t.Fatalf("after the retry: %s", got.State)
				}
			}
		})
	}
}

func TestApplyWithoutDriver(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	res, err := en.s.Submit(actions.Submission{Event: detection("evil.example"), ActionType: events.ActionSwitchACL})
	if err != nil {
		t.Fatal(err)
	}
	_, err = en.e.Approve(res.Record.ID, "alice", "")
	var u *UnavailableError
	if !errors.As(err, &u) || u.Type != events.ActionSwitchACL || len(u.Available) != 1 {
		t.Fatalf("approving a type with no driver: %v", err)
	}
	if _, err := en.e.Approve(res.Record.ID, "alice", "nonsense"); !errors.As(err, &u) || !strings.Contains(u.Reason, "unknown") {
		t.Fatalf("unknown type: %v", err)
	}
	// The operator picks one that exists.
	if _, err := en.e.Approve(res.Record.ID, "alice", events.ActionDNSSinkhole); err != nil {
		t.Fatal(err)
	}
	en.idle()
	if got := en.get(res.Record.ID); got.State != events.StateActive || got.ActionType != events.ActionDNSSinkhole {
		t.Fatalf("got %s %s", got.State, got.ActionType)
	}
	if _, err := en.e.Approve(res.Record.ID, "bob", events.ActionARPIsolate); err == nil {
		t.Fatal("re-approving as another type must be refused")
	}
}

// TestFailedRevertIsRetriedAndNeverReportedReverted: AdGuard answering 502
// during a manual revert made the action failed; the reaper never retried
// and a second revert reported "reverted" without calling the driver.
func TestFailedRevertIsRetriedAndNeverReportedReverted(t *testing.T) {
	en := newEnv(t, Config{RetryBase: 10 * time.Second, RetryMax: 40 * time.Second}, nil)
	r := en.active("evil.example")
	fail := errors.New("adguard 502: bad gateway")
	en.drv.revertErrs = []error{fail, fail, fail, fail}

	if _, err := en.e.Revert(context.Background(), r.ID, "alice", "false positive"); err != nil {
		t.Fatal(err)
	}
	en.idle()
	got := en.get(r.ID)
	if got.State != events.StateRevertFailed || got.RevertedAt != nil {
		t.Fatalf("after a failed revert: %s", got.State)
	}
	// A second manual revert calls the driver again — and fails again.
	en.e.Revert(context.Background(), r.ID, "alice", "again")
	en.idle()
	if en.drv.reverts.Load() != 2 || en.get(r.ID).State != events.StateRevertFailed {
		t.Fatalf("the second revert did not call the driver: %d calls, %s", en.drv.reverts.Load(), en.get(r.ID).State)
	}
	// The reaper retries with backoff: 10s, then 20s, then 40s (capped).
	for i, wait := range []time.Duration{20 * time.Second, 40 * time.Second} {
		before := en.drv.reverts.Load()
		en.clk.Advance(wait - time.Second)
		en.e.Reap(context.Background())
		en.idle()
		if en.drv.reverts.Load() != before {
			t.Fatalf("retry %d ran before its backoff", i)
		}
		en.clk.Advance(time.Second)
		en.e.Reap(context.Background())
		en.idle()
		if en.drv.reverts.Load() != before+1 {
			t.Fatalf("retry %d did not run", i)
		}
		if en.get(r.ID).State != events.StateRevertFailed {
			t.Fatal("reported lifted while the driver still fails")
		}
	}
	en.clk.Advance(time.Hour)
	en.e.Reap(context.Background())
	en.idle()
	got = en.get(r.ID)
	if got.State != events.StateReverted || got.RevertedBy != actions.ActorTTL {
		t.Fatalf("after AdGuard recovered: %s by %s", got.State, got.RevertedBy)
	}
	want := ">pending by auto-policy; pending>approved by alice; approved>active by alice; " +
		"active>revert_failed by alice; revert_failed>revert_failed by alice; revert_failed>reverted by ttl"
	if trail := auditTrail(t, en.s, r.ID); trail != want {
		t.Errorf("audit:\n got %s\nwant %s", trail, want)
	}
	// Reverting a reverted action is answered with it, nothing else runs.
	before := en.drv.reverts.Load()
	if rec, err := en.e.Revert(context.Background(), r.ID, "bob", "x"); err != nil || rec.State != events.StateReverted {
		t.Fatalf("%+v %v", rec, err)
	}
	if en.drv.reverts.Load() != before {
		t.Error("the driver ran for an already reverted action")
	}
}

// TestRevertIsRecordedBeforeRevertReturns: the intent was written by the
// background goroutine, so the HTTP answer to a revert still under way (a
// 202) could be read before it and show an active action with nothing in
// flight.
func TestRevertIsRecordedBeforeRevertReturns(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	r := en.active("evil.example")
	gate := make(chan struct{})
	en.drv.revertGate = gate // set before any revert runs

	if _, err := en.e.Revert(context.Background(), r.ID, "alice", "false positive"); err != nil {
		t.Fatal(err)
	}
	got := en.get(r.ID)
	if got.Op != actions.OpRevert || got.OpActor != "alice" || got.Action().InFlight != events.OperationRevert {
		t.Fatalf("right after Revert: op %q by %q, in_flight %q; want the revert recorded",
			got.Op, got.OpActor, got.Action().InFlight)
	}
	close(gate)
	en.idle()
	if got := en.get(r.ID); got.State != events.StateReverted || got.RevertedBy != "alice" || got.Op != actions.OpNone {
		t.Fatalf("after the driver answered: %s by %s, op %q", got.State, got.RevertedBy, got.Op)
	}
}

// TestRevertThatCannotBeRecordedStartsNothing: with the intent recorded on
// the request, a revert the store refuses is answered with the conflict
// and the action as it is, and no driver call runs. (In the background it
// was only logged, and the caller was answered as if it had started.)
func TestRevertThatCannotBeRecordedStartsNothing(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	r := en.active("evil.example")
	// Another operation outstanding in the store (left by a previous run)
	// that this process is not running: the revert cannot start.
	if _, err := en.s.BeginOp(r.ID, actions.OpApply, "alice", "", en.clk.Now().Add(time.Hour), events.StateActive); err != nil {
		t.Fatal(err)
	}
	_, err := en.e.Revert(context.Background(), r.ID, "bob", "x")
	var c *actions.ConflictError
	if !errors.As(err, &c) || c.Current.ID != r.ID {
		t.Fatalf("revert with another operation outstanding: %v, want a conflict naming the action", err)
	}
	if en.drv.reverts.Load() != 0 || en.e.Busy(r.ID) {
		t.Fatal("a revert that could not be recorded must not run")
	}
}

func TestReaperExpiresAndReverts(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	old := en.pending("old.example")
	act := en.active("act.example")
	en.clk.Advance(30 * time.Second)
	en.e.Reap(context.Background())
	en.idle()
	if en.get(act.ID).State != events.StateActive || en.drv.reverts.Load() != 0 {
		t.Fatal("reverted before its TTL")
	}
	en.clk.Advance(31 * time.Second)
	en.e.Reap(context.Background())
	en.idle()
	if got := en.get(act.ID); got.State != events.StateReverted || got.RevertedBy != actions.ActorTTL {
		t.Fatalf("TTL revert: %s by %s", got.State, got.RevertedBy)
	}
	en.clk.Advance(25 * time.Hour)
	en.e.Reap(context.Background())
	if got := en.get(old.ID); got.State != events.StateExpired {
		t.Fatalf("pending after its deadline: %s", got.State)
	}
	if _, err := en.e.Revert(context.Background(), old.ID, "bob", ""); err == nil {
		t.Fatal("an expired action has nothing to revert")
	}
}

// TestRecoverAfterACrash: nothing reconciled at start-up, and the store was
// in memory.
func TestRecoverAfterACrash(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	act := en.active("act.example")
	// Interrupted apply: approved, op recorded, the process died.
	mid := en.pending("mid.example")
	if _, err := en.s.Approve(mid.ID, "alice", "", en.clk.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// Interrupted revert.
	rev := en.active("rev.example")
	en.s.BeginOp(rev.ID, actions.OpRevert, "bob", "fp", en.clk.Now().Add(time.Second), events.StateActive)

	en.restart()
	en.e.Recover()
	en.idle()
	if got := en.get(act.ID); got.State != events.StateActive || got.ExpiresAt == nil {
		t.Fatalf("the active block is not known after a restart: %+v", got.Action())
	}
	if got := en.get(mid.ID); got.State != events.StateApplyFailed || !strings.Contains(got.FailureReason, "interrupted") {
		t.Fatalf("interrupted apply: %s %q", got.State, got.FailureReason)
	}
	if got := en.get(rev.ID); got.State != events.StateReverted || got.RevertedBy != "bob" {
		t.Fatalf("interrupted revert: %s by %s", got.State, got.RevertedBy)
	}
	// …and the surviving block is reverted at its TTL.
	en.clk.Advance(61 * time.Second)
	en.e.Reap(context.Background())
	en.idle()
	if got := en.get(act.ID); got.State != events.StateReverted || got.RevertedBy != actions.ActorTTL {
		t.Fatalf("after its TTL: %s", got.State)
	}
}

func TestSubmitAutoAppliesAndFolds(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	ev := detection("c2.example")
	res, err := en.e.Submit(ev, Decision{Auto: true, ActionType: events.ActionDNSSinkhole, PolicyRule: "auto", TTLSeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	en.idle()
	if got := en.get(res.Record.ID); got.State != events.StateActive || got.ApprovedBy != actions.ActorPolicy {
		t.Fatalf("auto: %+v", got.Action())
	}
	again := detection("c2.example")
	res2, _ := en.e.Submit(again, Decision{Auto: true, ActionType: events.ActionDNSSinkhole})
	en.idle()
	if res2.Outcome != actions.OutcomeFolded || res2.Record.ID != res.Record.ID || en.drv.applies.Load() != 1 {
		t.Fatalf("a repeat must fold into the active block: %+v applies=%d", res2.Outcome, en.drv.applies.Load())
	}
	p := en.pending("later.example")
	res3, _ := en.e.Submit(detection("later.example"), Decision{Auto: true, ActionType: events.ActionDNSSinkhole, TTLSeconds: 60})
	en.idle()
	if res3.Outcome != actions.OutcomePromoted || en.get(p.ID).State != events.StateActive {
		t.Fatalf("promotion: %s %s", res3.Outcome, en.get(p.ID).State)
	}
}

func TestShutdownWaitsForDriverCalls(t *testing.T) {
	en := newEnv(t, Config{}, nil)
	en.drv.delay = 100 * time.Millisecond
	r := en.pending("x.example")
	en.e.Approve(r.ID, "alice", "")
	en.e.Shutdown(5 * time.Second)
	if got := en.get(r.ID); got.State != events.StateActive {
		t.Fatalf("shutdown cut the apply short: %s", got.State)
	}
}
