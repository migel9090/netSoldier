// Package enforce drives actions through the state machine of package
// actions: it calls the drivers on their own deadlines, decides what every
// driver outcome means, runs the reaper and reconciles the store with what
// is really in force. See the actions package documentation for the
// states and who may move them.
package enforce

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/libs/events"
)

// Config holds the engine's deadlines and intervals.
type Config struct {
	// DriverTimeout is the deadline of one synchronous driver call. It is
	// the engine's own: a caller giving up does not cut a call short.
	DriverTimeout time.Duration
	// ConfirmTimeout is how long a deferred operation (netagent) may wait
	// for its confirmation.
	ConfirmTimeout time.Duration
	// RetryBase / RetryMax bound the backoff of revert retries.
	RetryBase, RetryMax time.Duration
	// ReapInterval is how often the reaper runs.
	ReapInterval time.Duration
	// ReconcileInterval is how often the sinkhole is reconciled after the
	// start-up pass.
	ReconcileInterval time.Duration
	// AgentGrace is how long an isolation may be missing from the agent's
	// active list after activation before it counts as ended.
	AgentGrace time.Duration
	// Prune says what the reaper may forget.
	Prune actions.PruneOptions
}

func (c *Config) defaults() {
	set := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	set(&c.DriverTimeout, 8*time.Second)
	set(&c.ConfirmTimeout, 8*time.Second)
	set(&c.RetryBase, 10*time.Second)
	set(&c.RetryMax, 10*time.Minute)
	set(&c.ReapInterval, 10*time.Second)
	set(&c.ReconcileInterval, 5*time.Minute)
	set(&c.AgentGrace, 10*time.Second)
}

// Engine is safe for concurrent use.
type Engine struct {
	store   *actions.Store
	drivers map[string]drivers.Driver
	sink    *drivers.SinkholeDriver
	agent   *drivers.ARPIsolateDriver
	cfg     Config
	now     func() time.Time

	mu       sync.Mutex
	inflight map[string]*op
	signals  map[string]chan struct{}
	wg       sync.WaitGroup
	stop     chan struct{}
	stopOnce sync.Once
}

// op is one driver operation in progress in this process.
type op struct {
	kind string
	done chan struct{}
}

// New returns an engine over store and the configured drivers, keyed by
// action type.
func New(store *actions.Store, drvs map[string]drivers.Driver, cfg Config) *Engine {
	cfg.defaults()
	e := &Engine{
		store:    store,
		drivers:  drvs,
		cfg:      cfg,
		now:      time.Now,
		inflight: map[string]*op{},
		signals:  map[string]chan struct{}{},
		stop:     make(chan struct{}),
	}
	if d, ok := drvs[events.ActionDNSSinkhole].(*drivers.SinkholeDriver); ok {
		e.sink = d
	}
	if d, ok := drvs[events.ActionARPIsolate].(*drivers.ARPIsolateDriver); ok {
		e.agent = d
	}
	return e
}

// Store returns the store the engine works on.
func (e *Engine) Store() *actions.Store { return e.store }

// UnavailableError says an action type cannot be used now.
type UnavailableError struct {
	Type      string
	Reason    string
	Available []string
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("action type %q is not available: %s", e.Type, e.Reason)
}

// Available lists the action types an operator may choose now.
func (e *Engine) Available() []string {
	out := []string{}
	for t := range e.drivers {
		if e.checkType(t) == nil {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

func (e *Engine) checkType(t string) error {
	d, ok := e.drivers[t]
	if !ok {
		reason := "no driver is configured for it"
		switch t {
		case events.ActionDNSSinkhole, events.ActionARPIsolate, events.ActionSwitchACL:
		default:
			reason = "unknown action type"
		}
		return &UnavailableError{Type: t, Reason: reason}
	}
	if a, ok := d.(drivers.Availability); ok {
		if err := a.Available(); err != nil {
			return &UnavailableError{Type: t, Reason: err.Error()}
		}
	}
	return nil
}

func (e *Engine) unavailable(t string) error {
	err := e.checkType(t)
	var u *UnavailableError
	if errors.As(err, &u) {
		u.Available = e.Available()
	}
	return err
}

// Decision is what the policy decided, in the engine's terms.
type Decision struct {
	Auto       bool
	ActionType string
	PolicyRule string
	TTLSeconds int
}

// Submit records a decision for ev and, when the policy approved it
// itself, starts the apply.
func (e *Engine) Submit(ev events.DetectionEvent, d Decision) (actions.SubmitResult, error) {
	res, err := e.store.Submit(actions.Submission{
		Event: ev, ActionType: d.ActionType, PolicyRule: d.PolicyRule, TTLSeconds: d.TTLSeconds,
		Auto: d.Auto, OpDeadline: e.now().Add(e.cfg.DriverTimeout),
	})
	if err != nil {
		return res, err
	}
	if len(res.Evicted) > 0 {
		pendingExpired.WithLabelValues("capacity").Add(float64(len(res.Evicted)))
		slog.Warn("approval queue full: oldest pending actions expired", "count", len(res.Evicted))
	}
	if res.Outcome != actions.OutcomeCreated {
		detectionsFolded.WithLabelValues(res.Outcome).Inc()
	}
	if res.Record.State == events.StateApproved && res.Record.Op == actions.OpApply &&
		(res.Outcome == actions.OutcomeCreated || res.Outcome == actions.OutcomePromoted) {
		e.startApply(res.Record)
	}
	return res, nil
}

// Approve approves a pending action and starts its apply. actionType, when
// not empty, is the operator's choice of enforcement; it must name a driver
// that is available now. Approving again an action that is approved or
// active is answered with the action and applies nothing.
func (e *Engine) Approve(id, actor, actionType string) (actions.Record, error) {
	rec, err := e.store.Get(id)
	if err != nil {
		return rec, err
	}
	want := actionType
	if want == "" {
		want = rec.ActionType
	}
	if rec.State == events.StateApproved || rec.State == events.StateActive {
		if actionType != "" && actionType != rec.ActionType {
			return rec, &actions.ConflictError{Current: rec,
				Msg: fmt.Sprintf("action %s was already approved as %s", rec.ID, rec.ActionType)}
		}
		return rec, nil
	}
	if rec.State == events.StatePending {
		if err := e.unavailable(want); err != nil {
			return rec, err
		}
		if (want == events.ActionARPIsolate || want == events.ActionSwitchACL) && rec.TargetMAC != "" {
			// One device-level enforcement per device: two would share one
			// isolation, and lifting either would lift both.
			other, found, err := e.store.EnforcedOn(want, rec.TargetMAC)
			if err != nil {
				return rec, err
			}
			if found && other.ID != rec.ID {
				return rec, &actions.ConflictError{Current: rec,
					Msg: fmt.Sprintf("device %s already has %s %s (%s)", rec.TargetMAC, want, other.ID, other.State)}
			}
		}
	}
	rec, err = e.store.Approve(id, actor, actionType, e.now().Add(e.cfg.DriverTimeout))
	var c *actions.ConflictError
	if errors.As(err, &c) && (c.Current.State == events.StateApproved || c.Current.State == events.StateActive) &&
		(actionType == "" || actionType == c.Current.ActionType) {
		// Lost the race to a concurrent approve: the winner applies.
		return c.Current, nil
	}
	if err != nil {
		return rec, err
	}
	slog.Info("action approved", "action_id", id, "actor", actor, "action_type", rec.ActionType)
	e.startApply(rec)
	return rec, nil
}

// Reject closes a pending action.
func (e *Engine) Reject(id, actor, reason string) (actions.Record, error) {
	rec, err := e.store.Reject(id, actor, reason)
	if err == nil {
		slog.Info("action rejected", "action_id", id, "actor", actor)
	}
	return rec, err
}

// Revert lifts an enforcement. A revert of an action that is reverted
// already is answered with the action; a revert of a revert_failed action
// retries now.
func (e *Engine) Revert(ctx context.Context, id, actor, reason string) (actions.Record, error) {
	for {
		rec, err := e.store.Get(id)
		if err != nil {
			return rec, err
		}
		if o := e.current(id); o != nil {
			select {
			case <-o.done:
				continue
			case <-ctx.Done():
				return rec, ctx.Err()
			}
		}
		switch {
		case rec.State == events.StateReverted:
			return rec, nil
		case events.IsEnforcedState(rec.State) && rec.Op == actions.OpRevert:
			// A deferred release is outstanding; its result decides.
			return rec, nil
		case events.IsEnforcedState(rec.State):
			if _, started := e.startRevert(rec, actor, reason); started {
				return rec, nil
			}
			continue
		case rec.State == events.StateApproved:
			return rec, &actions.ConflictError{Current: rec,
				Msg: fmt.Sprintf("action %s is still being applied; revert it once it is active", rec.ID)}
		default:
			return rec, &actions.ConflictError{Current: rec,
				Msg: fmt.Sprintf("action %s is %s: nothing is enforced", rec.ID, rec.State)}
		}
	}
}

// Wait waits until no operation is in flight for id, ctx is done or max
// passes, and reports whether the action has settled.
func (e *Engine) Wait(ctx context.Context, id string, max time.Duration) bool {
	o := e.current(id)
	if o == nil {
		return true
	}
	t := time.NewTimer(max)
	defer t.Stop()
	select {
	case <-o.done:
		return true
	case <-ctx.Done():
	case <-t.C:
	}
	return false
}

// Busy reports whether a driver operation for id is in flight here.
func (e *Engine) Busy(id string) bool { return e.current(id) != nil }

func (e *Engine) current(id string) *op {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.inflight[id]
}

// begin registers an operation, or returns false when one is in flight.
func (e *Engine) begin(id, kind string) (*op, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if o := e.inflight[id]; o != nil {
		return o, false
	}
	o := &op{kind: kind, done: make(chan struct{})}
	e.inflight[id] = o
	e.wg.Add(1)
	return o, true
}

func (e *Engine) end(id string, o *op) {
	e.mu.Lock()
	if e.inflight[id] == o {
		delete(e.inflight, id)
	}
	e.mu.Unlock()
	close(o.done)
	e.wg.Done()
}

func (e *Engine) driver(t string) (drivers.Driver, error) {
	if d, ok := e.drivers[t]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("no driver configured for action type %q", t)
}

func (e *Engine) driverCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), e.cfg.DriverTimeout)
}

func (e *Engine) startApply(rec actions.Record) {
	o, ok := e.begin(rec.ID, actions.OpApply)
	if !ok {
		return
	}
	go func() {
		defer e.end(rec.ID, o)
		e.runApply(rec)
	}()
}

// runApply calls the driver and decides what its answer means:
//
//   - success: active, the TTL starts now;
//   - ErrDeferred: wait for the agent's confirmation, up to ConfirmTimeout;
//   - ErrNotApplied: apply_failed, nothing to undo;
//   - anything else (a timeout, a dropped connection, an error after the
//     write): the change may have taken effect, so it is undone with a
//     revert; apply_failed when that works, revert_failed (still enforced,
//     the reaper's to finish) when it does not.
func (e *Engine) runApply(rec actions.Record) {
	actor := rec.OpActor
	drv, err := e.driver(rec.ActionType)
	if err != nil {
		driverFailures.WithLabelValues("apply").Inc()
		e.note(e.store.ApplyFailed(rec.ID, actor, "apply failed: "+err.Error()))
		return
	}
	a := rec.EnforcementAction
	ctx, cancel := e.driverCtx()
	err = drv.Apply(ctx, &a)
	cancel()
	switch {
	case err == nil:
		_, err := e.store.Activate(rec.ID, actor, "enforcement applied by "+drv.Name())
		e.logErr(err)
		if err == nil {
			slog.Info("action active", "action_id", rec.ID, "action_type", rec.ActionType)
		}
	case errors.Is(err, drivers.ErrDeferred):
		deadline := e.now().Add(e.cfg.ConfirmTimeout)
		if _, err := e.store.ExtendOp(rec.ID, actions.OpApply, deadline); err != nil {
			e.logErr(err)
			return
		}
		if !e.awaitSettle(rec.ID, actions.OpApply, deadline) {
			return
		}
		if cur, err := e.store.Get(rec.ID); err == nil && cur.Op == actions.OpApply {
			e.overdue(cur)
		}
	case errors.Is(err, drivers.ErrNotApplied):
		driverFailures.WithLabelValues("apply").Inc()
		slog.Error("driver apply failed — device is NOT enforced", "action_id", rec.ID, "error", err)
		e.note(e.store.ApplyFailed(rec.ID, actor, "apply failed: "+err.Error()))
	default:
		driverFailures.WithLabelValues("apply").Inc()
		slog.Error("driver apply outcome unknown — undoing it", "action_id", rec.ID, "error", err)
		e.compensate(rec, drv, err)
	}
}

// compensate undoes an apply whose outcome is unknown.
func (e *Engine) compensate(rec actions.Record, drv drivers.Driver, applyErr error) {
	a := rec.EnforcementAction
	ctx, cancel := e.driverCtx()
	err := drv.Revert(ctx, &a)
	cancel()
	if err == nil {
		compensations.WithLabelValues("ok").Inc()
		e.note(e.store.ApplyFailed(rec.ID, rec.OpActor,
			fmt.Sprintf("apply failed (%v); whatever it changed was undone", applyErr)))
		return
	}
	compensations.WithLabelValues("failed").Inc()
	driverFailures.WithLabelValues("compensate").Inc()
	slog.Error("could not undo a failed apply — treating the action as STILL ENFORCED; the reaper retries",
		"action_id", rec.ID, "apply_error", applyErr, "revert_error", err)
	e.note(e.store.RevertFailed(rec.ID, rec.OpActor,
		fmt.Sprintf("apply failed (%v) and undoing it failed (%v): treated as still enforced", applyErr, err),
		e.now().Add(e.cfg.RetryBase), true))
}

// startRevert persists the intent and runs the revert in the background.
// It returns false when another operation is in flight.
func (e *Engine) startRevert(rec actions.Record, actor, reason string) (*op, bool) {
	o, ok := e.begin(rec.ID, actions.OpRevert)
	if !ok {
		return o, false
	}
	go func() {
		defer e.end(rec.ID, o)
		cur, err := e.store.BeginOp(rec.ID, actions.OpRevert, actor, reason,
			e.now().Add(e.cfg.DriverTimeout), events.StateActive, events.StateRevertFailed)
		if err != nil {
			e.logErr(err)
			return
		}
		e.runRevert(cur, actor, reason)
	}()
	return o, true
}

// runRevert calls the driver. Only its confirmation makes the action
// reverted; any failure leaves it revert_failed — still enforced — with
// the next retry scheduled.
func (e *Engine) runRevert(rec actions.Record, actor, reason string) {
	retry := rec.State == events.StateRevertFailed
	drv, err := e.driver(rec.ActionType)
	if err == nil {
		a := rec.EnforcementAction
		ctx, cancel := e.driverCtx()
		err = drv.Revert(ctx, &a)
		cancel()
	}
	switch {
	case err == nil:
		if retry {
			revertRetries.WithLabelValues("ok").Inc()
		}
		r, err := e.store.Reverted(rec.ID, actor, reason)
		e.logErr(err)
		if err == nil {
			slog.Info("action reverted", "action_id", rec.ID, "actor", actor, "state", r.State)
		}
	case errors.Is(err, drivers.ErrDeferred):
		deadline := e.now().Add(e.cfg.ConfirmTimeout)
		if _, err := e.store.ExtendOp(rec.ID, actions.OpRevert, deadline); err != nil {
			e.logErr(err)
			return
		}
		if !e.awaitSettle(rec.ID, actions.OpRevert, deadline) {
			return
		}
		if cur, err := e.store.Get(rec.ID); err == nil && cur.Op == actions.OpRevert {
			e.overdue(cur)
		}
	default:
		if retry {
			revertRetries.WithLabelValues("failed").Inc()
		}
		e.revertFailed(rec, actor, "revert failed: "+err.Error())
	}
}

func (e *Engine) revertFailed(rec actions.Record, actor, failure string) {
	driverFailures.WithLabelValues("revert").Inc()
	next := e.now().Add(e.backoff(rec.Attempts))
	slog.Error("revert failed — enforcement is STILL ACTIVE; will retry", "action_id", rec.ID,
		"actor", actor, "error", failure, "next_attempt", next)
	e.note(e.store.RevertFailed(rec.ID, actor, failure, next, !actions.IsSystemActor(actor)))
}

func (e *Engine) backoff(attempts int) time.Duration {
	d := e.cfg.RetryBase
	for i := 0; i < attempts && d < e.cfg.RetryMax; i++ {
		d *= 2
	}
	return min(d, e.cfg.RetryMax)
}

// awaitSettle waits until the outstanding op is no longer op (a result
// arrived), the deadline passes or the engine stops. It returns false when
// the engine is stopping: the deadline is persisted, and the reaper of the
// next start deals with it.
func (e *Engine) awaitSettle(id, op string, deadline time.Time) bool {
	e.mu.Lock()
	ch, ok := e.signals[id]
	if !ok {
		ch = make(chan struct{})
		e.signals[id] = ch
	}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		if e.signals[id] == ch {
			delete(e.signals, id)
		}
		e.mu.Unlock()
	}()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if cur, err := e.store.Get(id); err != nil || cur.Op != op {
			return true
		}
		if !e.now().Before(deadline) {
			return true
		}
		select {
		case <-ch:
			return true
		case <-tick.C:
		case <-e.stop:
			return false
		}
	}
}

func (e *Engine) signal(id string) {
	e.mu.Lock()
	ch, ok := e.signals[id]
	delete(e.signals, id)
	e.mu.Unlock()
	if ok {
		close(ch)
	}
}

// overdue handles an operation whose deadline passed without an outcome.
func (e *Engine) overdue(rec actions.Record) {
	drv, err := e.driver(rec.ActionType)
	deferred := err == nil && drivers.IsDeferring(drv)
	switch {
	case rec.Op == actions.OpApply && deferred:
		confirmTimeouts.WithLabelValues(drivers.CommandIsolate).Inc()
		failure := fmt.Sprintf("the netagent did not confirm the isolation within %s", e.cfg.ConfirmTimeout)
		if !e.withdraw(rec.ID, drivers.CommandIsolate) {
			// It was fetched: the agent may still carry it out, so ask for
			// the opposite too. Its own TTL is the backstop.
			if err := drv.Revert(context.Background(), &rec.EnforcementAction); err != nil &&
				!errors.Is(err, drivers.ErrDeferred) {
				e.logErr(err)
			}
			failure += "; a release was queued in case it is applied late"
		}
		driverFailures.WithLabelValues("apply").Inc()
		e.note(e.store.ApplyFailed(rec.ID, actions.ActorAgent, failure))
	case rec.Op == actions.OpRevert && deferred:
		confirmTimeouts.WithLabelValues(drivers.CommandRelease).Inc()
		e.withdraw(rec.ID, drivers.CommandRelease)
		e.revertFailed(rec, rec.OpActor,
			fmt.Sprintf("the netagent did not confirm the release within %s", e.cfg.ConfirmTimeout))
	case rec.Op == actions.OpApply:
		// A synchronous apply this process did not finish (it was
		// restarted mid-call): its outcome is unknown, so undo it.
		interruptedOps.WithLabelValues("apply").Inc()
		if err != nil {
			e.note(e.store.RevertFailed(rec.ID, rec.OpActor,
				"interrupted apply, and "+err.Error()+": treated as still enforced", e.now().Add(e.cfg.RetryBase), true))
			return
		}
		e.compensate(rec, drv, errors.New("interrupted by a restart"))
	case rec.Op == actions.OpRevert:
		interruptedOps.WithLabelValues("revert").Inc()
		e.runRevert(rec, rec.OpActor, rec.OpReason)
	}
}

// withdraw cancels the action's queued, unsent commands of the given type
// and reports whether nothing of that type had been sent.
func (e *Engine) withdraw(actionID, cmdType string) bool {
	cmds, err := e.store.OpenCommands()
	if err != nil {
		e.logErr(err)
		return false
	}
	unsent := true
	for _, c := range cmds {
		if c.ActionID != actionID || c.Type != cmdType {
			continue
		}
		cancelled, err := e.store.CancelCommand(c.ID)
		if err != nil || !cancelled {
			unsent = false
		}
	}
	return unsent
}

func (e *Engine) note(_ actions.Record, err error) { e.logErr(err) }

func (e *Engine) logErr(err error) {
	if err == nil {
		return
	}
	var c *actions.ConflictError
	if errors.As(err, &c) {
		// Someone else moved the action first; their transition stands.
		slog.Info("transition skipped: the action moved on", "detail", err.Error())
		return
	}
	slog.Error("state transition could not be persisted", "error", err)
}

// Shutdown stops waiting for confirmations and waits up to timeout for the
// driver calls in flight to finish.
func (e *Engine) Shutdown(timeout time.Duration) {
	e.stopOnce.Do(func() { close(e.stop) })
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
		slog.Warn("shutdown: driver calls still in flight; they will be recovered at the next start")
	}
}
