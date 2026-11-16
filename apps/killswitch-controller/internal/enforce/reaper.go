package enforce

import (
	"context"
	"log/slog"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/libs/events"
)

// Recover resumes what a previous run left unfinished. A synchronous
// driver call that was under way when the process stopped has an unknown
// outcome: an apply is undone (and ends apply_failed, or revert_failed if
// undoing fails), a revert is retried. A deferred operation keeps its
// persisted deadline and is left to the agent's result or the reaper.
func (e *Engine) Recover() {
	recs, err := e.store.WithOp()
	if err != nil {
		slog.Error("start-up recovery: cannot list unfinished operations", "error", err)
		return
	}
	for _, rec := range recs {
		drv, err := e.driver(rec.ActionType)
		if err == nil && drivers.IsDeferring(drv) {
			continue
		}
		slog.Warn("start-up recovery: driver call interrupted by the last stop", "action_id", rec.ID,
			"operation", rec.Op, "state", rec.State)
		e.runOp(rec.ID, rec.Op, func() { e.overdue(rec) })
	}
}

// runOp runs fn as the action's operation, unless one is in flight.
func (e *Engine) runOp(id, kind string, fn func()) bool {
	o, ok := e.begin(id, kind)
	if !ok {
		return false
	}
	go func() {
		defer e.end(id, o)
		fn()
	}()
	return true
}

// Run runs the reaper and the reconciliation until ctx is done.
func (e *Engine) Run(ctx context.Context) {
	reap := time.NewTicker(e.cfg.ReapInterval)
	defer reap.Stop()
	// The first reconciliation runs at once and is retried on every reaper
	// tick until it succeeds; after that, every ReconcileInterval.
	reconciled := false
	lastReconcile := time.Time{}
	for {
		if e.sink != nil && (!reconciled || time.Since(lastReconcile) >= e.cfg.ReconcileInterval) {
			if err := e.Reconcile(ctx); err == nil {
				reconciled, lastReconcile = true, time.Now()
			}
		}
		e.Reap(ctx)
		select {
		case <-ctx.Done():
			return
		case <-reap.C:
		}
	}
}

// Reap does one pass of the reaper's work:
//
//   - pending actions past their deadline become expired (actor ttl);
//   - active actions past expires_at are reverted (actor ttl);
//   - revert_failed actions are retried when their backoff has run out;
//   - operations past their deadline are resolved (overdue);
//   - finished actions beyond the cap, and old ledger, audit and command
//     rows, are pruned.
func (e *Engine) Reap(ctx context.Context) {
	now := e.now()
	due, err := e.store.Due(now)
	if err != nil {
		slog.Error("reaper: cannot read due actions", "error", err)
		return
	}
	for _, r := range due.Expire {
		if expired, err := e.store.ExpireIfDue(r.ID); err != nil {
			e.logErr(err)
		} else if expired {
			pendingExpired.WithLabelValues("ttl").Inc()
			slog.Info("pending action expired unapproved", "action_id", r.ID)
		}
	}
	for _, r := range due.Revert {
		if e.Busy(r.ID) {
			continue
		}
		reason := "TTL expired"
		if r.State == events.StateRevertFailed {
			reason = "retry of a failed revert"
		}
		if _, _, err := e.startRevert(r, actions.ActorTTL, reason); err != nil {
			e.logErr(err)
		}
	}
	for _, r := range due.Overdue {
		rec := r
		e.runOp(rec.ID, rec.Op, func() { e.overdue(rec) })
	}
	if err := e.store.Prune(now, e.cfg.Prune); err != nil {
		slog.Error("reaper: prune failed", "error", err)
	}
	e.refreshGauges()
	_ = ctx
}

func (e *Engine) refreshGauges() {
	counts, err := e.store.Counts()
	if err != nil {
		return
	}
	pendingActions.Set(float64(counts[events.StatePending]))
	activeActions.Set(float64(counts[events.StateActive] + counts[events.StateRevertFailed]))
	revertFailedActions.Set(float64(counts[events.StateRevertFailed]))
	awaitingActions.Set(float64(counts[events.StateApproved]))
}

// Reconcile compares what the store says the sinkhole enforces with
// AdGuard's rules. What this service added and nothing needs is removed;
// an enforcement that is gone is recorded as ended (actor reconcile), never
// silently re-created; a rule this service did not add is never touched.
// When AdGuard cannot be read, nothing changes.
func (e *Engine) Reconcile(ctx context.Context) error {
	if e.sink == nil {
		return nil
	}
	recs, err := e.store.InForce(events.ActionDNSSinkhole)
	if err != nil {
		return err
	}
	var claims []drivers.SinkholeClaim
	byID := map[string]actions.Record{}
	outstanding := map[string]bool{}
	for _, r := range recs {
		byID[r.ID] = r
		if r.Op != actions.OpNone || r.State == events.StateApproved {
			outstanding[r.ID] = true
			continue
		}
		claims = append(claims, drivers.SinkholeClaim{ActionID: r.ID, Domain: r.BlockedDomain})
	}
	inFlight := func(id string) bool { return outstanding[id] || e.Busy(id) }

	rctx, cancel := context.WithTimeout(ctx, 2*e.cfg.DriverTimeout)
	rep, err := e.sink.Reconcile(rctx, claims, inFlight)
	cancel()
	if err != nil {
		reconcileRuns.WithLabelValues(events.ActionDNSSinkhole, "error").Inc()
		slog.Error("sinkhole reconciliation failed; nothing was changed, will retry", "error", err)
		return err
	}
	reconcileRuns.WithLabelValues(events.ActionDNSSinkhole, "ok").Inc()
	count := func(finding string, n int) {
		if n > 0 {
			reconcileFindings.WithLabelValues(events.ActionDNSSinkhole, finding).Add(float64(n))
		}
	}
	count(findingRemoved, len(rep.Removed))
	count(findingStaleRef, len(rep.StaleRefs))
	count(findingAdopted, len(rep.Adopted))
	for _, id := range rep.Missing {
		r := byID[id]
		if r.State == events.StateRevertFailed {
			count(findingRevertTookEffect, 1)
			e.note(e.store.Reverted(id, actions.ActorReconcile,
				"the rule is no longer in AdGuard: the failed revert took effect after all"))
			continue
		}
		count(findingMissing, 1)
		slog.Warn("sinkhole rule missing from AdGuard: recording the action as lifted, not re-applying it",
			"action_id", id, "domain", r.BlockedDomain)
		e.note(e.store.Reverted(id, actions.ActorReconcile,
			"the AdGuard rule for "+r.BlockedDomain+" is gone (removed outside netSoldier, or lost by AdGuard); recorded as lifted, not re-applied"))
	}
	if n := len(rep.Missing) + len(rep.Removed) + len(rep.StaleRefs) + len(rep.Adopted); n > 0 {
		slog.Warn("sinkhole reconciliation repaired differences", "missing", rep.Missing,
			"orphan_rules_removed", rep.Removed, "stale_references", rep.StaleRefs, "adopted", rep.Adopted)
	} else {
		slog.Info("sinkhole reconciliation: store and AdGuard agree", "enforced", len(claims))
	}
	return nil
}

// maxCommandsPerPoll bounds one poll response. The agent acts on at most
// 16 commands per response and ignores the rest, so handing out more would
// mark commands sent that it never sees.
const maxCommandsPerPoll = 16

// AgentPoll serves one netagent poll (contract §8.2): it applies the
// results the agent reports, reconciles with the isolations it says are in
// force, and hands it the queued commands.
func (e *Engine) AgentPoll(req drivers.PollRequest) (drivers.PollResponse, error) {
	resp := drivers.PollResponse{Commands: []drivers.AgentCommand{}}
	if e.agent == nil {
		return resp, nil
	}
	if dropped := req.Sanitize(); dropped > 0 {
		agentInvalidEntries.Add(float64(dropped))
		slog.Warn("netagent poll: malformed entries dropped", "agent", req.Agent, "dropped", dropped)
	}
	e.agent.Seen(req.Agent)

	for _, res := range req.Results {
		cmd, changed, err := e.store.CompleteCommand(res.ID, res.OK, res.Error)
		if err != nil {
			return resp, err
		}
		if !changed {
			agentUnknownResults.Inc()
			continue
		}
		e.onCommandResult(cmd, res.OK, res.Error)
	}
	if err := e.reconcileAgent(req.Active); err != nil {
		return resp, err
	}
	cmds, err := e.store.TakeCommands(maxCommandsPerPoll)
	if err != nil {
		return resp, err
	}
	resp.Commands = append(resp.Commands, cmds...)
	return resp, nil
}

func (e *Engine) onCommandResult(cmd drivers.AgentCommand, ok bool, errText string) {
	outcome := "ok"
	if !ok {
		outcome = "refused"
	}
	agentResults.WithLabelValues(cmd.Type, outcome).Inc()
	if cmd.ActionID == "" {
		if !ok {
			slog.Error("netagent refused a release requested by reconciliation", "mac", cmd.MAC, "ip", cmd.IP, "error", errText)
		}
		return
	}
	defer e.signal(cmd.ActionID)
	rec, err := e.store.Get(cmd.ActionID)
	if err != nil {
		e.logErr(err)
		return
	}
	switch cmd.Type {
	case drivers.CommandIsolate:
		switch {
		case rec.State == events.StateApproved && rec.Op == actions.OpApply && ok:
			e.note(e.store.Activate(rec.ID, actions.ActorAgent, "the netagent confirmed the isolation"))
		case rec.State == events.StateApproved && rec.Op == actions.OpApply:
			driverFailures.WithLabelValues("apply").Inc()
			slog.Error("netagent refused the isolation — device is NOT isolated", "action_id", rec.ID, "error", errText)
			e.note(e.store.ApplyFailed(rec.ID, actions.ActorAgent, "the netagent refused the isolation: "+errText))
		case ok && !events.IsEnforcedState(rec.State):
			// Confirmed after the controller gave up on it: nothing here
			// wants this isolation any more.
			reconcileFindings.WithLabelValues(events.ActionARPIsolate, findingLateConfirmation).Inc()
			if err := e.agent.Release(cmd.MAC, cmd.IP); err != nil {
				e.logErr(err)
			}
		case !ok && rec.State == events.StateActive && rec.Op == actions.OpNone:
			// A re-issue of an isolation the agent had dropped was refused:
			// it is not in force and cannot be restored.
			slog.Error("netagent refused to restore an isolation it had dropped — device is NOT isolated",
				"action_id", rec.ID, "error", errText)
			e.note(e.store.Reverted(rec.ID, actions.ActorAgent,
				"the netagent no longer had this isolation and refused to restore it: "+errText))
		}
	case drivers.CommandRelease:
		if !events.IsEnforcedState(rec.State) {
			return
		}
		actor, reason := rec.OpActor, rec.OpReason
		if rec.Op != actions.OpRevert || actor == "" {
			actor, reason = actions.ActorAgent, "the netagent confirmed a release"
		}
		if ok {
			e.note(e.store.Reverted(rec.ID, actor, reason))
			return
		}
		e.revertFailed(rec, actor, "the netagent refused the release: "+errText)
	}
}

// reconcileAgent compares the agent's active list with the isolations the
// store has in force, on every poll:
//
//   - an isolation nobody here owns is released;
//   - an active isolation the agent no longer has (it restarted, or its own
//     clock ran out first) is issued again for the rest of its TTL — the
//     agent extends a repeat rather than duplicating it; one that was due
//     anyway is recorded as ended by ttl;
//   - a revert_failed isolation the agent no longer has did end after all.
func (e *Engine) reconcileAgent(active []drivers.AgentIsolation) error {
	recs, err := e.store.InForce(events.ActionARPIsolate)
	if err != nil {
		return err
	}
	open, err := e.store.OpenCommands()
	if err != nil {
		return err
	}
	owned := map[string]bool{}
	for _, r := range recs {
		owned[drivers.CanonicalMAC(r.TargetMAC)] = true
	}
	pending := map[string]bool{}
	for _, c := range open {
		pending[c.MAC] = true
	}
	listed := map[string]bool{}
	for _, a := range active {
		listed[a.MAC] = true
		if owned[a.MAC] || pending[a.MAC] {
			continue
		}
		reconcileFindings.WithLabelValues(events.ActionARPIsolate, findingUnowned).Inc()
		slog.Warn("netagent reports an isolation nothing here owns: releasing it", "mac", a.MAC, "ip", a.IP)
		if err := e.agent.Release(a.MAC, a.IP); err != nil {
			e.logErr(err)
		}
		pending[a.MAC] = true
	}
	now := e.now()
	for _, r := range recs {
		mac := drivers.CanonicalMAC(r.TargetMAC)
		if !events.IsEnforcedState(r.State) || r.Op != actions.OpNone || e.Busy(r.ID) || listed[mac] || pending[mac] {
			continue
		}
		if r.State == events.StateActive && r.ActivatedAt != nil && now.Sub(*r.ActivatedAt) < e.cfg.AgentGrace {
			continue
		}
		if r.State == events.StateRevertFailed {
			reconcileFindings.WithLabelValues(events.ActionARPIsolate, findingRevertTookEffect).Inc()
			e.note(e.store.Reverted(r.ID, actions.ActorReconcile,
				"the netagent no longer reports the isolation: the failed release took effect"))
			continue
		}
		if r.ExpiresAt != nil && !now.Before(r.ExpiresAt.Add(-e.cfg.AgentGrace)) {
			e.note(e.store.Reverted(r.ID, actions.ActorTTL, "TTL expired (ended by the netagent's own clock)"))
			continue
		}
		remaining := 0
		if r.ExpiresAt != nil {
			remaining = int(r.ExpiresAt.Sub(now).Seconds()) + 1
		}
		reconcileFindings.WithLabelValues(events.ActionARPIsolate, findingReissued).Inc()
		slog.Warn("netagent no longer reports an isolation that is still wanted: issuing it again",
			"action_id", r.ID, "mac", mac, "ttl_seconds", remaining)
		a := r.Action()
		if err := e.agent.Reissue(&a, remaining); err != nil {
			// It cannot be restored from here: it is not in force.
			e.note(e.store.Reverted(r.ID, actions.ActorReconcile,
				"the netagent no longer has this isolation and it cannot be issued again: "+err.Error()))
		}
		pending[mac] = true
	}
	return nil
}
