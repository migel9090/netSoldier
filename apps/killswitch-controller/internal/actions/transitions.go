package actions

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// Submission is what the policy decided about one detection.
type Submission struct {
	Event      events.DetectionEvent
	ActionType string
	PolicyRule string
	TTLSeconds int
	// Auto: the policy approves it itself (state approved, actor
	// auto-policy) and the caller applies it at once.
	Auto bool
	// OpDeadline is when the automatic apply must have an outcome.
	OpDeadline time.Time
}

// Submit outcomes.
const (
	// OutcomeCreated: a new action.
	OutcomeCreated = "created"
	// OutcomeFolded: a repeat of an open action's client and target; the
	// existing action is returned and nothing else changes.
	OutcomeFolded = "folded"
	// OutcomePromoted: an automatic decision for a client and target that
	// were already pending approval; the pending action was approved by the
	// policy instead of a second action being created.
	OutcomePromoted = "promoted"
	// OutcomeDuplicate: this detection id already has an action.
	OutcomeDuplicate = "duplicate"
)

// SubmitResult is the action a submission ended up in.
type SubmitResult struct {
	Record  Record
	Outcome string
	// Evicted lists pending actions expired to make room under MaxPending.
	Evicted []Record
}

// DedupeKey identifies "the same thing on the same device": the client by
// IP and MAC, and the target the detection names (or, without one, its
// indicator). A detection with neither has a key of its own.
func DedupeKey(ev events.DetectionEvent) string {
	var what string
	switch {
	case ev.Target != nil && ev.Target.Value != "":
		what = ev.Target.Type + ":" + strings.ToLower(ev.Target.Value)
	case ev.MatchedIoC != "":
		what = "ioc:" + ev.IoCType + ":" + strings.ToLower(ev.MatchedIoC)
	default:
		return "detection:" + ev.ID
	}
	return "client=" + ev.ClientIP + "/" + strings.ToLower(ev.ClientMAC) + "|" + what
}

// Submit records a policy decision.
//
// A detection id that already has an action gets that action back. A
// detection for a client and target that already have an open action
// (pending, approved, active or revert_failed) is folded into it — and an
// automatic decision promotes a pending one to approved — so a noisy
// detector cannot fill the queue with copies. Otherwise a new action is
// created; a new pending action beyond MaxPending expires the oldest one.
func (s *Store) Submit(sub Submission) (SubmitResult, error) {
	ev := sub.Event
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		storeErrors.WithLabelValues("submit").Inc()
		return SubmitResult{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit

	same, err := queryRecords(tx, "detection_id = ? OR last_detection_id = ? ORDER BY seq LIMIT 1", ev.ID, ev.ID)
	if err != nil {
		return SubmitResult{}, err
	}
	if len(same) > 0 {
		return SubmitResult{Record: same[0], Outcome: OutcomeDuplicate}, nil
	}

	key := DedupeKey(ev)
	open, err := queryRecords(tx, "dedupe_key = ? AND state IN "+openList+" ORDER BY seq DESC LIMIT 1", key)
	if err != nil {
		return SubmitResult{}, err
	}
	if len(open) > 0 {
		r := open[0]
		r.Repeats++
		r.LastDetectionID, r.LastSeenAt = ev.ID, now
		res := SubmitResult{Outcome: OutcomeFolded}
		var tr *Transition
		if sub.Auto && r.State == events.StatePending {
			r.State = events.StateApproved
			r.ApprovedBy, r.AutoApproved = ActorPolicy, true
			r.ActionType, r.PolicyRule, r.TTLSeconds = sub.ActionType, sub.PolicyRule, sub.TTLSeconds
			r.PendingUntil = time.Time{}
			r.Op, r.OpActor, r.OpReason, r.OpDeadline = OpApply, ActorPolicy, "", sub.OpDeadline
			res.Outcome = OutcomePromoted
			tr = &Transition{Actor: ActorPolicy,
				Reason: fmt.Sprintf("approved automatically: detection %s cleared the auto-block bar (%s)", ev.ID, sub.PolicyRule)}
		}
		if err := s.put(tx, &r, now); err != nil {
			return s.submitFailed(err)
		}
		if tr != nil {
			if err := insertAudit(tx, now, &r, events.StatePending, tr.Actor, tr.Reason); err != nil {
				return s.submitFailed(err)
			}
		}
		if err := tx.Commit(); err != nil {
			return s.submitFailed(err)
		}
		res.Record = r
		return res, nil
	}

	var domain string
	if ev.Target != nil && ev.Target.Type == events.TargetDomain {
		domain = ev.Target.Value
	}
	r := Record{
		EnforcementAction: events.EnforcementAction{
			SchemaVersion:    events.EnforcementSchemaVersion,
			Timestamp:        now,
			DetectionID:      ev.ID,
			DetectionSummary: ev.Summary,
			ClientName:       ev.ClientName,
			ActionType:       sub.ActionType,
			State:            events.StatePending,
			TargetMAC:        ev.ClientMAC,
			TargetIP:         ev.ClientIP,
			BlockedDomain:    domain,
			PolicyRule:       sub.PolicyRule,
			AutoApproved:     sub.Auto,
			TTLSeconds:       sub.TTLSeconds,
		},
		DedupeKey:  key,
		LastSeenAt: now,
	}
	res := SubmitResult{Outcome: OutcomeCreated}
	if sub.Auto {
		r.State, r.ApprovedBy = events.StateApproved, ActorPolicy
		r.Op, r.OpActor, r.OpDeadline = OpApply, ActorPolicy, sub.OpDeadline
	} else {
		r.PendingUntil = now.Add(s.opts.PendingTTL)
		if res.Evicted, err = s.makeRoom(tx, now); err != nil {
			return s.submitFailed(err)
		}
	}
	if err := s.put(tx, &r, now); err != nil {
		return s.submitFailed(err)
	}
	if err := insertAudit(tx, now, &r, "", ActorPolicy, sub.PolicyRule); err != nil {
		return s.submitFailed(err)
	}
	if err := tx.Commit(); err != nil {
		return s.submitFailed(err)
	}
	res.Record = r
	return res, nil
}

func (s *Store) submitFailed(err error) (SubmitResult, error) {
	storeErrors.WithLabelValues("submit").Inc()
	auditWriteFailures.Inc()
	return SubmitResult{}, fmt.Errorf("persist submission: %w", err)
}

// makeRoom expires the oldest pending actions until one more fits.
func (s *Store) makeRoom(tx *sql.Tx, now time.Time) ([]Record, error) {
	var n int
	if err := tx.QueryRow("SELECT COUNT(*) FROM actions WHERE state = 'pending'").Scan(&n); err != nil {
		return nil, err
	}
	over := n - s.opts.MaxPending + 1
	if over <= 0 {
		return nil, nil
	}
	oldest, err := queryRecords(tx, "state = 'pending' ORDER BY seq ASC LIMIT ?", over)
	if err != nil {
		return nil, err
	}
	for i := range oldest {
		r := &oldest[i]
		r.State, r.PendingUntil = events.StateExpired, time.Time{}
		if err := s.put(tx, r, now); err != nil {
			return nil, err
		}
		reason := fmt.Sprintf("approval queue full (%d pending): the oldest request was expired to make room", s.opts.MaxPending)
		if err := insertAudit(tx, now, r, events.StatePending, ActorSystem, reason); err != nil {
			return nil, err
		}
	}
	return oldest, nil
}

// Approve is the compare-and-swap at the heart of "applies exactly once":
// only a pending action becomes approved, and only one caller can make it
// so. actionType, when not empty, replaces the proposed type. deadline is
// when the apply that follows must have an outcome.
func (s *Store) Approve(id, actor, actionType string, deadline time.Time) (Record, error) {
	if _, err := s.ExpireIfDue(id); err != nil {
		return Record{}, err
	}
	return s.mutate("approve", id, func(r *Record, now time.Time) (*Transition, error) {
		if r.State != events.StatePending {
			return nil, conflict(r, "action %s is %s, not pending", r.ID, r.State)
		}
		reason := "approved"
		if actionType != "" && actionType != r.ActionType {
			reason = fmt.Sprintf("approved as %s (proposed %s)", actionType, r.ActionType)
			r.ActionType = actionType
		}
		r.State, r.ApprovedBy, r.PendingUntil = events.StateApproved, actor, time.Time{}
		r.Op, r.OpActor, r.OpReason, r.OpDeadline = OpApply, actor, "", deadline
		return &Transition{Actor: actor, Reason: reason}, nil
	})
}

// Reject closes a pending action without enforcing anything.
func (s *Store) Reject(id, actor, reason string) (Record, error) {
	if _, err := s.ExpireIfDue(id); err != nil {
		return Record{}, err
	}
	return s.mutate("reject", id, func(r *Record, now time.Time) (*Transition, error) {
		if r.State != events.StatePending {
			return nil, conflict(r, "action %s is %s, not pending", r.ID, r.State)
		}
		r.State, r.RejectedBy, r.Reason, r.PendingUntil = events.StateRejected, actor, reason, time.Time{}
		return &Transition{Actor: actor, Reason: reason}, nil
	})
}

// ExpireIfDue expires a pending action whose deadline has passed. It
// reports whether it did.
func (s *Store) ExpireIfDue(id string) (bool, error) {
	expired := false
	_, err := s.mutate("expire", id, func(r *Record, now time.Time) (*Transition, error) {
		if r.State != events.StatePending || r.PendingUntil.IsZero() || now.Before(r.PendingUntil) {
			return nil, errUnchanged
		}
		expired = true
		r.State, r.PendingUntil = events.StateExpired, time.Time{}
		return &Transition{Actor: ActorTTL,
			Reason: fmt.Sprintf("not approved within %s", s.opts.PendingTTL)}, nil
	})
	if errors.Is(err, errUnchanged) {
		err = nil
	}
	return expired, err
}

// errUnchanged aborts a mutate that has nothing to do.
var errUnchanged = errors.New("unchanged")

// BeginOp records that a driver operation is starting, before the driver
// is called. The action must be in one of the given states and have no
// other operation outstanding. No audit entry: the state has not changed.
func (s *Store) BeginOp(id, op, actor, reason string, deadline time.Time, from ...string) (Record, error) {
	return s.mutate("begin_op", id, func(r *Record, now time.Time) (*Transition, error) {
		if !inStates(r.State, from) {
			return nil, conflict(r, "action %s is %s, cannot %s", r.ID, r.State, op)
		}
		if r.Op != OpNone && r.Op != op {
			return nil, conflict(r, "action %s has a %s outstanding", r.ID, r.Op)
		}
		r.Op, r.OpActor, r.OpReason, r.OpDeadline = op, actor, reason, deadline
		return nil, nil
	})
}

// ExtendOp moves the deadline of the outstanding operation, for a driver
// whose backend confirms later.
func (s *Store) ExtendOp(id, op string, deadline time.Time) (Record, error) {
	return s.mutate("extend_op", id, func(r *Record, now time.Time) (*Transition, error) {
		if r.Op != op {
			return nil, conflict(r, "action %s has no %s outstanding", r.ID, op)
		}
		r.OpDeadline = deadline
		return nil, nil
	})
}

// ClearOp forgets an outstanding operation without changing the state.
func (s *Store) ClearOp(id string) (Record, error) {
	return s.mutate("clear_op", id, func(r *Record, now time.Time) (*Transition, error) {
		r.Op, r.OpActor, r.OpReason, r.OpDeadline = OpNone, "", "", time.Time{}
		return nil, nil
	})
}

// Activate records that the driver confirmed the apply. The TTL starts now,
// not at creation: an action approved an hour after it was proposed still
// lasts its full TTL.
func (s *Store) Activate(id, actor, reason string) (Record, error) {
	return s.mutate("activate", id, func(r *Record, now time.Time) (*Transition, error) {
		if r.State != events.StateApproved {
			return nil, conflict(r, "action %s is %s, not approved", r.ID, r.State)
		}
		at := now
		r.State, r.ActivatedAt, r.ExpiresAt, r.FailureReason = events.StateActive, &at, nil, ""
		if r.TTLSeconds > 0 {
			exp := at.Add(time.Duration(r.TTLSeconds) * time.Second)
			r.ExpiresAt = &exp
		}
		clearOp(r)
		return &Transition{Actor: actor, Reason: reason}, nil
	})
}

// ApplyFailed records that the apply did not take effect and nothing is
// enforced. It applies to an approved action, and to a revert_failed one
// that was never active (a failed apply whose compensation had to be
// retried).
func (s *Store) ApplyFailed(id, actor, failure string) (Record, error) {
	return s.mutate("apply_failed", id, func(r *Record, now time.Time) (*Transition, error) {
		neverActive := r.State == events.StateRevertFailed && r.ActivatedAt == nil
		if r.State != events.StateApproved && !neverActive {
			return nil, conflict(r, "action %s is %s, cannot fail an apply", r.ID, r.State)
		}
		r.State, r.FailureReason, r.NextAttemptAt = events.StateApplyFailed, failure, time.Time{}
		clearOp(r)
		return &Transition{Actor: actor, Reason: failure}, nil
	})
}

// Reverted records that the driver confirmed the enforcement is lifted. An
// action that was never active (its apply failed and had to be undone)
// ends as apply_failed instead: it was never in force.
func (s *Store) Reverted(id, actor, reason string) (Record, error) {
	return s.mutate("reverted", id, func(r *Record, now time.Time) (*Transition, error) {
		if !events.IsEnforcedState(r.State) {
			return nil, conflict(r, "action %s is %s, not enforced", r.ID, r.State)
		}
		clearOp(r)
		r.NextAttemptAt = time.Time{}
		if r.ActivatedAt == nil {
			r.State = events.StateApplyFailed
			return &Transition{Actor: actor, Reason: "the failed apply was undone: " + reason}, nil
		}
		at := now
		r.State, r.RevertedAt, r.RevertedBy, r.FailureReason = events.StateReverted, &at, actor, ""
		if reason != "" {
			r.Reason = reason
		}
		return &Transition{Actor: actor, Reason: reason}, nil
	})
}

// RevertFailed records that the enforcement could NOT be lifted: it is
// still in force and the reaper retries at next. A retry that fails again
// changes no state and is audited only when audit is set (an operator's
// attempt, as opposed to the reaper's own retries).
func (s *Store) RevertFailed(id, actor, failure string, next time.Time, audit bool) (Record, error) {
	return s.mutate("revert_failed", id, func(r *Record, now time.Time) (*Transition, error) {
		if !inStates(r.State, []string{events.StateApproved, events.StateActive, events.StateRevertFailed}) {
			return nil, conflict(r, "action %s is %s, cannot fail a revert", r.ID, r.State)
		}
		changed := r.State != events.StateRevertFailed
		r.State, r.FailureReason, r.NextAttemptAt = events.StateRevertFailed, failure, next
		r.Attempts++
		clearOp(r)
		if changed || audit {
			return &Transition{Actor: actor, Reason: failure}, nil
		}
		return nil, nil
	})
}

func clearOp(r *Record) {
	r.Op, r.OpActor, r.OpReason, r.OpDeadline = OpNone, "", "", time.Time{}
}

func inStates(state string, states []string) bool {
	for _, s := range states {
		if s == state {
			return true
		}
	}
	return false
}
