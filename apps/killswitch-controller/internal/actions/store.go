package actions

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

var actionCounter atomic.Int64

// StoreOptions configures retention and identity.
type StoreOptions struct {
	// MaxActions bounds the in-memory map. Every /evaluate call creates an
	// action and nothing used to evict them, so a noisy detector (or an
	// unauthenticated caller) grew the map until the pod hit its limit.
	// Oldest terminal actions are dropped first; pending and active ones
	// are never evicted because they still describe live enforcement.
	MaxActions int
	// IDPrefix namespaces action IDs per process. A plain global counter
	// restarted at 1 on every boot, so "ACT-1" in the ClickHouse audit log
	// could mean several different actions over a service's lifetime.
	IDPrefix string
}

// Store manages enforcement actions through their lifecycle.
// Thread-safe for concurrent API and TTL-revert access.
// The store is a pure state machine — driver calls happen outside.
type Store struct {
	mu      sync.RWMutex
	actions map[string]*events.EnforcementAction
	order   []string // insertion order, for bounded eviction
	audit   AuditWriter
	opts    StoreOptions
}

// AuditWriter records every state transition for accountability.
type AuditWriter interface {
	Write(ctx context.Context, entry AuditEntry) error
}

// AuditEntry is a single append-only audit record.
type AuditEntry struct {
	Timestamp   string `json:"timestamp"`
	ActionID    string `json:"action_id"`
	FromState   string `json:"from_state"`
	ToState     string `json:"to_state"`
	Actor       string `json:"actor"`
	Reason      string `json:"reason"`
	DetectionID string `json:"detection_id"`
	TargetMAC   string `json:"target_mac"`
	TargetIP    string `json:"target_ip"`
	ActionType  string `json:"action_type"`
}

func NewStore(audit AuditWriter, opts StoreOptions) *Store {
	if opts.MaxActions <= 0 {
		opts.MaxActions = 10000
	}
	if opts.IDPrefix == "" {
		opts.IDPrefix = "ACT"
	}
	return &Store{
		actions: make(map[string]*events.EnforcementAction),
		audit:   audit,
		opts:    opts,
	}
}

// terminalStates are safe to evict: they no longer describe live enforcement.
var terminalStates = map[string]struct{}{
	events.StateReverted: {},
	events.StateRejected: {},
	events.StateFailed:   {},
}

// Create inserts a new enforcement action. For auto-approved actions,
// state starts at Approved; otherwise Pending.
func (s *Store) Create(detectionID, targetMAC, targetIP, actionType, policyRule string, ttl int, autoApproved bool, domain string) *events.EnforcementAction {
	id := fmt.Sprintf("%s-%d", s.opts.IDPrefix, actionCounter.Add(1))
	now := time.Now()

	state := events.StatePending
	var approvedBy string
	if autoApproved {
		state = events.StateApproved
		approvedBy = "auto-policy"
	}

	var expiresAt *time.Time
	if ttl > 0 {
		t := now.Add(time.Duration(ttl) * time.Second)
		expiresAt = &t
	}

	action := &events.EnforcementAction{
		SchemaVersion: events.EnforcementSchemaVersion,
		ID:            id,
		Timestamp:     now,
		DetectionID:   detectionID,
		ActionType:    actionType,
		State:         state,
		TargetMAC:     targetMAC,
		TargetIP:      targetIP,
		BlockedDomain: domain,
		PolicyRule:    policyRule,
		AutoApproved:  autoApproved,
		TTLSeconds:    ttl,
		ExpiresAt:     expiresAt,
		ApprovedBy:    approvedBy,
	}

	s.mu.Lock()
	s.actions[id] = action
	s.order = append(s.order, id)
	s.evictLocked()
	s.mu.Unlock()

	s.writeAudit("", state, "system", "created", action)
	slog.Info("action created", "id", id, "state", state, "target", targetMAC, "type", actionType)
	return action
}

// Approve transitions a pending action to approved. Idempotent: returns
// nil if the action is already approved or active.
func (s *Store) Approve(id, approvedBy string) error {
	return s.transition(id, events.StateApproved, approvedBy, "approved by "+approvedBy,
		events.StatePending)
}

// Reject transitions a pending action to rejected. Idempotent.
func (s *Store) Reject(id, reason string) error {
	return s.transition(id, events.StateRejected, "operator", reason,
		events.StatePending)
}

// Activate transitions an approved action to active. Idempotent.
func (s *Store) Activate(id string) error {
	return s.transition(id, events.StateActive, "system", "enforcement applied",
		events.StateApproved)
}

// Revert transitions an active action to reverted. Idempotent.
func (s *Store) Revert(id, reason string) error {
	s.mu.Lock()
	a, ok := s.actions[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("action %s not found", id)
	}
	if a.State == events.StateReverted {
		s.mu.Unlock()
		return nil
	}
	if a.State != events.StateActive && a.State != events.StateFailed {
		s.mu.Unlock()
		return fmt.Errorf("action %s is %s, cannot revert", id, a.State)
	}
	from := a.State
	a.State = events.StateReverted
	now := time.Now()
	a.RevertedAt = &now
	s.mu.Unlock()

	s.writeAudit(from, events.StateReverted, "system", reason, a)
	slog.Info("action reverted", "id", id, "reason", reason)
	return nil
}

// RecordFailure marks an action as failed and records why. It exists so a
// driver error is visible in the API and the audit log instead of only in the
// pod's stderr: "approved but never enforced" and "actively enforced" must
// not look the same to whoever is reading the queue.
func (s *Store) RecordFailure(id, reason string) {
	s.mu.Lock()
	a, ok := s.actions[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	from := a.State
	a.State = events.StateFailed
	a.FailureReason = reason
	s.mu.Unlock()

	s.writeAudit(from, events.StateFailed, "system", reason, a)
	slog.Error("action failed", "id", id, "from", from, "reason", reason)
}

// evictLocked drops the oldest terminal actions once the map exceeds
// MaxActions. Caller must hold the write lock.
func (s *Store) evictLocked() {
	if len(s.actions) <= s.opts.MaxActions {
		return
	}
	kept := s.order[:0:0]
	removed := 0
	target := len(s.actions) - s.opts.MaxActions
	for _, id := range s.order {
		a, ok := s.actions[id]
		if !ok {
			continue
		}
		if removed < target {
			if _, terminal := terminalStates[a.State]; terminal {
				delete(s.actions, id)
				removed++
				continue
			}
		}
		kept = append(kept, id)
	}
	s.order = kept
	if removed > 0 {
		slog.Debug("evicted terminal actions", "count", removed, "remaining", len(s.actions))
	}
}

// transition is the generic idempotent state changer.
// allowedFrom lists the valid source states; if the action is already
// in the target state, it returns nil (idempotent).
func (s *Store) transition(id, to, actor, reason string, allowedFrom ...string) error {
	s.mu.Lock()
	a, ok := s.actions[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("action %s not found", id)
	}
	if a.State == to {
		s.mu.Unlock()
		return nil
	}
	allowed := false
	for _, f := range allowedFrom {
		if a.State == f {
			allowed = true
			break
		}
	}
	if !allowed {
		s.mu.Unlock()
		return fmt.Errorf("action %s is %s, cannot transition to %s", id, a.State, to)
	}
	from := a.State
	a.State = to
	if to == events.StateApproved {
		a.ApprovedBy = actor
	}
	s.mu.Unlock()

	s.writeAudit(from, to, actor, reason, a)
	slog.Info("action transitioned", "id", id, "from", from, "to", to)
	return nil
}

// Get returns an action by ID, or nil if not found.
func (s *Store) Get(id string) *events.EnforcementAction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a, ok := s.actions[id]; ok {
		copy := *a
		return &copy
	}
	return nil
}

// ListByState returns all actions in the given state.
func (s *Store) ListByState(state string) []events.EnforcementAction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []events.EnforcementAction
	for _, a := range s.actions {
		if a.State == state {
			out = append(out, *a)
		}
	}
	return out
}

// ListExpired returns active actions that have passed their TTL.
func (s *Store) ListExpired() []events.EnforcementAction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []events.EnforcementAction
	for _, a := range s.actions {
		if a.State == events.StateActive && a.ExpiresAt != nil && time.Now().After(*a.ExpiresAt) {
			out = append(out, *a)
		}
	}
	return out
}

func (s *Store) writeAudit(from, to, actor, reason string, a *events.EnforcementAction) {
	if s.audit == nil {
		return
	}
	entry := AuditEntry{
		// Millisecond precision: two transitions on the same action within
		// one second were previously indistinguishable and unorderable in
		// the audit log.
		Timestamp:   time.Now().UTC().Format("2006-01-02 15:04:05.000"),
		ActionID:    a.ID,
		FromState:   from,
		ToState:     to,
		Actor:       actor,
		Reason:      reason,
		DetectionID: a.DetectionID,
		TargetMAC:   a.TargetMAC,
		TargetIP:    a.TargetIP,
		ActionType:  a.ActionType,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.audit.Write(ctx, entry); err != nil {
		auditWriteFailures.Inc()
		// An enforcement action with no audit record is an accountability
		// gap, not a log line to shrug at — surface it as a metric so it
		// can be alerted on.
		slog.Error("audit write FAILED — enforcement action has no audit record",
			"action_id", a.ID, "from", from, "to", to, "error", err)
	}
}

var auditWriteFailures = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "killswitch",
	Name:      "audit_write_failures_total",
	Help:      "Audit records that could not be persisted (accountability gap).",
})

func init() {
	prometheus.MustRegister(auditWriteFailures)
}
