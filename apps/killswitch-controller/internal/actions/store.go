package actions

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

var actionCounter atomic.Int64

// RevertHook is called when an action is reverted (TTL or manual) so
// the enforcement driver can unapply the block.
type RevertHook func(action *events.EnforcementAction)

// Store manages enforcement actions through their lifecycle.
// Thread-safe for concurrent API and TTL-revert access.
type Store struct {
	mu       sync.RWMutex
	actions  map[string]*events.EnforcementAction
	audit    AuditWriter
	OnRevert RevertHook
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

func NewStore(audit AuditWriter) *Store {
	return &Store{
		actions: make(map[string]*events.EnforcementAction),
		audit:   audit,
	}
}

// Create inserts a new enforcement action. For auto-approved actions,
// state starts at Approved; otherwise Pending.
func (s *Store) Create(detectionID, targetMAC, targetIP, actionType, policyRule string, ttl int, autoApproved bool, domain string) *events.EnforcementAction {
	id := fmt.Sprintf("ACT-%d", actionCounter.Add(1))
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
	s.mu.Unlock()

	s.writeAudit("", state, "system", "created", action)
	slog.Info("action created", "id", id, "state", state, "target", targetMAC, "type", actionType)
	return action
}

// Approve transitions a pending action to approved.
func (s *Store) Approve(id, approvedBy string) error {
	return s.transition(id, events.StatePending, events.StateApproved, approvedBy, "approved by "+approvedBy)
}

// Reject transitions a pending action to rejected.
func (s *Store) Reject(id, reason string) error {
	return s.transition(id, events.StatePending, events.StateRejected, "operator", reason)
}

// Activate transitions an approved action to active.
func (s *Store) Activate(id string) error {
	return s.transition(id, events.StateApproved, events.StateActive, "system", "enforcement applied")
}

// Revert transitions an active action to reverted.
func (s *Store) Revert(id, reason string) error {
	s.mu.Lock()
	a, ok := s.actions[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("action %s not found", id)
	}
	if a.State != events.StateActive {
		s.mu.Unlock()
		return fmt.Errorf("action %s is %s, not active", id, a.State)
	}
	from := a.State
	a.State = events.StateReverted
	now := time.Now()
	a.RevertedAt = &now
	s.mu.Unlock()

	s.writeAudit(from, events.StateReverted, "system", reason, a)
	slog.Info("action reverted", "id", id, "reason", reason)

	if s.OnRevert != nil {
		copy := *a
		go s.OnRevert(&copy)
	}
	return nil
}

func (s *Store) transition(id, expectedFrom, to, actor, reason string) error {
	s.mu.Lock()
	a, ok := s.actions[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("action %s not found", id)
	}
	if a.State != expectedFrom {
		s.mu.Unlock()
		return fmt.Errorf("action %s is %s, expected %s", id, a.State, expectedFrom)
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

// RevertExpired checks all active actions and reverts those past their TTL.
func (s *Store) RevertExpired() {
	s.mu.RLock()
	var expired []string
	for id, a := range s.actions {
		if a.State == events.StateActive && a.ExpiresAt != nil && time.Now().After(*a.ExpiresAt) {
			expired = append(expired, id)
		}
	}
	s.mu.RUnlock()

	for _, id := range expired {
		s.Revert(id, "TTL expired")
	}
}

// RunTTLRevert periodically checks for expired active actions.
func (s *Store) RunTTLRevert(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.RevertExpired()
		}
	}
}

func (s *Store) writeAudit(from, to, actor, reason string, a *events.EnforcementAction) {
	if s.audit == nil {
		return
	}
	entry := AuditEntry{
		Timestamp:   time.Now().UTC().Format("2006-01-02 15:04:05"),
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
		slog.Warn("audit write failed", "action_id", a.ID, "error", err)
	}
}
