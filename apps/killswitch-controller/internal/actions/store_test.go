package actions

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

func newTestStore() *Store {
	return NewStore(NopAuditWriter{}, StoreOptions{})
}

func TestCreatePending(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")

	if a.State != events.StatePending {
		t.Fatalf("expected pending state, got %q", a.State)
	}
	if a.AutoApproved {
		t.Fatal("should not be auto-approved")
	}
}

func TestCreateAutoApproved(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, true, "evil.com")

	if a.State != events.StateApproved {
		t.Fatalf("expected approved state for auto, got %q", a.State)
	}
	if !a.AutoApproved {
		t.Fatal("should be auto-approved")
	}
	if a.ApprovedBy != "auto-policy" {
		t.Fatalf("expected approver auto-policy, got %q", a.ApprovedBy)
	}
}

func TestApprovePending(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")

	if err := s.Approve(a.ID, "operator"); err != nil {
		t.Fatal(err)
	}

	got := s.Get(a.ID)
	if got.State != events.StateApproved {
		t.Fatalf("expected approved, got %q", got.State)
	}
}

func TestApproveIdempotent(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")
	s.Approve(a.ID, "op1")

	if err := s.Approve(a.ID, "op2"); err != nil {
		t.Fatalf("second approve should be idempotent, got %v", err)
	}
}

func TestRejectPending(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")

	if err := s.Reject(a.ID, "false positive"); err != nil {
		t.Fatal(err)
	}

	got := s.Get(a.ID)
	if got.State != events.StateRejected {
		t.Fatalf("expected rejected, got %q", got.State)
	}
}

func TestActivateApproved(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")
	s.Approve(a.ID, "operator")

	if err := s.Activate(a.ID); err != nil {
		t.Fatal(err)
	}

	got := s.Get(a.ID)
	if got.State != events.StateActive {
		t.Fatalf("expected active, got %q", got.State)
	}
}

func TestRevertActive(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")
	s.Approve(a.ID, "operator")
	s.Activate(a.ID)

	if err := s.Revert(a.ID, "manual revert"); err != nil {
		t.Fatal(err)
	}

	got := s.Get(a.ID)
	if got.State != events.StateReverted {
		t.Fatalf("expected reverted, got %q", got.State)
	}
	if got.RevertedAt == nil {
		t.Fatal("RevertedAt should be set")
	}
}

func TestRevertIdempotent(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")
	s.Approve(a.ID, "operator")
	s.Activate(a.ID)
	s.Revert(a.ID, "first revert")

	if err := s.Revert(a.ID, "second revert"); err != nil {
		t.Fatalf("second revert should be idempotent, got %v", err)
	}
}

func TestInvalidTransitions(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")

	if err := s.Activate(a.ID); err == nil {
		t.Fatal("should not activate a pending action")
	}

	if err := s.Revert(a.ID, "reason"); err == nil {
		t.Fatal("should not revert a pending action")
	}
}

func TestRejectNotAllowedAfterApproval(t *testing.T) {
	s := newTestStore()
	a := s.Create("DET-1", "", "192.168.1.10", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")
	s.Approve(a.ID, "operator")

	if err := s.Reject(a.ID, "too late"); err == nil {
		t.Fatal("should not reject an approved action")
	}
}

func TestGetNotFound(t *testing.T) {
	s := newTestStore()
	if s.Get("NONEXISTENT") != nil {
		t.Fatal("expected nil for unknown action")
	}
}

func TestListByState(t *testing.T) {
	s := newTestStore()
	s.Create("DET-1", "", "10.0.0.1", events.ActionDNSSinkhole, "test", 3600, false, "evil.com")
	s.Create("DET-2", "", "10.0.0.2", events.ActionDNSSinkhole, "test", 3600, false, "bad.com")
	a3 := s.Create("DET-3", "", "10.0.0.3", events.ActionDNSSinkhole, "test", 3600, true, "worse.com")
	s.Activate(a3.ID)

	pending := s.ListByState(events.StatePending)
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending, got %d", len(pending))
	}

	active := s.ListByState(events.StateActive)
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}
}

func TestActionNotFoundErrors(t *testing.T) {
	s := newTestStore()

	if err := s.Approve("FAKE", "op"); err == nil {
		t.Fatal("expected error for unknown action")
	}
	if err := s.Reject("FAKE", "reason"); err == nil {
		t.Fatal("expected error for unknown action")
	}
	if err := s.Activate("FAKE"); err == nil {
		t.Fatal("expected error for unknown action")
	}
	if err := s.Revert("FAKE", "reason"); err == nil {
		t.Fatal("expected error for unknown action")
	}
}

// TestRecordFailureMarksActionFailed covers the state that distinguishes
// "approved but never enforced" from "actively enforced". Collapsing a driver
// failure into either `active` or `reverted` told the operator the device was
// in a state it was not — the one lie a killswitch must never tell.
func TestRecordFailureMarksActionFailed(t *testing.T) {
	s := NewStore(NopAuditWriter{}, StoreOptions{})
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 3600, true, "evil.example")

	s.RecordFailure(a.ID, "adguard 500: boom")

	got := s.Get(a.ID)
	if got == nil {
		t.Fatal("action disappeared")
	}
	if got.State != events.StateFailed {
		t.Errorf("state = %q, want failed", got.State)
	}
	if got.FailureReason != "adguard 500: boom" {
		t.Errorf("failure_reason = %q, want the driver error", got.FailureReason)
	}
}

func TestRecordFailureUnknownActionIsNoop(t *testing.T) {
	s := NewStore(NopAuditWriter{}, StoreOptions{})
	s.RecordFailure("ACT-nope", "whatever") // must not panic
}

// TestFailedActionCanBeReverted: a failed apply may have partially landed, so
// an operator has to be able to drive a revert rather than being stuck.
func TestFailedActionCanBeReverted(t *testing.T) {
	s := NewStore(NopAuditWriter{}, StoreOptions{})
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 3600, true, "evil.example")
	s.RecordFailure(a.ID, "partial apply")

	if err := s.Revert(a.ID, "operator cleanup"); err != nil {
		t.Fatalf("a failed action should be revertible: %v", err)
	}
	if got := s.Get(a.ID); got.State != events.StateReverted {
		t.Errorf("state = %q, want reverted", got.State)
	}
}

// TestStoreEvictsTerminalActionsOnly is the memory-leak regression test.
// Every /evaluate call creates an action and nothing ever evicted them, so a
// noisy detector grew the map until the pod hit its limit. Pending and active
// actions describe LIVE enforcement and must never be dropped.
func TestStoreEvictsTerminalActionsOnly(t *testing.T) {
	s := NewStore(NopAuditWriter{}, StoreOptions{MaxActions: 10})

	// Five actions that stay live (pending).
	var live []string
	for i := 0; i < 5; i++ {
		a := s.Create("DET-live", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
			events.ActionDNSSinkhole, "test", 3600, false, "live.example")
		live = append(live, a.ID)
	}

	// Many actions driven to a terminal state.
	for i := 0; i < 50; i++ {
		a := s.Create("DET-term", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
			events.ActionDNSSinkhole, "test", 3600, false, "term.example")
		if err := s.Reject(a.ID, "not interesting"); err != nil {
			t.Fatal(err)
		}
	}

	// Every live action must survive.
	for _, id := range live {
		if s.Get(id) == nil {
			t.Fatalf("pending action %s was evicted — it still describes live enforcement", id)
		}
	}

	// And the map must be bounded.
	total := len(s.ListByState(events.StatePending)) +
		len(s.ListByState(events.StateRejected)) +
		len(s.ListByState(events.StateActive)) +
		len(s.ListByState(events.StateReverted))
	if total > 10 {
		t.Errorf("store holds %d actions, want at most MaxActions=10", total)
	}
}

func TestStoreIDPrefixNamespacesActions(t *testing.T) {
	// A plain global counter restarted at 1 on every boot, so "ACT-1" in the
	// ClickHouse audit log could refer to several different actions over a
	// service's lifetime.
	s := NewStore(NopAuditWriter{}, StoreOptions{IDPrefix: "ACT-host-123"})
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 0, false, "x.example")
	if !strings.HasPrefix(a.ID, "ACT-host-123-") {
		t.Errorf("action ID %q should carry the instance prefix", a.ID)
	}
}

func TestStoreDefaultsApplied(t *testing.T) {
	s := NewStore(NopAuditWriter{}, StoreOptions{MaxActions: -1, IDPrefix: ""})
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "", events.ActionDNSSinkhole,
		"test", 0, false, "x.example")
	if !strings.HasPrefix(a.ID, "ACT-") {
		t.Errorf("default prefix not applied: %q", a.ID)
	}
	if s.opts.MaxActions <= 0 {
		t.Errorf("MaxActions should fall back to a positive default, got %d", s.opts.MaxActions)
	}
}

// TestAuditTimestampHasSubSecondPrecision: two transitions on the same action
// within one second were previously indistinguishable and unorderable in the
// audit log, which is the record the whole human-in-the-loop story rests on.
func TestAuditTimestampHasSubSecondPrecision(t *testing.T) {
	rec := &recordingAudit{}
	s := NewStore(rec, StoreOptions{})
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 3600, false, "x.example")
	if err := s.Approve(a.ID, "operator"); err != nil {
		t.Fatal(err)
	}

	entries := rec.entries()
	if len(entries) < 2 {
		t.Fatalf("expected at least 2 audit entries, got %d", len(entries))
	}
	for _, e := range entries {
		if !strings.Contains(e.Timestamp, ".") {
			t.Errorf("audit timestamp %q has no sub-second component", e.Timestamp)
		}
	}
}

type recordingAudit struct {
	mu  sync.Mutex
	buf []AuditEntry
}

func (r *recordingAudit) Write(_ context.Context, e AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, e)
	return nil
}

func (r *recordingAudit) entries() []AuditEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]AuditEntry, len(r.buf))
	copy(out, r.buf)
	return out
}

// TestAuditFailureDoesNotBlockTransition: losing an audit record is serious,
// but it must not wedge the state machine — the operator still needs to be
// able to revert.
func TestAuditFailureDoesNotBlockTransition(t *testing.T) {
	s := NewStore(failingAudit{}, StoreOptions{})
	a := s.Create("DET-1", "aa:bb:cc:dd:ee:ff", "192.168.1.10",
		events.ActionDNSSinkhole, "test", 3600, false, "x.example")
	if err := s.Approve(a.ID, "operator"); err != nil {
		t.Fatalf("transition should still succeed when the audit sink fails: %v", err)
	}
}

type failingAudit struct{}

func (failingAudit) Write(_ context.Context, _ AuditEntry) error {
	return errors.New("clickhouse unreachable")
}
