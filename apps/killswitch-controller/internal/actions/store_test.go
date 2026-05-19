package actions

import (
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

func newTestStore() *Store {
	return NewStore(NopAuditWriter{})
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
