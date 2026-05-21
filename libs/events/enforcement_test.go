package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEnforcementSchemaVersion(t *testing.T) {
	if EnforcementSchemaVersion == "" {
		t.Fatal("EnforcementSchemaVersion must not be empty")
	}
}

func TestEnforcementStateConstants(t *testing.T) {
	states := []string{StatePending, StateApproved, StateActive, StateReverted, StateRejected}
	seen := make(map[string]bool)
	for _, s := range states {
		if s == "" {
			t.Error("state constant must not be empty")
		}
		if seen[s] {
			t.Errorf("duplicate state: %q", s)
		}
		seen[s] = true
	}
	if len(states) != 5 {
		t.Errorf("expected 5 enforcement states, got %d", len(states))
	}
}

func TestEnforcementActionTypeConstants(t *testing.T) {
	types := []string{ActionDNSSinkhole, ActionARPIsolate, ActionSwitchACL}
	seen := make(map[string]bool)
	for _, at := range types {
		if at == "" {
			t.Error("action type constant must not be empty")
		}
		if seen[at] {
			t.Errorf("duplicate action type: %q", at)
		}
		seen[at] = true
	}
	if len(types) != 3 {
		t.Errorf("expected 3 action types, got %d", len(types))
	}
}

func TestEnforcementActionJSONRoundtrip(t *testing.T) {
	now := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	expires := now.Add(time.Hour)
	reverted := now.Add(30 * time.Minute)

	original := EnforcementAction{
		SchemaVersion: EnforcementSchemaVersion,
		ID:            "ACT-42",
		Timestamp:     now,
		DetectionID:   "DET-7",
		ActionType:    ActionDNSSinkhole,
		State:         StateActive,
		TargetMAC:     "aa:bb:cc:dd:ee:ff",
		TargetIP:      "192.168.1.100",
		BlockedDomain: "evil.com",
		PolicyRule:    "auto: confidence=95 severity=critical",
		AutoApproved:  true,
		TTLSeconds:    3600,
		ExpiresAt:     &expires,
		RevertedAt:    &reverted,
		ApprovedBy:    "auto-policy",
		Reason:        "confidence >= 90",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded EnforcementAction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("id: got %q, want %q", decoded.ID, original.ID)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("timestamp mismatch")
	}
	if decoded.DetectionID != original.DetectionID {
		t.Errorf("detection_id: got %q, want %q", decoded.DetectionID, original.DetectionID)
	}
	if decoded.ActionType != original.ActionType {
		t.Errorf("action_type: got %q, want %q", decoded.ActionType, original.ActionType)
	}
	if decoded.State != original.State {
		t.Errorf("state: got %q, want %q", decoded.State, original.State)
	}
	if decoded.TargetMAC != original.TargetMAC {
		t.Errorf("target_mac: got %q, want %q", decoded.TargetMAC, original.TargetMAC)
	}
	if decoded.BlockedDomain != original.BlockedDomain {
		t.Errorf("blocked_domain: got %q, want %q", decoded.BlockedDomain, original.BlockedDomain)
	}
	if decoded.AutoApproved != original.AutoApproved {
		t.Errorf("auto_approved: got %v, want %v", decoded.AutoApproved, original.AutoApproved)
	}
	if decoded.TTLSeconds != original.TTLSeconds {
		t.Errorf("ttl_seconds: got %d, want %d", decoded.TTLSeconds, original.TTLSeconds)
	}
	if decoded.ExpiresAt == nil || !decoded.ExpiresAt.Equal(expires) {
		t.Errorf("expires_at mismatch")
	}
	if decoded.RevertedAt == nil || !decoded.RevertedAt.Equal(reverted) {
		t.Errorf("reverted_at mismatch")
	}
	if decoded.ApprovedBy != original.ApprovedBy {
		t.Errorf("approved_by: got %q, want %q", decoded.ApprovedBy, original.ApprovedBy)
	}
}

func TestEnforcementActionOmitemptyFields(t *testing.T) {
	action := EnforcementAction{
		SchemaVersion: "1.0",
		ID:            "ACT-1",
		ActionType:    ActionDNSSinkhole,
		State:         StatePending,
		TargetMAC:     "aa:bb:cc:dd:ee:ff",
	}

	data, _ := json.Marshal(action)
	var raw map[string]any
	json.Unmarshal(data, &raw)

	omit := []string{"target_ip", "blocked_domain", "ttl_seconds", "expires_at", "reverted_at", "approved_by", "reason"}
	for _, key := range omit {
		if _, ok := raw[key]; ok {
			t.Errorf("omitempty field %q present with zero value", key)
		}
	}
}

func TestEnforcementActionBackwardCompat(t *testing.T) {
	jsonWithExtra := `{
		"schema_version": "1.0",
		"id": "ACT-1",
		"timestamp": "2026-05-20T10:00:00Z",
		"detection_id": "DET-1",
		"action_type": "dns_sinkhole",
		"state": "pending",
		"target_mac": "aa:bb:cc:dd:ee:ff",
		"policy_rule": "auto",
		"auto_approved": false,
		"future_field_v2": 42
	}`

	var action EnforcementAction
	if err := json.Unmarshal([]byte(jsonWithExtra), &action); err != nil {
		t.Fatalf("unmarshal with unknown field should succeed: %v", err)
	}
	if action.ID != "ACT-1" {
		t.Errorf("id: got %q, want ACT-1", action.ID)
	}
	if action.State != StatePending {
		t.Errorf("state: got %q, want pending", action.State)
	}
}
