package events

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestEnforcementSchemaVersion(t *testing.T) {
	if EnforcementSchemaVersion != "2.0" {
		t.Fatalf("EnforcementSchemaVersion = %q, want 2.0", EnforcementSchemaVersion)
	}
}

func TestEnforcementStateConstants(t *testing.T) {
	seen := make(map[string]bool)
	for _, s := range enforcementStates {
		if s == "" {
			t.Error("state constant must not be empty")
		}
		if seen[s] {
			t.Errorf("duplicate state: %q", s)
		}
		seen[s] = true
	}
	for _, want := range []string{
		StatePending, StateApproved, StateActive, StateReverted, StateRejected,
		StateExpired, StateApplyFailed, StateRevertFailed,
	} {
		if !seen[want] {
			t.Errorf("state %q missing from the wire vocabulary", want)
		}
	}
	// The two failures mean opposite things for the device and must never
	// share a spelling.
	if StateApplyFailed == StateRevertFailed {
		t.Error("apply_failed and revert_failed must be distinct")
	}
	// The 1.x single failure state could not say whether the device was
	// still enforced; it must not come back.
	if seen["failed"] {
		t.Error(`the 1.x state "failed" is still in the wire vocabulary`)
	}
}

func TestEnforcementStateClasses(t *testing.T) {
	for _, s := range enforcementStates {
		if IsTerminalState(s) && IsEnforcedState(s) {
			t.Errorf("%s is both terminal and enforced", s)
		}
	}
	for _, s := range []string{StateReverted, StateRejected, StateExpired, StateApplyFailed} {
		if !IsTerminalState(s) {
			t.Errorf("%s should be terminal", s)
		}
	}
	// revert_failed is STILL enforced: it must never count as finished, or
	// it would be evicted and never retried.
	for _, s := range []string{StatePending, StateApproved, StateActive, StateRevertFailed, "failed"} {
		if IsTerminalState(s) {
			t.Errorf("%s must not be terminal", s)
		}
	}
	for _, s := range []string{StateActive, StateRevertFailed} {
		if !IsEnforcedState(s) {
			t.Errorf("%s should count as enforced", s)
		}
	}
	for _, s := range []string{StatePending, StateApproved, StateApplyFailed, StateReverted, "failed", ""} {
		if IsEnforcedState(s) {
			t.Errorf("%s must not count as enforced", s)
		}
	}
}

// TestInFlightOperations: the outstanding-operation vocabulary is the two
// driver calls, and it is optional on the wire — a 2.0 action served before
// it existed must still decode.
func TestInFlightOperations(t *testing.T) {
	if len(operations) != 2 || operations[0] != OperationApply || operations[1] != OperationRevert {
		t.Errorf("operations = %v, want [apply revert]", operations)
	}
	var a EnforcementAction
	if err := json.Unmarshal([]byte(`{"schema_version":"2.0","id":"ACT-1","state":"active"}`), &a); err != nil ||
		a.InFlight != "" {
		t.Errorf("an action without in_flight: %+v %v", a, err)
	}
}

func TestEnforcementActionTypeConstants(t *testing.T) {
	seen := make(map[string]bool)
	for _, at := range actionTypes {
		if at == "" {
			t.Error("action type constant must not be empty")
		}
		if seen[at] {
			t.Errorf("duplicate action type: %q", at)
		}
		seen[at] = true
	}
	if len(actionTypes) != 3 {
		t.Errorf("expected 3 action types, got %d", len(actionTypes))
	}
}

func TestEnforcementActionJSONRoundtrip(t *testing.T) {
	now := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)
	activated := now.Add(time.Second)
	expires := activated.Add(time.Hour)
	reverted := now.Add(30 * time.Minute)

	original := EnforcementAction{
		SchemaVersion:    EnforcementSchemaVersion,
		ID:               "ACT-42",
		Timestamp:        now,
		DetectionID:      "DET-abc-7",
		DetectionSummary: "DNS query for a domain listed by ThreatFox",
		ClientName:       "kids-tablet",
		ActionType:       ActionDNSSinkhole,
		State:            StateRevertFailed,
		TargetMAC:        "aa:bb:cc:dd:ee:ff",
		TargetIP:         "192.168.1.100",
		BlockedDomain:    "evil.com",
		PolicyRule:       "auto: confidence=95 severity=critical",
		AutoApproved:     true,
		TTLSeconds:       3600,
		ActivatedAt:      &activated,
		ExpiresAt:        &expires,
		RevertedAt:       &reverted,
		ApprovedBy:       "auto-policy",
		RejectedBy:       "",
		RevertedBy:       "ttl",
		Reason:           "confidence >= 90",
		FailureReason:    "adguard 502",
		InFlight:         OperationRevert,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded EnforcementAction
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round trip changed the action:\n got %+v\nwant %+v", decoded, original)
	}

	var raw map[string]any
	_ = json.Unmarshal(data, &raw)
	for _, key := range []string{"detection_summary", "client_name", "activated_at", "reverted_by", "in_flight"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("v2 key %q missing from the wire", key)
		}
	}
}

func TestEnforcementActionOmitemptyFields(t *testing.T) {
	action := EnforcementAction{
		SchemaVersion: EnforcementSchemaVersion,
		ID:            "ACT-1",
		ActionType:    ActionDNSSinkhole,
		State:         StatePending,
		TargetMAC:     "aa:bb:cc:dd:ee:ff",
	}

	data, _ := json.Marshal(action)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)

	omit := []string{
		"target_ip", "blocked_domain", "ttl_seconds", "expires_at", "reverted_at",
		"approved_by", "reason", "detection_summary", "client_name", "activated_at",
		"rejected_by", "reverted_by", "failure_reason", "in_flight",
	}
	for _, key := range omit {
		if _, ok := raw[key]; ok {
			t.Errorf("omitempty field %q present with zero value", key)
		}
	}
}

func TestEnforcementActionIgnoresUnknownFields(t *testing.T) {
	jsonWithExtra := `{
		"schema_version": "2.0",
		"id": "ACT-1",
		"timestamp": "2026-05-20T10:00:00Z",
		"detection_id": "DET-a-1",
		"action_type": "dns_sinkhole",
		"state": "pending",
		"target_mac": "aa:bb:cc:dd:ee:ff",
		"policy_rule": "auto",
		"auto_approved": false,
		"future_field": 42
	}`
	var action EnforcementAction
	if err := json.Unmarshal([]byte(jsonWithExtra), &action); err != nil {
		t.Fatalf("unmarshal with unknown field should succeed: %v", err)
	}
	if action.ID != "ACT-1" || action.State != StatePending {
		t.Errorf("decoded %+v", action)
	}
}
