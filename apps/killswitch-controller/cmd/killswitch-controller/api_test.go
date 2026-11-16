package main

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

func TestHealthz(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	status, raw := h.request(http.MethodGet, "/healthz", "", nil, nil)
	if status != 200 || !bytes.Contains(raw, []byte(`"ok"`)) {
		t.Fatalf("healthz: %d %s", status, raw)
	}
}

func TestGetPolicy(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	var result map[string]any
	if status := h.get("/policy", &result); status != 200 {
		t.Fatalf("policy: %d", status)
	}
	if int(result["auto_min_confidence"].(float64)) != 90 {
		t.Errorf("auto_min_confidence: got %v, want 90", result["auto_min_confidence"])
	}
	if result["auto_min_severity"] != events.SeverityCritical {
		t.Errorf("auto_min_severity: got %v, want critical", result["auto_min_severity"])
	}
	if result["default_action"] != events.ActionDNSSinkhole {
		t.Errorf("default_action: got %v, want dns_sinkhole", result["default_action"])
	}
	types, _ := result["available_action_types"].([]any)
	if len(types) != 1 || types[0] != events.ActionDNSSinkhole {
		t.Errorf("available_action_types: %v", result["available_action_types"])
	}
}

func TestGetAllowlist(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	h.pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	var result map[string][]string
	h.get("/allowlist", &result)
	if len(result["macs"]) != 1 || len(result["ips"]) != 1 {
		t.Errorf("allowlist: %v", result)
	}
}

func TestEvaluateAutoBlock(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ev := criticalIoCEvent()
	got := h.evaluate(ev)
	if got.status != 200 || got.Decision.Action != "auto_block" {
		t.Fatalf("evaluate: %+v", got)
	}
	a := got.Action
	if a == nil || a.State != events.StateActive || !a.AutoApproved || a.ApprovedBy != "auto-policy" {
		t.Fatalf("action: %+v", a)
	}
	if a.BlockedDomain != "evil.com" || a.DetectionSummary != ev.Summary || a.ActivatedAt == nil || a.ExpiresAt == nil {
		t.Errorf("action should carry the target domain, the summary and its TTL: %+v", a)
	}
}

func TestEvaluatePending(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	got := h.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium), "suspicious.com"))
	if got.Decision.Action != "pending" || got.Action == nil || got.Action.State != events.StatePending {
		t.Fatalf("got %+v", got)
	}
	if got.Action.ExpiresAt != nil {
		t.Errorf("a pending action has no expires_at until it is active: %v", got.Action.ExpiresAt)
	}
}

func TestEvaluateIgnoreBelowThreshold(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	got := h.evaluate(testEvent(30, events.SeverityLow))
	if got.Decision.Action != "ignore" || got.Action != nil {
		t.Errorf("got %+v", got)
	}
}

func TestEvaluateIgnoreAllowlisted(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	h.pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")
	ev := testEvent(99, events.SeverityCritical)
	ev.ClientMAC = "aa:bb:cc:dd:ee:ff"
	if got := h.evaluate(ev); got.Decision.Action != "ignore" {
		t.Errorf("allowlisted device should be ignored, got %v", got.Decision.Action)
	}
}

func TestActionLifecycle(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	ev := withDomainTarget(testEvent(60, events.SeverityMedium), "maybe-bad.com")
	ev.ClientIP, ev.ClientMAC = "192.168.1.50", "02:22:33:44:55:66"
	h.evaluate(ev)

	pending := h.list("pending")
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	id := pending[0].ID

	var got events.EnforcementAction
	if status := h.get("/actions/"+id, &got); status != 200 || got.State != events.StatePending {
		t.Fatalf("get action: %d %s", status, got.State)
	}

	status, approved := h.approve(id, nil)
	if status != 200 || approved.State != events.StateActive || approved.ApprovedBy != testActor {
		t.Fatalf("approve: %d %+v", status, approved)
	}
	if active := h.list("active"); len(active) != 1 || active[0].ID != id {
		t.Fatalf("active: %+v", active)
	}

	status, reverted := h.revert(id, "bob")
	if status != 200 || reverted.State != events.StateReverted || reverted.RevertedBy != "bob" {
		t.Fatalf("revert: %d %+v", status, reverted)
	}
	if active := h.list("active"); len(active) != 0 {
		t.Errorf("expected 0 active after revert, got %d", len(active))
	}
	if history := h.list("history"); len(history) != 1 || history[0].ID != id {
		t.Errorf("history: %+v", history)
	}
}

func TestActionReject(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	a := h.createPending("02:00:00:00:00:01", "192.168.1.10", "maybe-bad.com")

	status, got := h.operate("/actions/"+a.ID+"/reject", "carol", map[string]string{"reason": "false positive"})
	if status != 200 || got.State != events.StateRejected || got.RejectedBy != "carol" || got.Reason != "false positive" {
		t.Fatalf("reject: %d %+v", status, got)
	}
	// Rejecting again, or approving a rejected action: 409 with the action.
	status, again := h.operate("/actions/"+a.ID+"/reject", "carol", nil)
	if status != http.StatusConflict || again.State != events.StateRejected || again.Error == "" {
		t.Fatalf("second reject: %d %+v", status, again)
	}
	if status, _ := h.approve(a.ID, nil); status != http.StatusConflict {
		t.Fatalf("approve after reject: %d", status)
	}
}

func TestGetActionNotFound(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	if status := h.get("/actions/ACT-NONEXISTENT", nil); status != 404 {
		t.Errorf("expected 404, got %d", status)
	}
	for _, verb := range []string{"approve", "reject", "revert"} {
		if status, _ := h.operate("/actions/ACT-NONEXISTENT/"+verb, testActor, nil); status != 404 {
			t.Errorf("%s of an unknown action: %d", verb, status)
		}
	}
}

// TestListsAreArraysNeverNull: Go encodes an empty slice as null.
func TestListsAreArraysNeverNull(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, path := range []string{"/actions/pending", "/actions/active", "/actions/failed", "/actions/history", "/audit"} {
		status, raw := h.request(http.MethodGet, path, testOperatorToken, nil, nil)
		if status != 200 || string(bytes.TrimSpace(raw)) != "[]" {
			t.Errorf("GET %s: %d %s, want []", path, status, raw)
		}
	}
}

func TestListQueryValidation(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, path := range []string{"/actions/history?limit=0", "/actions/history?limit=x", "/audit?limit=-1",
		"/audit?before=abc", "/audit?before=0"} {
		if status := h.get(path, nil); status != http.StatusBadRequest {
			t.Errorf("GET %s: %d, want 400", path, status)
		}
	}
	if status := h.get("/actions/history?limit=100000", nil); status != 200 {
		t.Errorf("an oversized limit is capped, not refused: %d", status)
	}
}

func TestEvaluateInvalidBody(t *testing.T) {
	h := newHarness(t, harnessOpts{insecure: true})
	if got := h.evaluateRaw([]byte("not json"), ""); got.status != 400 {
		t.Errorf("invalid body: expected 400, got %d", got.status)
	}
}

func TestOperatorBodiesMustBeJSON(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	a := h.createPending("02:00:00:00:00:01", "192.168.1.10", "x.example")
	status, _ := h.request(http.MethodPost, "/actions/"+a.ID+"/approve", testOperatorToken, []byte("{"),
		map[string]string{actorHeader: testActor})
	if status != http.StatusBadRequest {
		t.Fatalf("malformed body: %d", status)
	}
	if got := h.action(a.ID); got.State != events.StatePending {
		t.Fatalf("a malformed approve changed the action: %s", got.State)
	}
}
