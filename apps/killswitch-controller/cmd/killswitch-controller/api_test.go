package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

type nopDriver struct{}

func (nopDriver) Apply(_ context.Context, _ *events.EnforcementAction) error { return nil }
func (nopDriver) Revert(_ context.Context, _ *events.EnforcementAction) error { return nil }
func (nopDriver) Name() string                                                { return "nop" }

var _ drivers.Driver = nopDriver{}

type testEnv struct {
	srv    *httptest.Server
	store  *actions.Store
	policy *policy.Policy
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	pol := policy.DefaultPolicy()
	store := actions.NewStore(actions.NopAuditWriter{})
	resolve := func(string) drivers.Driver { return nopDriver{} }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /policy", handleGetPolicy(pol))
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve))
	mux.HandleFunc("GET /allowlist", handleGetAllowlist(pol))
	mux.HandleFunc("GET /actions/pending", handleListByState(store, events.StatePending))
	mux.HandleFunc("GET /actions/active", handleListByState(store, events.StateActive))
	mux.HandleFunc("GET /actions/{id}", handleGetAction(store))
	mux.HandleFunc("POST /actions/{id}/approve", handleApprove(store, resolve))
	mux.HandleFunc("POST /actions/{id}/reject", handleReject(store))
	mux.HandleFunc("POST /actions/{id}/revert", handleRevert(store, resolve))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &testEnv{srv: srv, store: store, policy: pol}
}

func (e *testEnv) post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	data, _ := json.Marshal(body)
	resp, err := http.Post(e.srv.URL+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (e *testEnv) get(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func decodeJSON[T any](t *testing.T, resp *http.Response) T {
	t.Helper()
	defer resp.Body.Close()
	var v T
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return v
}

func TestHealthz(t *testing.T) {
	env := newTestEnv(t)
	resp := env.get(t, "/healthz")
	if resp.StatusCode != 200 {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
	result := decodeJSON[map[string]string](t, resp)
	if result["status"] != "ok" {
		t.Errorf("status: got %q, want ok", result["status"])
	}
}

func TestGetPolicy(t *testing.T) {
	env := newTestEnv(t)
	resp := env.get(t, "/policy")
	if resp.StatusCode != 200 {
		t.Fatalf("policy: %d", resp.StatusCode)
	}
	result := decodeJSON[map[string]any](t, resp)
	if int(result["auto_min_confidence"].(float64)) != 90 {
		t.Errorf("auto_min_confidence: got %v, want 90", result["auto_min_confidence"])
	}
	if result["auto_min_severity"] != events.SeverityCritical {
		t.Errorf("auto_min_severity: got %v, want critical", result["auto_min_severity"])
	}
	if result["default_action"] != events.ActionDNSSinkhole {
		t.Errorf("default_action: got %v, want dns_sinkhole", result["default_action"])
	}
}

func TestGetAllowlist(t *testing.T) {
	env := newTestEnv(t)
	env.policy.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")
	env.policy.Allowlist.AddIP("10.0.0.1")

	resp := env.get(t, "/allowlist")
	result := decodeJSON[map[string]any](t, resp)
	macs := result["macs"].([]any)
	ips := result["ips"].([]any)
	if len(macs) != 1 {
		t.Errorf("expected 1 MAC, got %d", len(macs))
	}
	if len(ips) != 1 {
		t.Errorf("expected 1 IP, got %d", len(ips))
	}
}

func TestEvaluateAutoBlock(t *testing.T) {
	env := newTestEnv(t)

	resp := env.post(t, "/evaluate", events.DetectionEvent{
		ID:         "DET-1",
		Severity:   events.SeverityCritical,
		Confidence: 95,
		ClientIP:   "192.168.1.100",
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		Domain:     "evil.com",
		MatchedIoC: "evil.com",
		IoCType:    "domain",
		Source:     "test",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("evaluate: %d", resp.StatusCode)
	}

	result := decodeJSON[map[string]any](t, resp)
	decision := result["decision"].(map[string]any)
	action := result["action"].(map[string]any)

	if decision["Action"] != "auto_block" {
		t.Errorf("decision.Action: got %v, want auto_block", decision["Action"])
	}
	if action["state"] != events.StateActive {
		t.Errorf("action.state: got %v, want active (nop driver succeeds)", action["state"])
	}
	if action["auto_approved"] != true {
		t.Errorf("action.auto_approved: got %v, want true", action["auto_approved"])
	}
}

func TestEvaluatePending(t *testing.T) {
	env := newTestEnv(t)

	resp := env.post(t, "/evaluate", events.DetectionEvent{
		ID:         "DET-2",
		Severity:   events.SeverityMedium,
		Confidence: 60,
		ClientIP:   "192.168.1.100",
		Domain:     "suspicious.com",
		IoCType:    "domain",
	})

	result := decodeJSON[map[string]any](t, resp)
	decision := result["decision"].(map[string]any)
	action := result["action"].(map[string]any)

	if decision["Action"] != "pending" {
		t.Errorf("decision.Action: got %v, want pending", decision["Action"])
	}
	if action["state"] != events.StatePending {
		t.Errorf("action.state: got %v, want pending", action["state"])
	}
}

func TestEvaluateIgnoreBelowThreshold(t *testing.T) {
	env := newTestEnv(t)

	resp := env.post(t, "/evaluate", events.DetectionEvent{
		ID:         "DET-3",
		Severity:   events.SeverityLow,
		Confidence: 30,
		ClientIP:   "192.168.1.100",
	})

	result := decodeJSON[map[string]any](t, resp)
	decision := result["decision"].(map[string]any)

	if decision["Action"] != "ignore" {
		t.Errorf("decision.Action: got %v, want ignore", decision["Action"])
	}
	if result["action"] != nil {
		t.Errorf("ignored events should have nil action, got %v", result["action"])
	}
}

func TestEvaluateIgnoreAllowlisted(t *testing.T) {
	env := newTestEnv(t)
	env.policy.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	resp := env.post(t, "/evaluate", events.DetectionEvent{
		ID:         "DET-4",
		Severity:   events.SeverityCritical,
		Confidence: 99,
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		ClientIP:   "192.168.1.100",
	})

	result := decodeJSON[map[string]any](t, resp)
	decision := result["decision"].(map[string]any)

	if decision["Action"] != "ignore" {
		t.Errorf("allowlisted device should be ignored, got %v", decision["Action"])
	}
}

func TestActionLifecycle(t *testing.T) {
	env := newTestEnv(t)

	// Create a pending action via evaluate
	env.post(t, "/evaluate", events.DetectionEvent{
		ID:         "DET-LC",
		Severity:   events.SeverityMedium,
		Confidence: 60,
		ClientIP:   "192.168.1.50",
		ClientMAC:  "11:22:33:44:55:66",
		Domain:     "maybe-bad.com",
		IoCType:    "domain",
	})

	// List pending — should have 1
	resp := env.get(t, "/actions/pending")
	pending := decodeJSON[[]map[string]any](t, resp)
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	actionID := pending[0]["id"].(string)

	// Get by ID
	resp = env.get(t, "/actions/"+actionID)
	if resp.StatusCode != 200 {
		t.Fatalf("get action: %d", resp.StatusCode)
	}
	action := decodeJSON[map[string]any](t, resp)
	if action["state"] != events.StatePending {
		t.Errorf("state: got %v, want pending", action["state"])
	}

	// Approve
	resp = env.post(t, "/actions/"+actionID+"/approve", map[string]string{"approved_by": "admin"})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("approve: %d %s", resp.StatusCode, body)
	}
	action = decodeJSON[map[string]any](t, resp)
	if action["state"] != events.StateActive {
		t.Errorf("after approve+activate: got %v, want active", action["state"])
	}

	// List active — should have 1
	resp = env.get(t, "/actions/active")
	active := decodeJSON[[]map[string]any](t, resp)
	if len(active) != 1 {
		t.Fatalf("expected 1 active, got %d", len(active))
	}

	// Revert
	resp = env.post(t, "/actions/"+actionID+"/revert", map[string]string{"reason": "false positive"})
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("revert: %d %s", resp.StatusCode, body)
	}
	action = decodeJSON[map[string]any](t, resp)
	if action["state"] != events.StateReverted {
		t.Errorf("after revert: got %v, want reverted", action["state"])
	}

	// Active list now empty
	resp = env.get(t, "/actions/active")
	active = decodeJSON[[]map[string]any](t, resp)
	if len(active) != 0 {
		t.Errorf("expected 0 active after revert, got %d", len(active))
	}
}

func TestActionReject(t *testing.T) {
	env := newTestEnv(t)

	env.post(t, "/evaluate", events.DetectionEvent{
		ID:         "DET-REJ",
		Severity:   events.SeverityMedium,
		Confidence: 60,
		ClientIP:   "192.168.1.50",
		Domain:     "maybe-bad.com",
		IoCType:    "domain",
	})

	resp := env.get(t, "/actions/pending")
	pending := decodeJSON[[]map[string]any](t, resp)
	actionID := pending[0]["id"].(string)

	resp = env.post(t, "/actions/"+actionID+"/reject", map[string]string{"reason": "false positive"})
	if resp.StatusCode != 200 {
		t.Fatalf("reject: %d", resp.StatusCode)
	}
	action := decodeJSON[map[string]any](t, resp)
	if action["state"] != events.StateRejected {
		t.Errorf("state: got %v, want rejected", action["state"])
	}
}

func TestGetActionNotFound(t *testing.T) {
	env := newTestEnv(t)
	resp := env.get(t, "/actions/ACT-NONEXISTENT")
	if resp.StatusCode != 404 {
		t.Errorf("expected 404, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestListPendingEmpty(t *testing.T) {
	env := newTestEnv(t)
	resp := env.get(t, "/actions/pending")
	result := decodeJSON[[]any](t, resp)
	if result != nil && len(result) != 0 {
		t.Errorf("expected empty list, got %d items", len(result))
	}
}

func TestAuthMiddleware(t *testing.T) {
	pol := policy.DefaultPolicy()
	store := actions.NewStore(actions.NopAuditWriter{})
	resolve := func(string) drivers.Driver { return nopDriver{} }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve))

	handler := authMiddleware("test-secret", mux)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	// GET requests pass without auth
	resp, _ := http.Get(srv.URL + "/healthz")
	if resp.StatusCode != 200 {
		t.Errorf("GET without auth should succeed, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// POST without auth → 401
	body, _ := json.Marshal(events.DetectionEvent{})
	resp, _ = http.Post(srv.URL+"/evaluate", "application/json", bytes.NewReader(body))
	if resp.StatusCode != 401 {
		t.Errorf("POST without auth: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// POST with wrong key → 401
	req, _ := http.NewRequest("POST", srv.URL+"/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer wrong-key")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Errorf("POST with wrong key: expected 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// POST with correct key → 200
	req, _ = http.NewRequest("POST", srv.URL+"/evaluate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Errorf("POST with correct key: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestEvaluateInvalidBody(t *testing.T) {
	env := newTestEnv(t)
	resp, err := http.Post(env.srv.URL+"/evaluate", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("invalid body: expected 400, got %d", resp.StatusCode)
	}
}
