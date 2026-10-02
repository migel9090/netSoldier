package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// signedEnv builds a server with both a bearer key and a webhook secret —
// the production posture. Before step 124 no test ever enabled auth, which is
// exactly why nobody noticed the detection-engine was sending the wrong
// header and would have been rejected with 401 the moment a key was set.
type signedEnv struct {
	srv    *httptest.Server
	key    string
	secret string
}

func newSignedEnv(t *testing.T, autoBlockAllowed bool) *signedEnv {
	t.Helper()
	pol := policy.DefaultPolicy()
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	store := actions.NewStore(actions.NopAuditWriter{}, actions.StoreOptions{})
	resolve := func(string) (drivers.Driver, error) { return nopDriver{}, nil }

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /evaluate", handleEvaluate(pol, store, resolve, autoBlockAllowed))

	env := &signedEnv{key: "api-key", secret: "wh-secret"}
	env.srv = httptest.NewServer(authMiddleware(env.key, env.secret, mux))
	t.Cleanup(env.srv.Close)
	return env
}

func (e *signedEnv) postSigned(t *testing.T, ev events.DetectionEvent) *http.Response {
	t.Helper()
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return e.postRaw(t, body, e.key, events.SignPayload(e.secret, body))
}

func (e *signedEnv) postRaw(t *testing.T, body []byte, key, sig string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.srv.URL+"/evaluate", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if sig != "" {
		req.Header.Set(events.SignatureHeader, sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func criticalIoCEvent() events.DetectionEvent {
	return events.DetectionEvent{
		ID:          "DET-sig-1",
		Severity:    events.SeverityCritical,
		Confidence:  95,
		ClientIP:    "192.168.1.100",
		ClientMAC:   "aa:bb:cc:dd:ee:ff",
		Domain:      "evil.com",
		MatchedIoC:  "evil.com",
		IoCType:     "domain",
		Source:      "threatfox",
		SignalClass: events.SignalIoC,
	}
}

// TestSignedEvaluateAccepted is the contract test whose absence let the
// detection → killswitch path break: a correctly signed, correctly
// authenticated detection event must be accepted.
func TestSignedEvaluateAccepted(t *testing.T) {
	env := newSignedEnv(t, true)
	resp := env.postSigned(t, criticalIoCEvent())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed request should be accepted, got %d", resp.StatusCode)
	}
}

func TestEvaluateRejectsMissingSignature(t *testing.T) {
	env := newSignedEnv(t, true)
	body, _ := json.Marshal(criticalIoCEvent())
	resp := env.postRaw(t, body, env.key, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned event should be rejected, got %d", resp.StatusCode)
	}
}

// TestEvaluateRejectsTamperedPayload covers the attack the old plaintext
// X-Webhook-Secret header allowed: raising confidence/severity, or pointing
// the action at the router, on a payload in flight.
func TestEvaluateRejectsTamperedPayload(t *testing.T) {
	env := newSignedEnv(t, true)

	original, _ := json.Marshal(events.DetectionEvent{
		ID:          "DET-sig-2",
		Severity:    events.SeverityLow,
		Confidence:  10,
		ClientIP:    "192.168.1.100",
		SignalClass: events.SignalIoC,
	})
	sig := events.SignPayload(env.secret, original)

	escalated, _ := json.Marshal(events.DetectionEvent{
		ID:          "DET-sig-2",
		Severity:    events.SeverityCritical,
		Confidence:  99,
		ClientIP:    "192.168.1.100",
		SignalClass: events.SignalIoC,
	})
	if resp := env.postRaw(t, escalated, env.key, sig); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("escalated payload should be rejected, got %d", resp.StatusCode)
	}
}

func TestEvaluateRejectsWrongBearer(t *testing.T) {
	env := newSignedEnv(t, true)
	body, _ := json.Marshal(criticalIoCEvent())
	sig := events.SignPayload(env.secret, body)
	if resp := env.postRaw(t, body, "wrong-key", sig); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong bearer token should be rejected, got %d", resp.StatusCode)
	}
}

// TestAutoBlockDowngradedWithoutAllowlist covers the empty-allowlist guard:
// with nothing protected, a known-bad critical detection must still be queued
// for a human rather than enforced, because the target could be the router.
func TestAutoBlockDowngradedWithoutAllowlist(t *testing.T) {
	env := newSignedEnv(t, false)
	resp := env.postSigned(t, criticalIoCEvent())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("evaluate: %d", resp.StatusCode)
	}

	result := decodeJSON[map[string]any](t, resp)
	decision := result["decision"].(map[string]any)
	if decision["Action"] != "pending" {
		t.Fatalf("auto-block must be downgraded to pending with an empty allowlist, got %v",
			decision["Action"])
	}
	action := result["action"].(map[string]any)
	if action["state"] != events.StatePending {
		t.Errorf("action.state: got %v, want pending", action["state"])
	}
	if action["auto_approved"] != false {
		t.Errorf("action.auto_approved: got %v, want false", action["auto_approved"])
	}
}

func TestBodySizeLimit(t *testing.T) {
	env := newSignedEnv(t, true)
	huge := bytes.Repeat([]byte("a"), maxBodyBytes+1024)
	resp := env.postRaw(t, huge, env.key, events.SignPayload(env.secret, huge))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body should be rejected with 413, got %d", resp.StatusCode)
	}
}

func TestValidBearerConstantTime(t *testing.T) {
	if !validBearer("Bearer secret", "secret") {
		t.Error("matching token should validate")
	}
	if validBearer("Bearer secre", "secret") {
		t.Error("truncated token must not validate")
	}
	if validBearer("Basic secret", "secret") {
		t.Error("wrong scheme must not validate")
	}
	if validBearer("", "secret") {
		t.Error("empty header must not validate")
	}
	if validBearer("Bearer secretx", "secret") {
		t.Error("longer token must not validate")
	}
}
