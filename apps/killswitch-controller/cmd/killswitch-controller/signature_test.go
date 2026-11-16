package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// newSignedEnv builds a server with a bearer key and a webhook secret — the
// production posture. Before step 124 no test ever enabled auth, which is
// exactly why nobody noticed the detection-engine was sending the wrong
// header and would have been rejected with 401 the moment a key was set.
func newSignedEnv(t *testing.T, autoBlockAllowed bool) *harness {
	t.Helper()
	pol := policy.DefaultPolicy()
	pol.AutoBlock = true
	if autoBlockAllowed {
		if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
			t.Fatalf("allowlist: %v", err)
		}
	}
	return newHarness(t, harnessOpts{pol: pol})
}

func (h *harness) postRaw(body []byte, key, sig string) int {
	h.t.Helper()
	hdr := map[string]string{}
	if sig != "" {
		hdr[events.SignatureHeader] = sig
	}
	status, _ := h.request(http.MethodPost, "/evaluate", key, body, hdr)
	return status
}

// TestSignedEvaluateAccepted is the contract test whose absence let the
// detection → killswitch path break: a correctly signed, correctly
// authenticated detection event must be accepted.
func TestSignedEvaluateAccepted(t *testing.T) {
	env := newSignedEnv(t, true)
	if got := env.evaluate(criticalIoCEvent()); got.status != http.StatusOK {
		t.Fatalf("signed request should be accepted, got %d", got.status)
	}
}

func TestEvaluateRejectsMissingSignature(t *testing.T) {
	env := newSignedEnv(t, true)
	body, _ := json.Marshal(criticalIoCEvent())
	if status := env.postRaw(body, testIngestToken, ""); status != http.StatusUnauthorized {
		t.Fatalf("unsigned event should be rejected, got %d", status)
	}
}

// TestEvaluateRejectsTamperedPayload covers the attack the old plaintext
// X-Webhook-Secret header allowed: raising confidence/severity, or pointing
// the action at the router, on a payload in flight.
func TestEvaluateRejectsTamperedPayload(t *testing.T) {
	env := newSignedEnv(t, true)
	low := testEvent(10, events.SeverityLow)
	original, _ := json.Marshal(low)
	sig := events.SignPayload(testWebhookSecret, original)

	high := low
	high.Severity, high.Confidence = events.SeverityCritical, 99
	escalated, _ := json.Marshal(high)
	if status := env.postRaw(escalated, testIngestToken, sig); status != http.StatusUnauthorized {
		t.Fatalf("escalated payload should be rejected, got %d", status)
	}
}

func TestEvaluateRejectsWrongBearer(t *testing.T) {
	env := newSignedEnv(t, true)
	body, _ := json.Marshal(criticalIoCEvent())
	if status := env.postRaw(body, "wrong-key", events.SignPayload(testWebhookSecret, body)); status != http.StatusUnauthorized {
		t.Fatalf("wrong bearer token should be rejected, got %d", status)
	}
}

// TestAutoBlockDowngradedWithoutAllowlist covers the empty-allowlist guard:
// with nothing protected, a known-bad critical detection must still be queued
// for a human rather than enforced, because the target could be the router.
func TestAutoBlockDowngradedWithoutAllowlist(t *testing.T) {
	env := newSignedEnv(t, false)
	got := env.evaluate(criticalIoCEvent())
	if got.status != http.StatusOK {
		t.Fatalf("evaluate: %d", got.status)
	}
	if got.Decision.Action != "pending" || got.Decision.Withheld != policy.WithheldEmptyAllowlist {
		t.Fatalf("auto-block must be withheld as pending with an empty allowlist, got %+v", got.Decision)
	}
	if got.Action == nil || got.Action.State != events.StatePending || got.Action.AutoApproved {
		t.Errorf("action: %+v", got.Action)
	}
}

func TestBodySizeLimit(t *testing.T) {
	env := newSignedEnv(t, true)
	huge := bytes.Repeat([]byte("a"), maxBodyBytes+1024)
	if status := env.postRaw(huge, testIngestToken, events.SignPayload(testWebhookSecret, huge)); status != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body should be rejected with 413, got %d", status)
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
