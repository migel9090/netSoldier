package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// --- Allowlist: devices on the allowlist must NEVER be blocked ---

func TestSecAllowlistBlocksAllSeverities(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.AutoBlock = true
	pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")
	pol.AutoMinConfidence = 0
	pol.AutoMinSeverity = events.SeverityLow

	for _, sev := range []string{
		events.SeverityLow,
		events.SeverityMedium,
		events.SeverityHigh,
		events.SeverityCritical,
	} {
		t.Run(sev, func(t *testing.T) {
			d := pol.Evaluate(events.DetectionEvent{
				Confidence: 100,
				Severity:   sev,
				ClientMAC:  "aa:bb:cc:dd:ee:ff",
				ClientIP:   "192.168.1.42",
			})
			if d.Action != "ignore" {
				t.Errorf("severity %s: got %q, want ignore", sev, d.Action)
			}
		})
	}
}

func TestSecAllowlistProtectsViaIPAlone(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.AutoBlock = true
	pol.Allowlist.AddIP("192.168.1.1")

	d := pol.Evaluate(events.DetectionEvent{
		Confidence: 100,
		Severity:   events.SeverityCritical,
		ClientMAC:  "ff:ff:ff:ff:ff:ff",
		ClientIP:   "192.168.1.1",
	})
	if d.Action != "ignore" {
		t.Errorf("IP-only allowlisted: got %q, want ignore", d.Action)
	}
}

func TestSecAllowlistProtectsViaMACAlone(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.AutoBlock = true
	pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	d := pol.Evaluate(events.DetectionEvent{
		Confidence: 100,
		Severity:   events.SeverityCritical,
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		ClientIP:   "10.99.99.99",
	})
	if d.Action != "ignore" {
		t.Errorf("MAC-only allowlisted: got %q, want ignore", d.Action)
	}
}

func TestSecAllowlistNoDriverApplied(t *testing.T) {
	drv := &recordingDriver{}
	h := newHarness(t, harnessOpts{driver: drv})
	h.pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	ev := withDomainTarget(testEvent(100, events.SeverityCritical), "evil.com")
	ev.ClientMAC, ev.ClientIP = "aa:bb:cc:dd:ee:ff", "192.168.1.42"
	got := h.evaluate(ev)
	if got.Decision.Action != "ignore" || got.Action != nil {
		t.Errorf("decision: %+v", got)
	}
	if drv.applied.Load() != 0 || h.actionCount() != 0 {
		t.Errorf("allowlisted: %d applies, %d actions", drv.applied.Load(), h.actionCount())
	}
}

func TestSecAllowlistConcurrentEvaluations(t *testing.T) {
	drv := &recordingDriver{}
	h := newHarness(t, harnessOpts{driver: drv})
	h.pol.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			ev := testEvent(100, events.SeverityCritical)
			ev.ClientMAC, ev.ClientIP = "aa:bb:cc:dd:ee:ff", "192.168.1.42"
			h.evaluate(ev)
		}()
	}
	wg.Wait()
	if drv.applied.Load() != 0 || h.actionCount() != 0 {
		t.Errorf("concurrent allowlisted evaluations: %d applies, %d actions", drv.applied.Load(), h.actionCount())
	}
}

// --- Authorization: every mutation requires the right bearer token ---

func TestSecAuthRequiredAllPOSTEndpoints(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	a := h.createPending("02:00:00:00:00:10", "192.168.1.10", "evil.com")

	ev, _ := json.Marshal(testEvent(99, events.SeverityCritical))
	for _, path := range []string{"/evaluate", "/actions/" + a.ID + "/approve", "/actions/" + a.ID + "/reject",
		"/actions/" + a.ID + "/revert", "/agent/v1/poll"} {
		t.Run(path, func(t *testing.T) {
			if status, _ := h.request(http.MethodPost, path, "", ev, map[string]string{actorHeader: testActor}); status != http.StatusUnauthorized {
				t.Errorf("POST %s without auth: got %d, want 401", path, status)
			}
		})
	}
	if got := h.action(a.ID); got.State != events.StatePending {
		t.Fatalf("an unauthenticated request changed the action: %s", got.State)
	}
}

func TestSecAuthRejectsInvalidSchemes(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	body, _ := json.Marshal(testEvent(99, events.SeverityCritical))
	for _, value := range []string{"ingest-token", "Basic ingest-token", "Bearer wrong-key", "Bearer ",
		"Bearer", "bearer ingest-token"} {
		t.Run(value, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/evaluate", jsonReader(body))
			req.Header.Set("Authorization", value)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("auth %q: got %d, want 401", value, resp.StatusCode)
			}
		})
	}
}

// TestSecAuthReadsNeedOperatorToken: /allowlist and /actions disclose which
// devices cannot be blocked and what is enforced, and were open to anything
// that could reach the service. Only the probes stay open.
func TestSecAuthReadsNeedOperatorToken(t *testing.T) {
	h := newHarness(t, harnessOpts{})
	for _, path := range []string{"/healthz", "/metrics"} {
		if status, _ := h.request(http.MethodGet, path, "", nil, nil); status != 200 {
			t.Errorf("GET %s without auth: got %d, want 200", path, status)
		}
	}
	for _, path := range []string{"/policy", "/allowlist", "/actions/pending", "/actions/active",
		"/actions/failed", "/actions/history", "/actions/ACT-x", "/audit"} {
		t.Run(path, func(t *testing.T) {
			for _, token := range []string{"", testIngestToken, testAgentToken} {
				if status, _ := h.request(http.MethodGet, path, token, nil, nil); status != http.StatusUnauthorized {
					t.Errorf("GET %s with %q: got %d, want 401", path, token, status)
				}
			}
			if status, _ := h.request(http.MethodGet, path, testOperatorToken, nil, nil); status == http.StatusUnauthorized {
				t.Errorf("GET %s with the operator token was refused", path)
			}
		})
	}
}
