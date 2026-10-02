//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// Shared credentials for the authenticated e2e posture.
const (
	e2eAPIKey        = "e2e-api-key"
	e2eWebhookSecret = "e2e-webhook-secret"
)

// TestDetectionToKillswitchContract is the test whose absence let the
// detection → enforcement path break in the shipped configuration.
//
// Two independent faults were live at once: the detection-engine sent the
// shared secret in X-Webhook-Secret while the killswitch required
// Authorization: Bearer, and the detection-engine's NetworkPolicy had no
// egress rule to the killswitch. Both were invisible because every e2e run
// started the killswitch with authentication disabled and used a webhook
// receiver that accepted anything.
//
// This test runs the real binaries with auth ON and asserts the whole chain:
// AdGuard query → IoC match → signed+authenticated webhook → policy
// decision → enforcement action.
func TestDetectionToKillswitchContract(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	root := repoRoot(t)
	detBin := goBuild(t, root, "apps/detection-engine")
	ksBin := goBuild(t, root, "apps/killswitch-controller")

	tlFile := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(tlFile, []byte("evil.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	entryTime := time.Now().Add(time.Minute)
	ag := startMockAdGuard(t, entryTime)

	// The killswitch IS the webhook receiver here: that is the real contract.
	ksAddr := freeAddr(t)
	stopKs := startProc(t, ksBin, map[string]string{
		"LISTEN_ADDR":        ksAddr,
		"ADGUARD_URL":        ag.url,
		"ADGUARD_USER":       "admin",
		"ADGUARD_PASSWORD":   "test",
		"KILLSWITCH_API_KEY": e2eAPIKey,
		"WEBHOOK_SECRET":     e2eWebhookSecret,
		"ALLOWLIST_IPS":      "192.168.1.1",
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	detAddr := freeAddr(t)
	stopDet := startProc(t, detBin, map[string]string{
		"LISTEN_ADDR":                 detAddr,
		"ADGUARD_URL":                 ag.url,
		"ADGUARD_USER":                "admin",
		"ADGUARD_PASSWORD":            "test",
		"THREATLIST_PATH":             tlFile,
		"POLL_INTERVAL":               "1s",
		"WEBHOOK_URL":                 "http://" + ksAddr + "/evaluate",
		"WEBHOOK_SECRET":              e2eWebhookSecret,
		"WEBHOOK_TOKEN":               e2eAPIKey,
		"DETECTION_API_KEY":           e2eAPIKey,
		"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1",
	})
	t.Cleanup(stopDet)
	waitHealthy(t, "http://"+detAddr+"/healthz")

	// The detection must reach the killswitch and produce an action. If the
	// credentials or the wire contract disagree, nothing arrives.
	deadline := time.Now().Add(30 * time.Second)
	var actions []events.EnforcementAction
	for time.Now().Before(deadline) {
		actions = listActions(t, ksAddr, "pending")
		if len(actions) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(actions) == 0 {
		t.Fatal("no enforcement action was created: the signed, authenticated webhook " +
			"from detection-engine never reached the killswitch")
	}

	a := actions[0]
	if a.BlockedDomain != "evil.example.com" {
		t.Errorf("blocked_domain = %q, want evil.example.com", a.BlockedDomain)
	}
	if a.DetectionID == "" {
		t.Error("the action should carry the detection ID that triggered it")
	}
}

// TestKillswitchRejectsUnauthenticated confirms the gate actually holds when
// enabled: an unsigned or unauthenticated evaluate must not create an action.
func TestKillswitchRejectsUnauthenticated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	root := repoRoot(t)
	ksBin := goBuild(t, root, "apps/killswitch-controller")

	entryTime := time.Now().Add(time.Minute)
	ag := startMockAdGuard(t, entryTime)

	ksAddr := freeAddr(t)
	stopKs := startProc(t, ksBin, map[string]string{
		"LISTEN_ADDR":        ksAddr,
		"ADGUARD_URL":        ag.url,
		"ADGUARD_USER":       "admin",
		"ADGUARD_PASSWORD":   "test",
		"KILLSWITCH_API_KEY": e2eAPIKey,
		"WEBHOOK_SECRET":     e2eWebhookSecret,
		"ALLOWLIST_IPS":      "192.168.1.1",
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	ev := events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            "DET-unauth",
		Timestamp:     time.Now().UTC(),
		Domain:        "attacker.example",
		MatchedIoC:    "attacker.example",
		IoCType:       "domain",
		ClientIP:      "192.168.1.200",
		ClientMAC:     "aa:bb:cc:dd:ee:99",
		Severity:      events.SeverityCritical,
		Confidence:    99,
		SignalClass:   events.SignalIoC,
	}
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		token string
		sig   string
	}{
		{"no credentials at all", "", ""},
		{"token but no signature", e2eAPIKey, ""},
		{"valid token, wrong signature", e2eAPIKey, events.SignPayload("wrong-secret", body)},
		{"valid signature, wrong token", "wrong-token", events.SignPayload(e2eWebhookSecret, body)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://"+ksAddr+"/evaluate", bytesReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if tc.sig != "" {
				req.Header.Set(events.SignatureHeader, tc.sig)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401 — an unauthenticated caller must not be "+
					"able to drive enforcement", resp.StatusCode)
			}
		})
	}

	if got := listActions(t, ksAddr, "pending"); len(got) != 0 {
		t.Fatalf("rejected requests must not create actions, got %d", len(got))
	}
}

// TestEmptyAllowlistDisablesAutoBlock covers the fail-safe: with nothing
// protected, even a known-bad critical detection is queued for a human
// instead of enforced, because the target could be the router.
func TestEmptyAllowlistDisablesAutoBlock(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	root := repoRoot(t)
	ksBin := goBuild(t, root, "apps/killswitch-controller")

	entryTime := time.Now().Add(time.Minute)
	ag := startMockAdGuard(t, entryTime)

	ksAddr := freeAddr(t)
	stopKs := startProc(t, ksBin, map[string]string{
		"LISTEN_ADDR":        ksAddr,
		"ADGUARD_URL":        ag.url,
		"ADGUARD_USER":       "admin",
		"ADGUARD_PASSWORD":   "test",
		"KILLSWITCH_API_KEY": e2eAPIKey,
		// No ALLOWLIST_* at all: nothing is protected.
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	ev := events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            "DET-noallow",
		Timestamp:     time.Now().UTC(),
		Domain:        "c2.example",
		MatchedIoC:    "c2.example",
		IoCType:       "domain",
		ClientIP:      "192.168.1.200",
		ClientMAC:     "aa:bb:cc:dd:ee:99",
		Severity:      events.SeverityCritical,
		Confidence:    99,
		SignalClass:   events.SignalIoC,
	}

	var result struct {
		Decision struct {
			Action string
		} `json:"decision"`
		Action *events.EnforcementAction `json:"action"`
	}
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eAPIKey, ev, &result)

	if result.Decision.Action != "pending" {
		t.Fatalf("decision = %q, want pending: with an empty allowlist the target could "+
			"be the router, so auto-block must be withheld", result.Decision.Action)
	}
	if result.Action == nil || result.Action.State != events.StatePending {
		t.Fatalf("action should be queued as pending, got %+v", result.Action)
	}
}

// TestHeuristicsNeverAutoBlockE2E is the end-to-end form of the step-124
// policy fix, exercised through the real HTTP API rather than the policy
// package alone.
//
// Composite confidence combines signals with a noisy-OR, so the strongest
// pair of heuristics the engine can produce — a beacon capped at 75 and a
// volumetric anomaly capped at 70 — combines to 93, which maps to severity
// "critical". That cleared both the 90/critical bar and AutoMinSignals=2, so
// two local heuristics could quarantine a household device with no human in
// the loop and nothing external attesting the destination was malicious.
// NTP, telemetry and update checks all look like beaconing.
func TestHeuristicsNeverAutoBlockE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	root := repoRoot(t)
	ksBin := goBuild(t, root, "apps/killswitch-controller")

	entryTime := time.Now().Add(time.Minute)
	ag := startMockAdGuard(t, entryTime)

	ksAddr := freeAddr(t)
	stopKs := startProc(t, ksBin, map[string]string{
		"LISTEN_ADDR":        ksAddr,
		"ADGUARD_URL":        ag.url,
		"ADGUARD_USER":       "admin",
		"ADGUARD_PASSWORD":   "test",
		"KILLSWITCH_API_KEY": e2eAPIKey,
		// Match the proxmox-soc overlay: corroboration required.
		"POLICY_AUTO_MIN_SIGNALS": "2",
		"ALLOWLIST_IPS":           "192.168.1.1",
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	base := events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		Timestamp:     time.Now().UTC(),
		Domain:        "updates.vendor.example",
		MatchedIoC:    "updates.vendor.example",
		IoCType:       "domain",
		ClientIP:      "192.168.1.150",
		ClientMAC:     "aa:bb:cc:dd:ee:50",
		Severity:      events.SeverityCritical,
		Confidence:    93, // exactly what combine([75, 70]) produces
	}

	type evalResult struct {
		Decision struct {
			Action string
			Reason string
		} `json:"decision"`
		Action *events.EnforcementAction `json:"action"`
	}

	// Two heuristics, corroborated, critical, 93 confidence → must still
	// wait for a human.
	heuristics := base
	heuristics.ID = "DET-heuristics"
	heuristics.SignalClass = events.SignalComposite
	heuristics.Signals = []string{events.SignalBeacon, events.SignalVolumetric}
	heuristics.SignalCount = 2

	var got evalResult
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eAPIKey, heuristics, &got)
	if got.Decision.Action != "pending" {
		t.Fatalf("beacon+volumetric must stay human-in-the-loop, got %q (reason: %s)",
			got.Decision.Action, got.Decision.Reason)
	}
	if got.Action == nil || got.Action.State != events.StatePending {
		t.Fatalf("action should be queued for approval, got %+v", got.Action)
	}
	// Nothing may have reached AdGuard.
	if rules := ag.Rules(); containsRule(rules, "||updates.vendor.example^") {
		t.Fatalf("no sinkhole rule should exist for a heuristic-only detection: %v", rules)
	}

	// The same client corroborated by an IDS signature IS known-bad.
	withSignature := base
	withSignature.ID = "DET-with-signature"
	withSignature.SignalClass = events.SignalComposite
	withSignature.Signals = []string{events.SignalBeacon, events.SignalVolumetric, events.SignalIDS}
	withSignature.SignalCount = 3

	var signed evalResult
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eAPIKey, withSignature, &signed)
	if signed.Decision.Action != "auto_block" {
		t.Fatalf("heuristics corroborated by an IDS signature should auto-block, got %q (reason: %s)",
			signed.Decision.Action, signed.Decision.Reason)
	}
}

// TestAllowlistProtectsGatewayE2E: devices commonly use the router as their
// DNS forwarder, so household queries can appear to come FROM the gateway.
// One feed match on an allowlisted address must never produce enforcement.
func TestAllowlistProtectsGatewayE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	root := repoRoot(t)
	ksBin := goBuild(t, root, "apps/killswitch-controller")

	entryTime := time.Now().Add(time.Minute)
	ag := startMockAdGuard(t, entryTime)

	ksAddr := freeAddr(t)
	stopKs := startProc(t, ksBin, map[string]string{
		"LISTEN_ADDR":        ksAddr,
		"ADGUARD_URL":        ag.url,
		"ADGUARD_USER":       "admin",
		"ADGUARD_PASSWORD":   "test",
		"KILLSWITCH_API_KEY": e2eAPIKey,
		// Spelled the way a router UI shows it, to prove normalization
		// works: the detection pipeline emits lowercase colon form.
		"ALLOWLIST_MACS": "AA-BB-CC-DD-EE-FF",
		"ALLOWLIST_IPS":  "192.168.1.0/29",
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	type evalResult struct {
		Decision struct {
			Action string
			Reason string
		} `json:"decision"`
		Action *events.EnforcementAction `json:"action"`
	}

	cases := []struct {
		name string
		ev   events.DetectionEvent
	}{
		{
			name: "allowlisted MAC in a different spelling",
			ev: events.DetectionEvent{
				ID: "DET-gw-mac", ClientMAC: "aa:bb:cc:dd:ee:ff", ClientIP: "10.9.9.9",
				Severity: events.SeverityCritical, Confidence: 99, SignalClass: events.SignalIoC,
				Domain: "c2.example", MatchedIoC: "c2.example", IoCType: "domain",
			},
		},
		{
			name: "address inside an allowlisted CIDR",
			ev: events.DetectionEvent{
				ID: "DET-gw-cidr", ClientMAC: "11:22:33:44:55:66", ClientIP: "192.168.1.1",
				Severity: events.SeverityCritical, Confidence: 99, SignalClass: events.SignalIoC,
				Domain: "c2.example", MatchedIoC: "c2.example", IoCType: "domain",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.ev.SchemaVersion = events.DetectionSchemaVersion
			tc.ev.Timestamp = time.Now().UTC()

			var got evalResult
			postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eAPIKey, tc.ev, &got)
			if got.Decision.Action != "ignore" {
				t.Fatalf("an allowlisted device must never be enforced against, got %q (reason: %s)",
					got.Decision.Action, got.Decision.Reason)
			}
			if got.Action != nil {
				t.Fatalf("no action should be created for an allowlisted device: %+v", got.Action)
			}
		})
	}

	if rules := ag.Rules(); len(rules) != 0 {
		t.Fatalf("no sinkhole rule should have been written: %v", rules)
	}
}
