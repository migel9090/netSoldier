//go:build e2e

package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
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
		"LISTEN_ADDR":             ksAddr,
		"KILLSWITCH_DB_PATH":      ksDBPath(t),
		"ADGUARD_URL":             ag.url,
		"ADGUARD_USER":            "admin",
		"ADGUARD_PASSWORD":        "test",
		"KILLSWITCH_API_KEY":      e2eAPIKey,
		"KILLSWITCH_INGEST_TOKEN": e2eIngestToken,
		"WEBHOOK_SECRET":          e2eWebhookSecret,
		"ALLOWLIST_IPS":           "192.168.1.1",
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
		"WEBHOOK_TOKEN":               e2eIngestToken,
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
	if !regexp.MustCompile(events.DetectionIDPattern).MatchString(a.DetectionID) {
		t.Errorf("detection_id = %q: the action should carry the namespaced id of the "+
			"detection that triggered it", a.DetectionID)
	}
	if a.DetectionSummary == "" {
		t.Error("the action should carry the detection's summary for the approval dialog")
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
		"LISTEN_ADDR":             ksAddr,
		"KILLSWITCH_DB_PATH":      ksDBPath(t),
		"ADGUARD_URL":             ag.url,
		"ADGUARD_USER":            "admin",
		"ADGUARD_PASSWORD":        "test",
		"KILLSWITCH_API_KEY":      e2eAPIKey,
		"KILLSWITCH_INGEST_TOKEN": e2eIngestToken,
		"WEBHOOK_SECRET":          e2eWebhookSecret,
		"ALLOWLIST_IPS":           "192.168.1.1",
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	ev := v2Event("attacker.example", 99, events.SeverityCritical)
	ev.ClientIP, ev.ClientMAC = "192.168.1.200", "aa:bb:cc:dd:ee:99"
	body, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	legacy := hmac.New(sha256.New, []byte(e2eWebhookSecret))
	legacy.Write(body)

	cases := []struct {
		name  string
		token string
		sig   string
	}{
		{"no credentials at all", "", ""},
		{"token but no signature", e2eIngestToken, ""},
		{"valid token, wrong signature", e2eIngestToken, events.SignPayload("wrong-secret", body)},
		{"valid signature, wrong token", "wrong-token", events.SignPayload(e2eWebhookSecret, body)},
		// The operator token approves actions; it cannot submit them.
		{"valid signature, operator token", e2eAPIKey, events.SignPayload(e2eWebhookSecret, body)},
		// A genuine signature captured ten minutes ago: outside the window.
		{"stale signature", e2eIngestToken,
			events.SignPayloadAt(e2eWebhookSecret, time.Now().Add(-10*time.Minute), body)},
		// The 1.x body-only scheme has no timestamp; accepting it would
		// reopen the replay hole.
		{"legacy body-only signature", e2eIngestToken, "sha256=" + hex.EncodeToString(legacy.Sum(nil))},
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
		"LISTEN_ADDR":             ksAddr,
		"KILLSWITCH_DB_PATH":      ksDBPath(t),
		"ADGUARD_URL":             ag.url,
		"ADGUARD_USER":            "admin",
		"ADGUARD_PASSWORD":        "test",
		"KILLSWITCH_API_KEY":      e2eAPIKey,
		"KILLSWITCH_INGEST_TOKEN": e2eIngestToken,
		"WEBHOOK_SECRET":          e2eWebhookSecret,
		// No ALLOWLIST_* at all: nothing is protected.
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	ev := v2Event("c2.example", 99, events.SeverityCritical)
	ev.ClientIP, ev.ClientMAC = "192.168.1.200", "aa:bb:cc:dd:ee:99"

	var result struct {
		Decision struct {
			Action string
		} `json:"decision"`
		Action *events.EnforcementAction `json:"action"`
	}
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eIngestToken, ev, &result)

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
		"LISTEN_ADDR":             ksAddr,
		"KILLSWITCH_DB_PATH":      ksDBPath(t),
		"ADGUARD_URL":             ag.url,
		"ADGUARD_USER":            "admin",
		"ADGUARD_PASSWORD":        "test",
		"KILLSWITCH_API_KEY":      e2eAPIKey,
		"KILLSWITCH_INGEST_TOKEN": e2eIngestToken,
		"WEBHOOK_SECRET":          e2eWebhookSecret,
		// Match the proxmox-soc overlay: corroboration required.
		"POLICY_AUTO_MIN_SIGNALS": "2",
		"ALLOWLIST_IPS":           "192.168.1.1",
	})
	t.Cleanup(stopKs)
	waitHealthy(t, "http://"+ksAddr+"/healthz")

	// A composite pointed at the beacon's destination, as the engine builds
	// it when no known-bad signal names a target of its own.
	base := v2Event("updates.vendor.example", 93, events.SeverityCritical) // 93 = combine([75, 70])
	base.ClientIP, base.ClientMAC = "192.168.1.150", "aa:bb:cc:dd:ee:50"
	base.Source = "composite"
	beacon := events.Signal{Class: events.SignalBeacon, Confidence: 75,
		Indicator: "updates.vendor.example", IndicatorType: events.IndicatorDomain, Source: "rita"}
	volumetric := events.Signal{Class: events.SignalVolumetric, Confidence: 70, Source: "iforest"}

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
	heuristics.ID = "DET-e2e-9001"
	heuristics.SignalClass = events.SignalComposite
	heuristics.Signals = []events.Signal{beacon, volumetric}

	var got evalResult
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eIngestToken, heuristics, &got)
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

	// An IDS signature that names a rule id attests nothing about the
	// beacon's destination: still a human's call (KS-2).
	withSignature := base
	withSignature.ID = "DET-e2e-9002"
	withSignature.SignalClass = events.SignalComposite
	withSignature.Signals = []events.Signal{beacon, volumetric,
		{Class: events.SignalIDS, Confidence: 70, Indicator: "2013028", IndicatorType: events.IndicatorSID}}

	var signed evalResult
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eIngestToken, withSignature, &signed)
	if signed.Decision.Action != "pending" ||
		!strings.Contains(signed.Decision.Reason, "no known-bad signal names the target updates.vendor.example") {
		t.Fatalf("an IDS hit on a rule id must not unlock a block of the beacon's destination, got %q (reason: %s)",
			signed.Decision.Action, signed.Decision.Reason)
	}

	// A signature that matched the destination itself, strongly, does.
	attested := base
	attested.ID = "DET-e2e-9003"
	attested.SignalClass = events.SignalComposite
	attested.Signals = []events.Signal{beacon, volumetric,
		{Class: events.SignalIDS, Confidence: 95, Indicator: "updates.vendor.example",
			IndicatorType: events.IndicatorDomain, Source: "suricata-dataset"}}

	var blocked evalResult
	postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eIngestToken, attested, &blocked)
	if blocked.Decision.Action != "auto_block" {
		t.Fatalf("a strong signature on the destination itself should auto-block, got %q (reason: %s)",
			blocked.Decision.Action, blocked.Decision.Reason)
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
		"LISTEN_ADDR":             ksAddr,
		"KILLSWITCH_DB_PATH":      ksDBPath(t),
		"ADGUARD_URL":             ag.url,
		"ADGUARD_USER":            "admin",
		"ADGUARD_PASSWORD":        "test",
		"KILLSWITCH_API_KEY":      e2eAPIKey,
		"KILLSWITCH_INGEST_TOKEN": e2eIngestToken,
		"WEBHOOK_SECRET":          e2eWebhookSecret,
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
		{name: "allowlisted MAC in a different spelling", ev: v2Event("c2.example", 99, events.SeverityCritical)},
		{name: "address inside an allowlisted CIDR", ev: v2Event("c2.example", 99, events.SeverityCritical)},
	}
	cases[0].ev.ClientMAC, cases[0].ev.ClientIP = "aa:bb:cc:dd:ee:ff", "10.9.9.9"
	cases[1].ev.ClientMAC, cases[1].ev.ClientIP = "11:22:33:44:55:66", "192.168.1.1"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got evalResult
			postAuthedJSON(t, "http://"+ksAddr+"/evaluate", e2eIngestToken, tc.ev, &got)
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
