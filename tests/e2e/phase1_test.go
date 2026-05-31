//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestPhase1E2E validates the complete Phase 1 flow end-to-end:
//
//   - Device inventory API reachable
//   - DNS threat detection pipeline (AdGuard poll → alert → webhook)
//   - Killswitch pending approval: evaluate → pending → approve → active → revert
//   - Killswitch auto-block: critical/high-confidence → immediate enforcement
//   - AdGuard sinkhole rules applied and reverted correctly
//   - Alerts API returns detection results
//
// All services run as real Go binaries against a mock AdGuard.
func TestPhase1E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	root := repoRoot(t)

	detBin := goBuild(t, root, "apps/detection-engine")
	invBin := goBuild(t, root, "apps/device-inventory")
	ksBin := goBuild(t, root, "apps/killswitch-controller")

	tlFile := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(tlFile, []byte("evil.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	entryTime := time.Now().Add(time.Minute)
	ag := startMockAdGuard(t, entryTime)
	wh := startWebhookReceiver(t)

	detAddr := freeAddr(t)
	stopDet := startProc(t, detBin, map[string]string{
		"LISTEN_ADDR":                 detAddr,
		"ADGUARD_URL":                 ag.url,
		"ADGUARD_USER":                "admin",
		"ADGUARD_PASSWORD":            "test",
		"THREATLIST_PATH":             tlFile,
		"POLL_INTERVAL":               "1s",
		"WEBHOOK_URL":                 wh.url,
		"WEBHOOK_SECRET":              "e2e-secret",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1",
	})
	t.Cleanup(stopDet)

	invAddr := freeAddr(t)
	stopInv := startProc(t, invBin, map[string]string{
		"LISTEN_ADDR": invAddr,
		"DB_PATH":     filepath.Join(t.TempDir(), "devices.db"),
	})
	t.Cleanup(stopInv)

	ksAddr := freeAddr(t)
	stopKs := startProc(t, ksBin, map[string]string{
		"LISTEN_ADDR":      ksAddr,
		"ADGUARD_URL":      ag.url,
		"ADGUARD_USER":     "admin",
		"ADGUARD_PASSWORD": "test",
	})
	t.Cleanup(stopKs)

	waitHealthy(t, "http://"+detAddr+"/healthz")
	waitHealthy(t, "http://"+invAddr+"/healthz")
	waitHealthy(t, "http://"+ksAddr+"/healthz")
	t.Log("all services healthy")

	// ── Detection pipeline ──────────────────────────────────────────

	t.Log("waiting for detection alert via webhook")
	select {
	case <-wh.got:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: no webhook delivery within 15s")
	}

	payloads := wh.received()
	if len(payloads) == 0 {
		t.Fatal("webhook: zero payloads")
	}
	var wp whPayload
	if err := json.Unmarshal(payloads[0], &wp); err != nil {
		t.Fatalf("webhook unmarshal: %v", err)
	}
	assertEq(t, "webhook.event", "threat_detected", wp.Event)
	assertEq(t, "alert.domain", "evil.example.com", wp.Alert.Domain)
	assertEq(t, "alert.client_ip", "192.168.1.42", wp.Alert.ClientIP)
	t.Log("detection pipeline OK")

	// ── Alerts API ──────────────────────────────────────────────────

	var alerts []alertEntry
	httpGetJSON(t, "http://"+detAddr+"/alerts", &alerts)
	if len(alerts) == 0 {
		t.Fatal("/alerts: empty")
	}
	assertEq(t, "/alerts[0].domain", "evil.example.com", alerts[0].Domain)
	t.Logf("alerts API OK (%d alert(s))", len(alerts))

	// ── Device inventory ────────────────────────────────────────────

	var devices []json.RawMessage
	httpGetJSON(t, "http://"+invAddr+"/devices", &devices)
	t.Logf("device-inventory API OK (%d device(s))", len(devices))

	// ── Killswitch: policy query ────────────────────────────────────

	var pol map[string]any
	httpGetJSON(t, "http://"+ksAddr+"/policy", &pol)
	if pol["default_action"] != "dns_sinkhole" {
		t.Errorf("policy default_action: want dns_sinkhole, got %v", pol["default_action"])
	}
	t.Log("policy endpoint OK")

	// ── Killswitch: ignore (below threshold) ────────────────────────

	type evalResp struct {
		Decision struct {
			Action string `json:"action"`
		} `json:"decision"`
		Action *actionSummary `json:"action"`
	}

	var ignoreResult evalResp
	httpPostJSON(t, "http://"+ksAddr+"/evaluate", map[string]any{
		"schema_version": "1.0",
		"id":             "DET-E2E-IGNORE",
		"domain":         "benign.example.com",
		"matched_ioc":    "benign.example.com",
		"ioc_type":       "domain",
		"client_ip":      "192.168.1.10",
		"severity":       "low",
		"confidence":     10,
		"source":         "e2e-test",
	}, &ignoreResult)
	assertEq(t, "ignore.decision", "ignore", ignoreResult.Decision.Action)
	if ignoreResult.Action != nil {
		t.Error("ignore: expected nil action")
	}
	t.Log("ignore decision OK")

	// ── Killswitch: pending approval flow ───────────────────────────

	t.Log("evaluating medium-severity detection → pending")
	var pendResult evalResp
	httpPostJSON(t, "http://"+ksAddr+"/evaluate", map[string]any{
		"schema_version": "1.0",
		"id":             "DET-E2E-PENDING",
		"domain":         "suspicious.example.com",
		"matched_ioc":    "suspicious.example.com",
		"ioc_type":       "domain",
		"client_ip":      "192.168.1.42",
		"client_mac":     "aa:bb:cc:dd:ee:ff",
		"severity":       "medium",
		"confidence":     75,
		"source":         "e2e-test",
		"threat":         "test-malware",
	}, &pendResult)
	assertEq(t, "pending.decision", "pending", pendResult.Decision.Action)
	if pendResult.Action == nil {
		t.Fatal("pending: action is nil")
	}
	assertEq(t, "pending.state", "pending", pendResult.Action.State)
	actionID := pendResult.Action.ID
	t.Logf("pending action created: %s", actionID)

	var pendingList []actionSummary
	httpGetJSON(t, "http://"+ksAddr+"/actions/pending", &pendingList)
	if !findAction(pendingList, actionID) {
		t.Fatalf("action %s not in /actions/pending", actionID)
	}

	// Approve.
	t.Log("approving action")
	var approved actionSummary
	httpPostJSON(t, "http://"+ksAddr+"/actions/"+actionID+"/approve",
		map[string]string{"approved_by": "e2e-operator"}, &approved)
	assertEq(t, "approved.state", "active", approved.State)
	assertEq(t, "approved.approved_by", "e2e-operator", approved.ApprovedBy)

	rules := ag.Rules()
	if !containsRule(rules, "||suspicious.example.com^") {
		t.Errorf("sinkhole rule not in AdGuard after approve; rules=%v", rules)
	}
	t.Log("approve OK — sinkhole rule verified")

	var activeList []actionSummary
	httpGetJSON(t, "http://"+ksAddr+"/actions/active", &activeList)
	if !findAction(activeList, actionID) {
		t.Fatalf("action %s not in /actions/active after approve", actionID)
	}

	// Revert.
	t.Log("reverting action")
	var reverted actionSummary
	httpPostJSON(t, "http://"+ksAddr+"/actions/"+actionID+"/revert",
		map[string]string{"reason": "e2e revert"}, &reverted)
	assertEq(t, "reverted.state", "reverted", reverted.State)

	rules = ag.Rules()
	if containsRule(rules, "||suspicious.example.com^") {
		t.Error("sinkhole rule still in AdGuard after revert")
	}
	t.Log("revert OK — rule removed")

	httpGetJSON(t, "http://"+ksAddr+"/actions/active", &activeList)
	if findAction(activeList, actionID) {
		t.Errorf("action %s still in /actions/active after revert", actionID)
	}

	// ── Killswitch: auto-block ──────────────────────────────────────

	t.Log("evaluating critical-severity detection → auto-block")
	var autoResult evalResp
	httpPostJSON(t, "http://"+ksAddr+"/evaluate", map[string]any{
		"schema_version": "1.0",
		"id":             "DET-E2E-AUTO",
		"domain":         "c2.evil.test",
		"matched_ioc":    "c2.evil.test",
		"ioc_type":       "domain",
		"client_ip":      "192.168.1.99",
		"client_mac":     "ff:ee:dd:cc:bb:aa",
		"severity":       "critical",
		"confidence":     95,
		"source":         "e2e-test",
		"threat":         "c2-beacon",
	}, &autoResult)
	assertEq(t, "auto.decision", "auto_block", autoResult.Decision.Action)
	if autoResult.Action == nil {
		t.Fatal("auto-block: action is nil")
	}
	autoID := autoResult.Action.ID
	t.Logf("auto-blocked: %s", autoID)

	httpGetJSON(t, "http://"+ksAddr+"/actions/active", &activeList)
	if !findAction(activeList, autoID) {
		t.Fatalf("auto-blocked action %s not in /actions/active", autoID)
	}

	rules = ag.Rules()
	if !containsRule(rules, "||c2.evil.test^") {
		t.Errorf("auto-block sinkhole rule not in AdGuard; rules=%v", rules)
	}
	t.Log("auto-block OK — immediately active with sinkhole rule")

	t.Log("Phase 1 e2e: all checks passed")
}

type actionSummary struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	ActionType    string `json:"action_type"`
	BlockedDomain string `json:"blocked_domain"`
	TargetIP      string `json:"target_ip"`
	TargetMAC     string `json:"target_mac"`
	AutoApproved  bool   `json:"auto_approved"`
	ApprovedBy    string `json:"approved_by"`
}

func findAction(list []actionSummary, id string) bool {
	for _, a := range list {
		if a.ID == id {
			return true
		}
	}
	return false
}

func containsRule(rules []string, want string) bool {
	for _, r := range rules {
		if r == want {
			return true
		}
	}
	return false
}
