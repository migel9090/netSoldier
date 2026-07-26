//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// TestVerticalSlice validates the full detection pipeline end-to-end:
//
//	mock AdGuard querylog (bad domain) → detection-engine alert
//	→ webhook delivery + /alerts API visible.
//
// The web-ui proxies /api/alerts to detection-engine /alerts via
// hooks.server.ts, so verifying the API covers the data path shown in the UI.
func TestVerticalSlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}

	root := repoRoot(t)

	detBin := goBuild(t, root, "apps/detection-engine")
	invBin := goBuild(t, root, "apps/device-inventory")

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

	waitHealthy(t, "http://"+detAddr+"/healthz")
	waitHealthy(t, "http://"+invAddr+"/healthz")

	t.Log("services healthy — waiting for alert pipeline")
	select {
	case <-wh.got:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout: no webhook delivery within 15 s")
	}

	// Webhook payload assertions.
	payloads := wh.received()
	if len(payloads) == 0 {
		t.Fatal("webhook: zero payloads")
	}

	var wp whPayload
	if err := json.Unmarshal(payloads[0], &wp); err != nil {
		t.Fatalf("webhook unmarshal: %v", err)
	}

	assertEq(t, "webhook.schema_version", events.DetectionSchemaVersion, wp.SchemaVersion)
	assertEq(t, "webhook.domain", "evil.example.com", wp.Domain)
	assertEq(t, "webhook.client_ip", "192.168.1.42", wp.ClientIP)
	assertEq(t, "webhook.matched_ioc", "evil.example.com", wp.MatchedIoC)
	assertEq(t, "webhook.ioc_type", "domain", wp.IoCType)
	assertEq(t, "webhook.severity", "high", wp.Severity)
	assertEq(t, "webhook.source", "local", wp.Source)
	if wp.ID == "" {
		t.Error("webhook id is empty")
	}
	if wp.Timestamp.IsZero() {
		t.Error("webhook timestamp is zero")
	}

	// /alerts API — same data the web-ui renders.
	var alerts []alertEntry
	httpGetJSON(t, "http://"+detAddr+"/alerts", &alerts)
	if len(alerts) == 0 {
		t.Fatal("/alerts: empty")
	}
	assertEq(t, "/alerts[0].domain", "evil.example.com", alerts[0].Domain)
	assertEq(t, "/alerts[0].client_ip", "192.168.1.42", alerts[0].ClientIP)

	// /devices API — valid but empty (no DHCP traffic in test).
	var devices []json.RawMessage
	httpGetJSON(t, "http://"+invAddr+"/devices", &devices)
	t.Logf("/devices: %d entries (0 expected)", len(devices))
}

// whPayload is the webhook body: since step 116 detection-engine sends the
// shared events.DetectionEvent directly, not the old {event, service, alert}
// envelope. Decoding into the real type keeps this test tied to the contract
// the killswitch consumes.
type whPayload = events.DetectionEvent

type alertEntry struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	ClientIP   string `json:"client_ip"`
	QueryType  string `json:"query_type"`
	MatchedIoC string `json:"matched_ioc"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
}
