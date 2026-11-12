//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// These tests pin the v2 event contract between the real binaries: typed
// enforcement targets, validation at the receiver, timestamped signatures
// with idempotent evaluation, and detection ids that survive a restart.

func startKillswitch(t *testing.T, ksBin, agURL string, extra map[string]string) string {
	t.Helper()
	ksAddr := freeAddr(t)
	env := map[string]string{
		"LISTEN_ADDR":        ksAddr,
		"ADGUARD_URL":        agURL,
		"ADGUARD_USER":       "admin",
		"ADGUARD_PASSWORD":   "test",
		"KILLSWITCH_API_KEY": e2eAPIKey,
		"WEBHOOK_SECRET":     e2eWebhookSecret,
		"ALLOWLIST_IPS":      "192.168.1.1",
	}
	for k, v := range extra {
		env[k] = v
	}
	t.Cleanup(startProc(t, ksBin, env))
	waitHealthy(t, "http://"+ksAddr+"/healthz")
	return ksAddr
}

// TestReplayedEventIsIdempotentE2E: one signed detection delivered twice —
// a sender retry, or a captured request replayed inside the signature
// window — used to create a second action and a second driver call. The
// repeat must get the first decision back and change nothing.
func TestReplayedEventIsIdempotentE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ksBin := goBuild(t, repoRoot(t), "apps/killswitch-controller")
	ag := startMockAdGuard(t, time.Now().Add(time.Minute))
	ksAddr := startKillswitch(t, ksBin, ag.url, nil)

	body, err := json.Marshal(v2Event("replayed-c2.example", 97, events.SeverityCritical))
	if err != nil {
		t.Fatal(err)
	}
	sig := events.SignPayload(e2eWebhookSecret, body)

	type result struct {
		Decision  struct{ Action, Reason string } `json:"decision"`
		Action    *events.EnforcementAction       `json:"action"`
		Duplicate bool                            `json:"duplicate"`
	}
	var first, second result
	for i, dst := range []*result{&first, &second} {
		status, raw := postEvaluateRaw(t, ksAddr, body, sig)
		if status != http.StatusOK {
			t.Fatalf("delivery %d: %d %s", i+1, status, raw)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}

	if first.Decision.Action != "auto_block" || first.Action == nil || first.Duplicate {
		t.Fatalf("first delivery: %+v", first)
	}
	if !second.Duplicate || second.Decision != first.Decision ||
		second.Action == nil || second.Action.ID != first.Action.ID {
		t.Fatalf("the repeat must return the original decision and action, got %+v", second)
	}
	if active := listActions(t, ksAddr, "active"); len(active) != 1 {
		t.Fatalf("one event, %d active actions", len(active))
	}
	if rules := ag.Rules(); len(rules) != 1 || rules[0] != "||replayed-c2.example^" {
		t.Fatalf("AdGuard rules = %v", rules)
	}
}

// TestInvalidEventRejectedE2E: /evaluate validated nothing, so a 1.x-shaped
// event (no summary, no evidence, restart-prone id) was evaluated and acted
// on. It must be refused with a status that says why — and a 4xx, so the
// sender does not retry it.
func TestInvalidEventRejectedE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	ksBin := goBuild(t, repoRoot(t), "apps/killswitch-controller")
	ag := startMockAdGuard(t, time.Now().Add(time.Minute))
	ksAddr := startKillswitch(t, ksBin, ag.url, nil)

	v1, _ := json.Marshal(map[string]any{
		"schema_version": "1.0",
		"id":             "DET-1",
		"timestamp":      time.Now().UTC(),
		"domain":         "cdn.legit.example (→203.0.113.7)",
		"matched_ioc":    "203.0.113.7",
		"ioc_type":       "ip",
		"client_ip":      "192.168.1.42",
		"severity":       "critical",
		"confidence":     95,
		"source":         "feodo",
		"signal_class":   "ioc",
	})
	status, raw := postEvaluateRaw(t, ksAddr, v1, events.SignPayload(e2eWebhookSecret, v1))
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d %s, want 422", status, raw)
	}
	for _, want := range []string{"schema_version", "id", "summary", "signals"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("refusal %s should mention %q", raw, want)
		}
	}
	if n := len(listActions(t, ksAddr, "active")) + len(listActions(t, ksAddr, "pending")); n != 0 {
		t.Fatalf("a refused event created %d actions", n)
	}
	if rules := ag.Rules(); len(rules) != 0 {
		t.Fatalf("nothing may reach AdGuard: %v", rules)
	}
}

// TestTypedTargetEndToEnd runs the real engine against the real killswitch
// with two detections the 1.x contract got wrong:
//
//   - a DNS query under a listed domain: the sinkhole rule must name the
//     listed indicator, not the queried subdomain;
//   - a DNS answer that is a listed IP: 1.x sent domain
//     "cdn.legit.example (→203.0.113.7)", auto-blocked it, and failed in the
//     driver. It must become a pending action with no blocked domain and a
//     policy_rule that says why.
func TestTypedTargetEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	root := repoRoot(t)
	detBin := goBuild(t, root, "apps/detection-engine")
	ksBin := goBuild(t, root, "apps/killswitch-controller")

	// Threat intel: one domain and one address, both critical.
	var mu sync.Mutex
	var exportedAt time.Time
	tiMux := http.NewServeMux()
	tiMux.HandleFunc("GET /export/json", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		if exportedAt.IsZero() {
			exportedAt = time.Now()
		}
		mu.Unlock()
		fmt.Fprint(w, `[{"Type":"domain","Value":"evil-ioc.example","Source":"threatfox","Confidence":95,"Threat":"c2"},
			{"Type":"ip","Value":"203.0.113.7","Source":"feodo","Confidence":95,"Threat":"c2"}]`)
	})
	tiLn := listenTCP(t)
	tiSrv := &http.Server{Handler: tiMux}
	go tiSrv.Serve(tiLn)
	t.Cleanup(func() { tiSrv.Close() })

	// The querylog stays empty until the engine has loaded the indicators,
	// or the entries would be consumed before there was anything to match.
	ready := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return !exportedAt.IsZero() && time.Since(exportedAt) > 1500*time.Millisecond
	}
	entryTime := time.Now().Add(time.Hour)
	ag := startMockAdGuardWith(t, ready,
		map[string]any{
			"question": map[string]string{"host": "x.evil-ioc.example", "type": "A"},
			"client":   "192.168.1.66", "time": entryTime,
		},
		map[string]any{
			"question": map[string]string{"host": "cdn.legit.example", "type": "A"},
			"client":   "192.168.1.67", "time": entryTime.Add(-time.Second),
			"answer": []map[string]any{{"value": "203.0.113.7", "type": "A", "ttl": 60}},
		},
	)

	ksAddr := startKillswitch(t, ksBin, ag.url, nil)
	stopDet := startProc(t, detBin, map[string]string{
		"LISTEN_ADDR":                 freeAddr(t),
		"ADGUARD_URL":                 ag.url,
		"ADGUARD_USER":                "admin",
		"ADGUARD_PASSWORD":            "test",
		"THREATLIST_PATH":             "/nonexistent",
		"THREAT_INTEL_URL":            "http://" + tiLn.Addr().String(),
		"POLL_INTERVAL":               "1s",
		"WEBHOOK_URL":                 "http://" + ksAddr + "/evaluate",
		"WEBHOOK_SECRET":              e2eWebhookSecret,
		"WEBHOOK_TOKEN":               e2eAPIKey,
		"DETECTION_API_KEY":           e2eAPIKey,
		"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1",
	})
	t.Cleanup(stopDet)

	var active, pending []events.EnforcementAction
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		active, pending = listActions(t, ksAddr, "active"), listActions(t, ksAddr, "pending")
		if len(active) >= 1 && len(pending) >= 1 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if len(active) != 1 || len(pending) != 1 {
		t.Fatalf("want one active (domain) and one pending (ip) action, got active=%+v pending=%+v",
			active, pending)
	}

	block := active[0]
	if block.BlockedDomain != "evil-ioc.example" || block.TargetIP != "192.168.1.66" {
		t.Errorf("domain hit: blocked_domain=%q target_ip=%q, want the listed indicator for .66",
			block.BlockedDomain, block.TargetIP)
	}
	held := pending[0]
	if held.BlockedDomain != "" || held.TargetIP != "192.168.1.67" {
		t.Errorf("ip hit: blocked_domain=%q target_ip=%q, want no domain for .67",
			held.BlockedDomain, held.TargetIP)
	}
	if !strings.Contains(held.PolicyRule, "target is ip 203.0.113.7") {
		t.Errorf("ip hit: policy_rule %q should say why it was not auto-blocked", held.PolicyRule)
	}
	if !strings.Contains(held.DetectionSummary, "203.0.113.7") || !strings.Contains(held.DetectionSummary, "cdn.legit.example") {
		t.Errorf("ip hit: the summary is what the operator reads, got %q", held.DetectionSummary)
	}

	idRe := regexp.MustCompile(events.DetectionIDPattern)
	for _, a := range []events.EnforcementAction{block, held} {
		if !idRe.MatchString(a.DetectionID) {
			t.Errorf("detection_id %q does not match %s", a.DetectionID, events.DetectionIDPattern)
		}
	}
	if rules := ag.Rules(); len(rules) != 1 || rules[0] != "||evil-ioc.example^" {
		t.Fatalf("AdGuard rules = %v, want only ||evil-ioc.example^", rules)
	}
}

// TestDetectionIDsSurviveRestartE2E: the engine's counter restarted at DET-1
// on every boot, so two boots produced the same id for different detections
// and the audit trail could not say which one an action came from.
func TestDetectionIDsSurviveRestartE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	detBin := goBuild(t, repoRoot(t), "apps/detection-engine")
	tlFile := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(tlFile, []byte("evil.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ag := startMockAdGuard(t, time.Now().Add(time.Hour))

	firstID := func() string {
		wh := startWebhookReceiver(t, e2eWebhookSecret, e2eAPIKey)
		addr := freeAddr(t)
		stop := startProc(t, detBin, map[string]string{
			"LISTEN_ADDR":                 addr,
			"ADGUARD_URL":                 ag.url,
			"ADGUARD_USER":                "admin",
			"ADGUARD_PASSWORD":            "test",
			"THREATLIST_PATH":             tlFile,
			"POLL_INTERVAL":               "1s",
			"WEBHOOK_URL":                 wh.url,
			"WEBHOOK_SECRET":              e2eWebhookSecret,
			"WEBHOOK_TOKEN":               e2eAPIKey,
			"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1",
		})
		defer stop()
		select {
		case <-wh.got:
		case <-time.After(20 * time.Second):
			t.Fatal("no webhook delivery within 20s")
		}
		var ev events.DetectionEvent
		if err := json.Unmarshal(wh.received()[0], &ev); err != nil {
			t.Fatal(err)
		}
		if verified, _, _ := wh.stats(); verified == 0 {
			t.Fatal("delivery was not verified under signature v2")
		}
		return ev.ID
	}

	before, after := firstID(), firstID()
	idRe := regexp.MustCompile(events.DetectionIDPattern)
	if !idRe.MatchString(before) || !idRe.MatchString(after) {
		t.Fatalf("ids %q, %q do not match %s", before, after, events.DetectionIDPattern)
	}
	if before == after {
		t.Fatalf("the first detection after a restart reused id %q", before)
	}
}
