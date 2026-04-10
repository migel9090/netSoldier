//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

	assertEq(t, "webhook.event", "threat_detected", wp.Event)
	assertEq(t, "webhook.service", "detection-engine", wp.Service)
	assertEq(t, "alert.domain", "evil.example.com", wp.Alert.Domain)
	assertEq(t, "alert.client_ip", "192.168.1.42", wp.Alert.ClientIP)
	assertEq(t, "alert.matched_ioc", "evil.example.com", wp.Alert.MatchedIoC)
	assertEq(t, "alert.severity", "high", wp.Alert.Severity)
	assertEq(t, "alert.source", "local", wp.Alert.Source)
	if wp.Alert.ID == "" {
		t.Error("alert.id is empty")
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

// ── types ───────────────────────────────────────────────────────────

type whPayload struct {
	Event   string     `json:"event"`
	Service string     `json:"service"`
	Alert   alertEntry `json:"alert"`
}

type alertEntry struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	ClientIP   string `json:"client_ip"`
	QueryType  string `json:"query_type"`
	MatchedIoC string `json:"matched_ioc"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
}

// ── mock AdGuard Home ───────────────────────────────────────────────

type mockAdGuard struct{ url string }

func startMockAdGuard(t *testing.T, entryTime time.Time) *mockAdGuard {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /control/querylog", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"data": []map[string]any{{
				"question": map[string]string{"host": "evil.example.com", "type": "A"},
				"client":   "192.168.1.42",
				"time":     entryTime,
				"reason":   "FilteredBlackList",
			}},
			"oldest": "",
		})
	})
	ln := listenTCP(t)
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return &mockAdGuard{url: "http://" + ln.Addr().String()}
}

// ── mock webhook receiver ───────────────────────────────────────────

type webhookRx struct {
	url string
	got chan struct{}
	mu  sync.Mutex
	buf []json.RawMessage
}

func startWebhookReceiver(t *testing.T) *webhookRx {
	t.Helper()
	rx := &webhookRx{got: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rx.mu.Lock()
		rx.buf = append(rx.buf, json.RawMessage(body))
		rx.mu.Unlock()
		select {
		case rx.got <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	})
	ln := listenTCP(t)
	rx.url = "http://" + ln.Addr().String()
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return rx
}

func (rx *webhookRx) received() []json.RawMessage {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	out := make([]json.RawMessage, len(rx.buf))
	copy(out, rx.buf)
	return out
}

// ── helpers ─────────────────────────────────────────────────────────

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.work not found — cannot locate repo root")
		}
		dir = parent
	}
}

func goBuild(t *testing.T, root, appPath string) string {
	t.Helper()
	name := filepath.Base(appPath)
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/"+name)
	cmd.Dir = filepath.Join(root, appPath)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s:\n%s\n%v", appPath, out, err)
	}
	return bin
}

func startProc(t *testing.T, bin string, env map[string]string) func() {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	merged := make(map[string]string)
	for _, e := range os.Environ() {
		if k, v, ok := strings.Cut(e, "="); ok {
			merged[k] = v
		}
	}
	for k, v := range env {
		merged[k] = v
	}
	cmd.Env = make([]string, 0, len(merged))
	for k, v := range merged {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	return func() {
		_ = cmd.Process.Signal(os.Interrupt)
		_ = cmd.Wait()
	}
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln := listenTCP(t)
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitHealthy(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("health check failed: %s", url)
}

func httpGetJSON(t *testing.T, url string, dst any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: %d %s", url, resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("GET %s: decode: %v", url, err)
	}
}

func assertEq(t *testing.T, field, want, got string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: want %q, got %q", field, want, got)
	}
}
