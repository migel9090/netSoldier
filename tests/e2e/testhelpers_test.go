//go:build e2e || integration

package e2e

import (
	"bytes"
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

	"github.com/migel9090/netSoldier/libs/events"
)

// Credentials for the authenticated e2e posture. They live here, in the
// untagged helper file, because the helpers below reference them and both the
// e2e and integration builds compile this file.
const (
	e2eAPIKey        = "e2e-api-key" // the killswitch operator token, and the other services' keys
	e2eIngestToken   = "e2e-ingest-token"
	e2eWebhookSecret = "e2e-webhook-secret"
	e2eAgentToken    = "e2e-agent-token"
	// e2eActor is who the web UI's proxy says is acting, on every operator
	// mutation (X-Netsoldier-Actor).
	e2eActor = "e2e-operator"
)

// ksDBPath is a fresh database for one killswitch process. The service
// refuses to start without one.
func ksDBPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "killswitch.db")
}

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
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off")
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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+e2eAPIKey)
	resp, err := http.DefaultClient.Do(req)
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

// httpGetJSONBearer is httpGetJSON with a bearer token. device-inventory
// requires its API key on reads as well as writes, so even the "is the API
// up" checks have to authenticate.
func httpGetJSONBearer(t *testing.T, url, token string, dst any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
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

// httpPostJSON posts to an authenticated endpoint. The token is sent
// unconditionally because the services now run with auth enabled in e2e —
// the production posture, which no earlier run exercised.
func httpPostJSON(t *testing.T, url string, body any, dst any) {
	t.Helper()
	token := e2eAPIKey
	if strings.HasSuffix(url, "/evaluate") {
		token = e2eIngestToken
	}
	postAuthedJSON(t, url, token, body, dst)
}

// postAuthedJSON posts a JSON body with a bearer token and, when the target
// requires it, an HMAC signature over the exact bytes sent.
func postAuthedJSON(t *testing.T, url, token string, body any, dst any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// Only /evaluate carries a signed detection payload; operator actions
	// are authenticated by the bearer token alone, and name the operator
	// the way the web UI's proxy does. Signature v2 is timestamped, so it
	// is computed here, at send time.
	if strings.HasSuffix(url, "/evaluate") {
		req.Header.Set(events.SignatureHeader, events.SignPayload(e2eWebhookSecret, data))
	} else {
		req.Header.Set("X-Netsoldier-Actor", e2eActor)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST %s: %d %s", url, resp.StatusCode, respBody)
	}
	if dst != nil {
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			t.Fatalf("POST %s: decode: %v", url, err)
		}
	}
}

// postEvaluateRaw posts exact bytes to /evaluate with the given signature
// header and returns the status and body, for tests that expect a refusal.
func postEvaluateRaw(t *testing.T, ksAddr string, body []byte, sig string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+ksAddr+"/evaluate", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e2eIngestToken)
	if sig != "" {
		req.Header.Set(events.SignatureHeader, sig)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /evaluate: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

var e2eEventSeq struct {
	sync.Mutex
	n uint64
}

// v2Event returns a contract-valid single-signal domain IoC detection for a
// test-chosen domain indicator, with a fresh id.
func v2Event(indicator string, confidence int, severity string) events.DetectionEvent {
	e2eEventSeq.Lock()
	e2eEventSeq.n++
	n := e2eEventSeq.n
	e2eEventSeq.Unlock()
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            events.FormatDetectionID("e2e", n),
		Timestamp:     time.Now().UTC(),
		Summary:       "DNS query for " + indicator + " matches e2e-test domain indicator " + indicator,
		Domain:        indicator,
		MatchedIoC:    indicator,
		IoCType:       events.IndicatorDomain,
		ClientIP:      "192.168.1.42",
		Severity:      severity,
		Confidence:    confidence,
		Source:        "e2e-test",
		SignalClass:   events.SignalIoC,
		Signals: []events.Signal{{Class: events.SignalIoC, Confidence: confidence,
			Indicator: indicator, IndicatorType: events.IndicatorDomain, Source: "e2e-test"}},
		Target: &events.Target{Type: events.TargetDomain, Value: indicator},
	}
}

// listActions fetches the killswitch actions in a given state.
func listActions(t *testing.T, ksAddr, state string) []events.EnforcementAction {
	t.Helper()
	var out []events.EnforcementAction
	httpGetJSON(t, "http://"+ksAddr+"/actions/"+state, &out)
	return out
}

// bytesReader is a tiny alias so request bodies read clearly in tests.
func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

type mockAdGuard struct {
	url   string
	mu    sync.Mutex
	rules []string
}

func (m *mockAdGuard) Rules() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.rules))
	copy(out, m.rules)
	return out
}

func startMockAdGuard(t *testing.T, entryTime time.Time) *mockAdGuard {
	t.Helper()
	return startMockAdGuardWith(t, nil, map[string]any{
		"question": map[string]string{"name": "evil.example.com", "type": "A"},
		"client":   "192.168.1.42",
		"time":     entryTime,
		"reason":   "FilteredBlackList",
	})
}

// startMockAdGuardWith serves the given querylog entries (newest first, as
// AdGuard does). While ready is non-nil and returns false the querylog is
// empty, so a test can hold the entries back until the engine has loaded the
// indicators they are meant to match.
func startMockAdGuardWith(t *testing.T, ready func() bool, entries ...map[string]any) *mockAdGuard {
	t.Helper()
	m := &mockAdGuard{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /control/querylog", func(w http.ResponseWriter, _ *http.Request) {
		data := entries
		if ready != nil && !ready() {
			data = []map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"data": data, "oldest": ""})
	})
	mux.HandleFunc("GET /control/filtering/status", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		rules := make([]string, len(m.rules))
		copy(rules, m.rules)
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"enabled":    true,
			"user_rules": rules,
		})
	})
	mux.HandleFunc("POST /control/filtering/set_rules", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Rules []string `json:"rules"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		m.mu.Lock()
		m.rules = req.Rules
		m.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	ln := listenTCP(t)
	m.url = "http://" + ln.Addr().String()
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return m
}

type webhookRx struct {
	url string
	got chan struct{}
	mu  sync.Mutex
	buf []json.RawMessage
	// Counters for the authenticated path, so a test can assert that
	// deliveries were accepted BECAUSE they were correctly signed rather
	// than because nothing was checked.
	verified     int
	badSignature int
	unauthorized int
}

// startWebhookReceiver starts a receiver that records deliveries.
//
// When secret/token are non-empty it VERIFIES them the way the killswitch
// does and records the result. The previous receiver accepted anything, so
// no test ever exercised the authenticated path — which is exactly how the
// detection-engine ended up sending X-Webhook-Secret while the killswitch
// required Authorization: Bearer, a mismatch that would have 401'd every
// enforcement request the moment an API key was configured.
func startWebhookReceiver(t *testing.T, creds ...string) *webhookRx {
	t.Helper()
	var secret, token string
	if len(creds) > 0 {
		secret = creds[0]
	}
	if len(creds) > 1 {
		token = creds[1]
	}

	rx := &webhookRx{got: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		if token != "" {
			if r.Header.Get("Authorization") != "Bearer "+token {
				rx.mu.Lock()
				rx.unauthorized++
				rx.mu.Unlock()
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		if secret != "" {
			if err := events.VerifyPayload(secret, r.Header.Get(events.SignatureHeader), body); err != nil {
				rx.mu.Lock()
				rx.badSignature++
				rx.mu.Unlock()
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			rx.mu.Lock()
			rx.verified++
			rx.mu.Unlock()
		}

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

// stats reports how deliveries were authenticated.
func (rx *webhookRx) stats() (verified, badSignature, unauthorized int) {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	return rx.verified, rx.badSignature, rx.unauthorized
}
