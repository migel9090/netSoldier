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
	e2eAPIKey        = "e2e-api-key"
	e2eWebhookSecret = "e2e-webhook-secret"
)

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

// httpPostJSON posts to an authenticated endpoint. The token is sent
// unconditionally because the services now run with auth enabled in e2e —
// the production posture, which no earlier run exercised.
func httpPostJSON(t *testing.T, url string, body any, dst any) {
	t.Helper()
	postAuthedJSON(t, url, e2eAPIKey, body, dst)
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
	// are authenticated by the bearer token alone.
	if strings.HasSuffix(url, "/evaluate") {
		req.Header.Set(events.SignatureHeader, events.SignPayload(e2eWebhookSecret, data))
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
	m := &mockAdGuard{}
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
