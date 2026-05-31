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

func httpPostJSON(t *testing.T, url string, body any, dst any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
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
