package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/capture"
	"github.com/migel9090/netSoldier/apps/netagent/internal/config"
	"github.com/migel9090/netSoldier/apps/netagent/internal/forward"
	"github.com/migel9090/netSoldier/apps/netagent/internal/peer"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeHealth(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "health.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The probe must accept exactly what the running agent writes: the image has
// no shell, so `netagent health` is the only way a kubelet exec probe can
// tell a live agent from a hung one (deploy/kustomize/base/netagent).
func TestHealthCheckAcceptsWhatTheAgentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	cfg := config.Config{Agent: "node-1", HealthFile: path, Heartbeat: time.Second}
	lo := &net.Interface{Index: 1, Name: "lo"}
	queue := forward.NewQueue(4)
	capt := capture.New(lo, nil, queue)
	inv := peer.New("device-inventory", "http://127.0.0.1:1/agent/v1/frames", "t", time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	stop := startHealth(ctx, cfg, capt, queue, inv, nil)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the agent wrote no health file")
		}
		time.Sleep(10 * time.Millisecond)
	}

	var out bytes.Buffer
	env := envMap(map[string]string{"NETAGENT_HEALTH_FILE": path, "NETAGENT_HEARTBEAT": "1s"})
	if code := runHealthCheck(env, time.Now(), &out); code != 0 {
		t.Fatalf("fresh health file judged unhealthy (%d): %s", code, out.String())
	}
	if !strings.Contains(out.String(), "node-1") {
		t.Errorf("output does not name the agent: %q", out.String())
	}

	cancel()
	stop()
	out.Reset()
	if code := runHealthCheck(env, time.Now(), &out); code == 0 {
		t.Fatalf("health file of a stopped agent judged healthy: %s", out.String())
	}
}

func TestHealthCheckRejects(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	fresh := writeHealth(t, `{"agent":"a","time":"2026-11-16T11:59:55Z"}`)
	cases := []struct {
		name string
		env  map[string]string
	}{
		{"no health file configured", map[string]string{}},
		{"missing file", map[string]string{"NETAGENT_HEALTH_FILE": filepath.Join(t.TempDir(), "absent.json")}},
		{"not JSON", map[string]string{"NETAGENT_HEALTH_FILE": writeHealth(t, "not json")}},
		{"no time", map[string]string{"NETAGENT_HEALTH_FILE": writeHealth(t, `{"agent":"a"}`)}},
		// Three default heartbeats is 9 s, below the 10 s floor: 11 s is stale.
		{"stale", map[string]string{"NETAGENT_HEALTH_FILE": writeHealth(t, `{"agent":"a","time":"2026-11-16T11:59:49Z"}`)}},
		{"stale for a short heartbeat", map[string]string{
			"NETAGENT_HEALTH_FILE": writeHealth(t, `{"agent":"a","time":"2026-11-16T11:59:30Z"}`),
			"NETAGENT_HEARTBEAT":   "5s"}},
		{"bad heartbeat", map[string]string{"NETAGENT_HEALTH_FILE": fresh, "NETAGENT_HEARTBEAT": "soon"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			if code := runHealthCheck(envMap(tc.env), now, &out); code != 1 {
				t.Fatalf("exit %d, want 1: %s", code, out.String())
			}
			if !strings.HasPrefix(out.String(), "unhealthy: ") {
				t.Errorf("output %q does not say unhealthy", out.String())
			}
		})
	}

	var out bytes.Buffer
	if code := runHealthCheck(envMap(map[string]string{"NETAGENT_HEALTH_FILE": fresh}), now, &out); code != 0 {
		t.Fatalf("a file written 5 s ago is healthy, got %d: %s", code, out.String())
	}
	slow := map[string]string{"NETAGENT_HEALTH_FILE": writeHealth(t, `{"agent":"a","time":"2026-11-16T11:59:40Z"}`),
		"NETAGENT_HEARTBEAT": "10s"}
	if code := runHealthCheck(envMap(slow), now, &out); code != 0 {
		t.Fatalf("20 s is within three 10 s heartbeats, got %d: %s", code, out.String())
	}
}

// Only `netagent` and `netagent health` are accepted: a mistyped probe
// command must not start a second agent with raw network access.
func TestSubcommand(t *testing.T) {
	now := func() time.Time { return time.Now() }
	var out, errOut bytes.Buffer
	if _, handled := subcommand(nil, envMap(nil), now, &out, &errOut); handled {
		t.Fatal("no argument must run the agent")
	}
	if code, handled := subcommand([]string{"health"}, envMap(nil), now, &out, &errOut); !handled || code != 1 {
		t.Fatalf("health without a file: handled=%v code=%d, want handled and 1", handled, code)
	}
	for _, args := range [][]string{{"healthz"}, {"health", "extra"}, {"-h"}} {
		if code, handled := subcommand(args, envMap(nil), now, &out, &errOut); !handled || code != 2 {
			t.Errorf("%q: handled=%v code=%d, want handled and 2", args, handled, code)
		}
	}
}

// TestHealthCheckRejectsAFutureStamp: a file stamped ahead of the clock
// passed as "fresh" (a negative age) for as long as it stayed ahead — after
// the clock stepped back, a stopped agent's last file kept the probe green.
// Within the limit it is still healthy: the next heartbeat corrects it.
func TestHealthCheckRejectsAFutureStamp(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for stamp, want := range map[string]int{
		"2026-11-16T12:00:05Z": 0, // within three heartbeats (10 s floor)
		"2026-11-16T12:01:00Z": 1,
		"2027-11-16T12:00:00Z": 1,
	} {
		var out bytes.Buffer
		env := envMap(map[string]string{"NETAGENT_HEALTH_FILE": writeHealth(t, `{"agent":"a","time":"`+stamp+`"}`)})
		if code := runHealthCheck(env, now, &out); code != want {
			t.Errorf("stamped %s at %s: exit %d, want %d (%s)", stamp, now.Format(time.RFC3339), code, want,
				strings.TrimSpace(out.String()))
		}
		if want == 1 && (!strings.HasPrefix(out.String(), "unhealthy: ") || strings.Count(out.String(), "\n") != 1) {
			t.Errorf("want a one-line reason, got %q", out.String())
		}
	}
}
