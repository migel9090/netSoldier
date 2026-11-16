package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
)

func noLookup(context.Context, string) ([]netip.Addr, error) {
	return nil, errors.New("lookup not expected")
}

// TestInfrastructureIsProtectedWithoutBeingListed: only what the operator
// typed into the allowlist was protected; the sensor's own addresses and the
// DNS server it enforces through were fair game for the device drivers.
func TestInfrastructureIsProtectedWithoutBeingListed(t *testing.T) {
	pol := policy.DefaultPolicy()
	if err := protectInfrastructure(context.Background(), pol, "http://192.0.2.53:3000", noLookup); err != nil {
		t.Fatal(err)
	}
	if !pol.Infrastructure.Contains("", "192.0.2.53") {
		t.Error("the DNS server named by ADGUARD_URL must be protected")
	}
	if !pol.Infrastructure.Contains("", "127.0.0.1") {
		t.Error("the sensor's own interface addresses must be protected")
	}
	if pol.Infrastructure.Contains("", "127.0.0.2") {
		t.Error("only the interface's own address is protected, not its whole subnet")
	}
	if pol.Allowlist.Len() != 0 || pol.AutoBlockEnabled() {
		t.Error("discovered infrastructure must not stand in for an operator allowlist")
	}

	guard, err := buildGuard(pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.Check("02:00:00:00:00:01", "192.0.2.53"); err == nil {
		t.Error("the guard must refuse the DNS server")
	}
}

func TestDNSServerResolvedByName(t *testing.T) {
	pol := policy.DefaultPolicy()
	lookup := func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != "adguard.lan" {
			t.Errorf("looked up %q", host)
		}
		return []netip.Addr{netip.MustParseAddr("::ffff:192.0.2.54")}, nil
	}
	if err := protectInfrastructure(context.Background(), pol, "http://adguard.lan:3000", lookup); err != nil {
		t.Fatal(err)
	}
	if !pol.Infrastructure.Contains("", "192.0.2.54") {
		t.Error("resolved DNS server address not protected")
	}

	// When the DNS server cannot be determined, the device drivers are not offered.
	failed := protectInfrastructure(context.Background(), policy.DefaultPolicy(), "http://adguard.lan:3000",
		func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") })
	if failed == nil {
		t.Fatal("an unresolvable DNS server must be reported")
	}
	pinned := policy.DefaultPolicy()
	pinned.GatewayIP, pinned.GatewayMAC = netip.MustParseAddr("192.168.1.1"), "aa:00:00:00:00:01"
	if err := deviceDriverReady(pinned, failed); err == nil {
		t.Error("device drivers must be withheld while infrastructure is incomplete")
	}
	if err := deviceDriverReady(pinned, nil); err != nil {
		t.Errorf("pinned gateway and complete infrastructure: %v", err)
	}
	pinned.GatewayMAC = ""
	if err := deviceDriverReady(pinned, nil); err == nil || !strings.Contains(err.Error(), "GATEWAY_MAC") {
		t.Errorf("a gateway pinned by IP alone is not enough for a device driver: %v", err)
	}
}

func TestBuildGuardCoversAllowlistAndGateway(t *testing.T) {
	t.Setenv("ALLOWLIST_IPS", "192.168.1.0/29")
	t.Setenv("ALLOWLIST_MACS", "AA-BB-CC-DD-EE-FF")
	t.Setenv("GATEWAY_IP", "10.0.0.1")
	t.Setenv("GATEWAY_MAC", "aa:00:00:00:00:01")
	pol, err := policy.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	guard, err := buildGuard(pol)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ mac, ip string }{
		{"02:00:00:00:00:09", "192.168.1.5"},
		{"aa:bb:cc:dd:ee:ff", "192.168.1.50"},
		{"02:00:00:00:00:09", "10.0.0.1"},
		{"aa:00:00:00:00:01", "192.168.1.50"},
	} {
		if err := guard.Check(tc.mac, tc.ip); err == nil {
			t.Errorf("%s / %s is protected and must be refused", tc.mac, tc.ip)
		}
	}
	if err := guard.Check("02:00:00:00:00:09", "192.168.1.50"); err != nil {
		t.Errorf("an unprotected device passes: %v", err)
	}
}

// ---- the real main(), in a subprocess --------------------------------------

// TestMainSubprocess is not a test: the start-up tests re-run the test
// binary with this one selected to execute main() as the service would.
func TestMainSubprocess(t *testing.T) {
	if os.Getenv("KILLSWITCH_TEST_RUN_MAIN") != "1" {
		t.Skip("helper process for the start-up tests")
	}
	main()
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// lockedBuffer collects a subprocess's output while the test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func startMain(t *testing.T, env map[string]string) (*exec.Cmd, *lockedBuffer) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMainSubprocess$")
	cmd.Env = append(os.Environ(), "KILLSWITCH_TEST_RUN_MAIN=1",
		// never reach for a real DNS server or AdGuard from a test
		"ADGUARD_URL=http://127.0.0.1:1", "CLICKHOUSE_URL=",
		"KILLSWITCH_DB_PATH="+filepath.Join(t.TempDir(), "ks.db"))
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd, out
}

func secureEnv(addr string) map[string]string {
	return map[string]string{
		"LISTEN_ADDR":             addr,
		"KILLSWITCH_API_KEY":      "op",
		"KILLSWITCH_INGEST_TOKEN": "in",
		"WEBHOOK_SECRET":          "s",
		"ALLOWLIST_IPS":           "192.168.1.1",
	}
}

// TestServiceRefusesToStart: each of these used to start with a log line —
// the router unprotected, or authentication silently off.
func TestServiceRefusesToStart(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"allowlist typo", map[string]string{"ALLOWLIST_MACS": "aa:bb:cc:dd:ee:fg"}, `aa:bb:cc:dd:ee:fg`},
		{"gateway MAC typo", map[string]string{"GATEWAY_MAC": "aa:00:00:00:00:0g"}, `GATEWAY_MAC entry`},
		{"no ingest token", map[string]string{"KILLSWITCH_INGEST_TOKEN": ""}, "KILLSWITCH_INGEST_TOKEN"},
		{"no operator token", map[string]string{"KILLSWITCH_API_KEY": ""}, "KILLSWITCH_API_KEY"},
		{"one key for both roles", map[string]string{"KILLSWITCH_INGEST_TOKEN": "op"}, "same value"},
		{"agent shares the operator token", map[string]string{"NETAGENT_KILLSWITCH_TOKEN": "op"}, "NETAGENT_KILLSWITCH_TOKEN must differ"},
		// Without its database the service cannot know what it enforces.
		{"database cannot be opened", map[string]string{"KILLSWITCH_DB_PATH": "/proc/killswitch/ks.db"}, "action database"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := secureEnv(freeTCPAddr(t))
			for k, v := range tc.env {
				env[k] = v
			}
			cmd, out := startMain(t, env)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("exit = %v, want status 1\n%s", err, out)
				}
			case <-time.After(20 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatalf("the service started:\n%s", out)
			}
			if !strings.Contains(out.String(), "refusing to start") || !strings.Contains(out.String(), tc.want) {
				t.Errorf("start-up refusal should name %q:\n%s", tc.want, out)
			}
		})
	}
}

// TestPendingOnlyStartIsVisibleInMetrics: with the explicit override the
// service starts, says so, and shows it on /metrics.
func TestPendingOnlyStartIsVisibleInMetrics(t *testing.T) {
	addr := freeTCPAddr(t)
	env := secureEnv(addr)
	env["ALLOWLIST_MACS"] = "aa:bb:cc:dd:ee:fg"
	env["ALLOWLIST_ON_INVALID"] = policy.OnInvalidPendingOnly
	cmd, out := startMain(t, env)
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	})

	var metrics string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/metrics")
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			metrics = string(b)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if metrics == "" {
		t.Fatalf("service did not come up:\n%s", out)
	}
	for _, want := range []string{"killswitch_protection_entries_rejected 1", "killswitch_auto_block_enabled 0",
		`killswitch_auto_block_withheld_total{reason="invalid_protection_config"} 0`} {
		if !strings.Contains(metrics, want) {
			t.Errorf("/metrics should contain %q", want)
		}
	}
	if !strings.Contains(out.String(), "auto-block DISABLED") {
		t.Errorf("start-up should say auto-block is disabled:\n%s", out)
	}
}
