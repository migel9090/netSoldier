//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// Step 125.18: detections that know which device they are about, and that
// arrive — through a burst, a receiver outage and a crash of the engine.

// switchableReceiver verifies the engine's credentials like the killswitch
// does and answers 503 while down is set, the way a restarting killswitch
// looks from outside.
type switchableReceiver struct {
	url   string
	down  atomic.Bool
	tries atomic.Int32
	mu    sync.Mutex
	got   []events.DetectionEvent
}

func startSwitchableReceiver(t *testing.T) *switchableReceiver {
	t.Helper()
	rx := &switchableReceiver{}
	ln := listenTCP(t)
	rx.url = "http://" + ln.Addr().String()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rx.tries.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer "+e2eAPIKey ||
			events.VerifyPayload(e2eWebhookSecret, r.Header.Get(events.SignatureHeader), body) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if rx.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var ev events.DetectionEvent
		if err := json.Unmarshal(body, &ev); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		rx.mu.Lock()
		rx.got = append(rx.got, ev)
		rx.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return rx
}

func (rx *switchableReceiver) events() []events.DetectionEvent {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	return append([]events.DetectionEvent(nil), rx.got...)
}

// startInventoryByIP stubs device-inventory's GET /devices/by-ip/{ip}
// (contract §5) for one device, bearer-authenticated.
func startInventoryByIP(t *testing.T, ip, mac, hostname string) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices/by-ip/{ip}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+e2eAPIKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.PathValue("ip") != ip {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"mac": mac, "ip": ip, "hostname": hostname})
	})
	ln := listenTCP(t)
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return "http://" + ln.Addr().String()
}

// startKillable starts bin like startProc does, but hands back the process
// so the test can SIGKILL it: a crash, not a clean shutdown.
func startKillable(t *testing.T, bin string, env map[string]string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return cmd
}

// storedAlert is the part of GET /alerts these tests read.
type storedAlert struct {
	ID         string `json:"id"`
	ClientMAC  string `json:"client_mac"`
	MatchedIoC string `json:"matched_ioc"`
}

func listAlerts(t *testing.T, addr string) []storedAlert {
	t.Helper()
	var out []storedAlert
	httpGetJSON(t, "http://"+addr+"/alerts?limit=1000", &out)
	return out
}

func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestBacklogSurvivesEngineCrashE2E: a detection made while the killswitch
// is unavailable stays in the engine's outbox across a SIGKILL, and the
// next process delivers that same event (same id) once the killswitch is
// back. The history the UI reads survives too.
func TestBacklogSurvivesEngineCrashE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	detBin := goBuild(t, repoRoot(t), "apps/detection-engine")
	tlFile := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(tlFile, []byte("evil.example.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var serving atomic.Bool
	serving.Store(true)
	ag := startMockAdGuardWith(t, serving.Load, map[string]any{
		"question": map[string]string{"host": "evil.example.com", "type": "A"},
		"client":   "192.168.1.42", "time": time.Now().Add(time.Hour),
	})
	rx := startSwitchableReceiver(t)
	rx.down.Store(true)
	inv := startInventoryByIP(t, "192.168.1.42", "aa:bb:cc:00:00:42", "kids-tablet")

	dbPath := filepath.Join(t.TempDir(), "state", "detection-engine.db")
	env := map[string]string{
		"ADGUARD_URL":                 ag.url,
		"ADGUARD_USER":                "admin",
		"ADGUARD_PASSWORD":            "test",
		"THREATLIST_PATH":             tlFile,
		"POLL_INTERVAL":               "1s",
		"WEBHOOK_URL":                 rx.url,
		"WEBHOOK_SECRET":              e2eWebhookSecret,
		"WEBHOOK_TOKEN":               e2eAPIKey,
		"DETECTION_API_KEY":           e2eAPIKey,
		"DEVICE_INVENTORY_URL":        inv,
		"DEVICE_API_KEY":              e2eAPIKey,
		"DB_PATH":                     dbPath,
		"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1",
	}

	// First process: detects, cannot deliver, is killed.
	env["LISTEN_ADDR"] = freeAddr(t)
	first := startKillable(t, detBin, env)
	waitHealthy(t, "http://"+env["LISTEN_ADDR"]+"/healthz")
	var alertID string
	eventually(t, "the detection to be recorded", 20*time.Second, func() bool {
		if a := listAlerts(t, env["LISTEN_ADDR"]); len(a) > 0 {
			alertID = a[0].ID
			return true
		}
		return false
	})
	eventually(t, "a refused delivery attempt", 20*time.Second, func() bool { return rx.tries.Load() > 0 })
	serving.Store(false) // nothing new for the next process to detect
	if err := first.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = first.Wait()
	t.Logf("first process killed with detection %s undelivered (%d refused attempts)", alertID, rx.tries.Load())

	// Second process: the killswitch is back.
	rx.down.Store(false)
	env["LISTEN_ADDR"] = freeAddr(t)
	stop := startProc(t, detBin, env)
	t.Cleanup(stop)
	waitHealthy(t, "http://"+env["LISTEN_ADDR"]+"/healthz")
	eventually(t, "the backlog to be delivered", 30*time.Second, func() bool { return len(rx.events()) > 0 })

	got := rx.events()
	if len(got) != 1 || got[0].ID != alertID {
		t.Fatalf("after the crash delivered %d event(s) %v, want exactly %s", len(got), ids(got), alertID)
	}
	if got[0].ClientMAC != "aa:bb:cc:00:00:42" || got[0].ClientName != "kids-tablet" {
		t.Errorf("client_mac=%q client_name=%q, want the inventory's device", got[0].ClientMAC, got[0].ClientName)
	}
	if err := got[0].Validate(); err != nil {
		t.Errorf("delivered event breaks the contract: %v", err)
	}
	if a := listAlerts(t, env["LISTEN_ADDR"]); len(a) != 1 || a[0].ID != alertID || a[0].ClientMAC != "aa:bb:cc:00:00:42" {
		t.Errorf("history after the crash = %+v, want [%s] with its MAC", a, alertID)
	}
	t.Logf("second process delivered %s, client_mac=%s", got[0].ID, got[0].ClientMAC)
}

// TestFloodDoesNotMaskCriticalDetectionE2E: a device makes its real C2
// lookup and then 250 lookups under a low-confidence listed domain within
// one poll, while the killswitch is briefly unavailable. Everything is
// recorded; the 250 repeats become one event; the critical detection is the
// first one delivered.
func TestFloodDoesNotMaskCriticalDetectionE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e in short mode")
	}
	detBin := goBuild(t, repoRoot(t), "apps/detection-engine")

	var mu sync.Mutex
	var exportedAt time.Time
	tiMux := http.NewServeMux()
	tiMux.HandleFunc("GET /export/json", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		if exportedAt.IsZero() {
			exportedAt = time.Now()
		}
		mu.Unlock()
		fmt.Fprint(w, `[{"Type":"domain","Value":"c2.real-threat.example","Source":"threatfox","Confidence":100,"Threat":"AsyncRAT"},
			{"Type":"domain","Value":"old-urlhaus-host.example","Source":"urlhaus","Confidence":0}]`)
	})
	tiLn := listenTCP(t)
	tiSrv := &http.Server{Handler: tiMux}
	go tiSrv.Serve(tiLn)
	t.Cleanup(func() { tiSrv.Close() })
	ready := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return !exportedAt.IsZero() && time.Since(exportedAt) > 1500*time.Millisecond
	}

	// Newest first, as AdGuard serves it: the junk, then the C2 lookup.
	base := time.Now().Add(time.Hour)
	var entries []map[string]any
	for i := 249; i >= 0; i-- {
		entries = append(entries, map[string]any{
			"question": map[string]string{"host": fmt.Sprintf("n%d.old-urlhaus-host.example", i), "type": "A"},
			"client":   "192.168.1.66", "time": base.Add(time.Duration(i+1) * time.Millisecond),
		})
	}
	entries = append(entries, map[string]any{
		"question": map[string]string{"host": "c2.real-threat.example", "type": "A"},
		"client":   "192.168.1.66", "time": base,
	})
	ag := startMockAdGuardWith(t, ready, entries...)
	rx := startSwitchableReceiver(t)
	rx.down.Store(true)
	inv := startInventoryByIP(t, "192.168.1.66", "aa:bb:cc:00:00:66", "kids-tablet")

	addr := freeAddr(t)
	stop := startProc(t, detBin, map[string]string{
		"LISTEN_ADDR":                 addr,
		"ADGUARD_URL":                 ag.url,
		"ADGUARD_USER":                "admin",
		"ADGUARD_PASSWORD":            "test",
		"THREATLIST_PATH":             "/nonexistent",
		"THREAT_INTEL_URL":            "http://" + tiLn.Addr().String(),
		"POLL_INTERVAL":               "1s",
		"WEBHOOK_URL":                 rx.url,
		"WEBHOOK_SECRET":              e2eWebhookSecret,
		"WEBHOOK_TOKEN":               e2eAPIKey,
		"DETECTION_API_KEY":           e2eAPIKey,
		"DEVICE_INVENTORY_URL":        inv,
		"DEVICE_API_KEY":              e2eAPIKey,
		"DB_PATH":                     filepath.Join(t.TempDir(), "detection-engine.db"),
		"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1",
	})
	t.Cleanup(stop)
	waitHealthy(t, "http://"+addr+"/healthz")

	eventually(t, "all 251 detections to be recorded", 40*time.Second, func() bool {
		return len(listAlerts(t, addr)) == 251
	})
	rx.down.Store(false) // the killswitch is back
	eventually(t, "the critical and the aggregated detection to arrive", 60*time.Second, func() bool {
		return len(rx.events()) >= 2
	})
	time.Sleep(2 * time.Second) // anything else that was going to arrive

	got := rx.events()
	counts := map[string]int{}
	for _, ev := range got {
		counts[ev.MatchedIoC]++
	}
	t.Logf("recorded 251 detections; delivered %d: critical C2=%d, junk=%d (of 250 hits), first=%s (%s)",
		len(got), counts["c2.real-threat.example"], counts["old-urlhaus-host.example"], got[0].MatchedIoC, got[0].Severity)
	if counts["c2.real-threat.example"] != 1 || counts["old-urlhaus-host.example"] != 1 || len(got) != 2 {
		t.Fatalf("delivered %v, want the critical detection once and the junk aggregated into one", counts)
	}
	if got[0].MatchedIoC != "c2.real-threat.example" || got[0].Severity != events.SeverityCritical {
		t.Errorf("first delivery = %s (%s), want the critical detection", got[0].MatchedIoC, got[0].Severity)
	}
	for _, ev := range got {
		if ev.ClientMAC != "aa:bb:cc:00:00:66" {
			t.Errorf("%s delivered with client_mac %q", ev.ID, ev.ClientMAC)
		}
	}
	for _, a := range listAlerts(t, addr) {
		if a.ClientMAC != "aa:bb:cc:00:00:66" {
			t.Fatalf("recorded alert %s has client_mac %q", a.ID, a.ClientMAC)
		}
	}
}

func ids(evs []events.DetectionEvent) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.ID
	}
	return out
}
