package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/feedback"
	"github.com/migel9090/netSoldier/libs/events"
)

const (
	testSecret = "wh-secret"
	testToken  = "wh-token"
	testDevKey = "dev-key"
	testAPIKey = "api-key"
)

// These tests run the service's real wiring — run() — against stub
// neighbours. Unit tests that hand-built alerts with MACs are how an
// enrichment hook nobody assigned went unnoticed.

// querylog serves AdGuard's /control/querylog with one lookup of a listed
// name, until serving is switched off.
type querylog struct {
	u       string
	serving atomic.Bool
}

func startQuerylog(t *testing.T, client string) *querylog {
	entries := []map[string]any{{
		"question": map[string]string{"host": "evil.example.com", "type": "A"},
		"client":   client, "time": time.Now().Add(time.Minute),
	}}
	q := &querylog{}
	q.serving.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		data := []map[string]any{}
		if q.serving.Load() {
			data = entries
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(srv.Close)
	q.u = srv.URL
	return q
}

func (q *querylog) url() string { return q.u }

type inventoryStub struct {
	url   string
	auths atomic.Int32
}

// startInventory serves device-inventory's GET /devices/by-ip/{ip}
// (contract §5) for one device.
func startInventory(t *testing.T, ip, mac, hostname string) *inventoryStub {
	inv := &inventoryStub{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices/by-ip/{ip}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testDevKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inv.auths.Add(1)
		if r.PathValue("ip") != ip {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"mac": mac, "ip": ip, "hostname": hostname})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	inv.url = srv.URL
	return inv
}

type receiverStub struct {
	url    string
	status atomic.Int32
	tries  atomic.Int32
	mu     sync.Mutex
	got    []events.DetectionEvent
}

func startReceiver(t *testing.T) *receiverStub {
	rx := &receiverStub{}
	rx.status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rx.tries.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Authorization") != "Bearer "+testToken ||
			events.VerifyPayload(testSecret, r.Header.Get(events.SignatureHeader), body) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		code := int(rx.status.Load())
		if code == http.StatusOK {
			var ev events.DetectionEvent
			_ = json.Unmarshal(body, &ev)
			rx.mu.Lock()
			rx.got = append(rx.got, ev)
			rx.mu.Unlock()
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	rx.url = srv.URL
	return rx
}

func (rx *receiverStub) events() []events.DetectionEvent {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	return append([]events.DetectionEvent(nil), rx.got...)
}

func baseEnv(t *testing.T, q *querylog, rx *receiverStub, invURL, dbPath string) map[string]string {
	tl := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(tl, []byte("evil.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"LISTEN_ADDR":          "127.0.0.1:0",
		"ADGUARD_URL":          q.url(),
		"ADGUARD_USER":         "admin",
		"ADGUARD_PASSWORD":     "test",
		"THREATLIST_PATH":      tl,
		"POLL_INTERVAL":        "100ms",
		"WEBHOOK_URL":          rx.url,
		"WEBHOOK_SECRET":       testSecret,
		"WEBHOOK_TOKEN":        testToken,
		"DEVICE_INVENTORY_URL": invURL,
		"DEVICE_API_KEY":       testDevKey,
		"DETECTION_API_KEY":    testAPIKey,
		"DB_PATH":              dbPath,
	}
}

// start runs the service; the returned stop cancels it and returns run's
// error once it has shut down.
func start(t *testing.T, env map[string]string) (addr string, stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx, func(k string) string { return env[k] }, func(a string) { addrCh <- a })
	}()
	select {
	case addr = <-addrCh:
	case err := <-errCh:
		cancel()
		t.Fatalf("run exited before listening: %v", err)
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("run did not start listening")
	}
	var once sync.Once
	var runErr error
	stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case runErr = <-errCh:
			case <-time.After(20 * time.Second):
				t.Fatal("run did not shut down")
			}
		})
		return runErr
	}
	t.Cleanup(func() { _ = stop() })
	return addr, stop
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func getAlerts(t *testing.T, addr string) []detection.Alert {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/alerts?limit=10")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []detection.Alert
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRunEnrichesDetectionsWithDeviceIdentity: what the killswitch receives,
// and what GET /alerts shows, carries the MAC and name device-inventory
// reports for the client address.
func TestRunEnrichesDetectionsWithDeviceIdentity(t *testing.T) {
	q := startQuerylog(t, "192.168.1.42")
	inv := startInventory(t, "192.168.1.42", "AA:BB:CC:00:00:42", "kids-tablet")
	rx := startReceiver(t)
	addr, stop := start(t, baseEnv(t, q, rx, inv.url, filepath.Join(t.TempDir(), "de.db")))

	waitFor(t, "a delivered detection", func() bool { return len(rx.events()) > 0 })
	ev := rx.events()[0]
	if ev.ClientMAC != "aa:bb:cc:00:00:42" || ev.ClientName != "kids-tablet" {
		t.Errorf("delivered client_mac=%q client_name=%q, want the inventory's device", ev.ClientMAC, ev.ClientName)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("delivered event breaks the contract: %v", err)
	}
	if inv.auths.Load() == 0 {
		t.Error("the inventory was never asked with DEVICE_API_KEY")
	}

	alerts := getAlerts(t, addr)
	if len(alerts) == 0 || alerts[0].ClientMAC != "aa:bb:cc:00:00:42" || alerts[0].ID != ev.ID {
		t.Errorf("GET /alerts = %+v, want the delivered detection with its MAC", alerts)
	}
	if err := stop(); err != nil {
		t.Errorf("clean shutdown returned %v", err)
	}
}

// TestRunKeepsHistoryAndBacklogAcrossRestart: a detection made while the
// killswitch is down is delivered by the next process, and the history
// still lists it.
func TestRunKeepsHistoryAndBacklogAcrossRestart(t *testing.T) {
	q := startQuerylog(t, "192.168.1.42")
	inv := startInventory(t, "192.168.1.42", "aa:bb:cc:00:00:42", "kids-tablet")
	rx := startReceiver(t)
	rx.status.Store(http.StatusServiceUnavailable)
	env := baseEnv(t, q, rx, inv.url, filepath.Join(t.TempDir(), "de.db"))

	addr, stop := start(t, env)
	waitFor(t, "a recorded alert", func() bool { return len(getAlerts(t, addr)) > 0 })
	waitFor(t, "a refused delivery attempt", func() bool { return rx.tries.Load() > 0 })
	id := getAlerts(t, addr)[0].ID
	q.serving.Store(false) // the querylog has nothing new for the next process
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if n := len(rx.events()); n != 0 {
		t.Fatalf("receiver accepted %d events while refusing", n)
	}

	rx.status.Store(http.StatusOK)
	addr2, _ := start(t, env)
	waitFor(t, "the backlog to be delivered", func() bool { return len(rx.events()) > 0 })
	if got := rx.events(); len(got) != 1 || got[0].ID != id || got[0].ClientMAC != "aa:bb:cc:00:00:42" {
		t.Fatalf("after restart delivered %+v, want exactly the earlier detection %s", got, id)
	}
	if alerts := getAlerts(t, addr2); len(alerts) != 1 || alerts[0].ID != id {
		t.Errorf("history after restart = %+v, want the earlier alert", alerts)
	}
}

// TestRunDoesNotRedetectAfterRestart: a restart resumes the querylog a little
// behind where it stopped, and re-reads more when the stored position is lost
// (a crash before it was written). Either way the lookup the first process
// already detected and delivered is not detected, recorded or delivered
// again — while one logged during the downtime is.
func TestRunDoesNotRedetectAfterRestart(t *testing.T) {
	logged := time.Now().Add(-2 * time.Second)
	var mu sync.Mutex
	entries := []map[string]any{{
		"question": map[string]string{"host": "evil.example.com", "type": "A"},
		"client":   "192.168.1.42", "time": logged,
	}}
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": entries})
	}))
	t.Cleanup(ag.Close)
	q := &querylog{u: ag.URL}
	inv := startInventory(t, "192.168.1.42", "aa:bb:cc:00:00:42", "kids-tablet")
	rx := startReceiver(t)
	dbPath := filepath.Join(t.TempDir(), "de.db")
	env := baseEnv(t, q, rx, inv.url, dbPath)

	_, stop := start(t, env)
	waitFor(t, "the first delivery", func() bool { return len(rx.events()) == 1 })
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	first := rx.events()[0].ID

	for _, lostPosition := range []bool{false, true} {
		if lostPosition {
			db, err := sql.Open("sqlite", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`DELETE FROM ingest_cursors`); err != nil {
				t.Fatal(err)
			}
			db.Close()
		}
		// Metrics are per test binary, not per run: measure from here.
		addr, stop := start(t, env)
		pages := metric(t, addr, "detection_engine_querylog_pages_total")
		replays := metric(t, addr, "detection_engine_replayed_detections_total")
		waitFor(t, "a few polls", func() bool {
			return metric(t, addr, "detection_engine_querylog_pages_total") >= pages+5
		})
		if got := rx.events(); len(got) != 1 {
			t.Fatalf("lost position=%v: %d deliveries %v, want only the first", lostPosition, len(got), got)
		}
		if a := getAlerts(t, addr); len(a) != 1 || a[0].ID != first {
			t.Fatalf("lost position=%v: history %+v, want only %s", lostPosition, a, first)
		}
		if n := metric(t, addr, "detection_engine_replayed_detections_total") - replays; n != 1 {
			t.Errorf("lost position=%v: re-reads recognised %v times, want once (then the overlap's seen set)", lostPosition, n)
		}
		if err := stop(); err != nil {
			t.Fatal(err)
		}
	}

	// Logged while nothing was running, by another device (the same device
	// and name within ten minutes is folded into the first delivery by the
	// outbox): detected by the next start.
	mu.Lock()
	entries = append([]map[string]any{{
		"question": map[string]string{"host": "evil.example.com", "type": "A"},
		"client":   "192.168.1.43", "time": time.Now().Add(-time.Second),
	}}, entries...)
	mu.Unlock()
	start(t, env)
	waitFor(t, "the lookup made while down", func() bool { return len(rx.events()) == 2 })
	if got := rx.events(); got[1].ID == first {
		t.Errorf("the new lookup reused the first id")
	}
}

// TestRunWithoutInventoryStillDelivers: identity is best effort. An
// unreachable inventory costs the MAC, never the detection, and is counted.
func TestRunWithoutInventoryStillDelivers(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()

	q := startQuerylog(t, "192.168.1.42")
	rx := startReceiver(t)
	addr, _ := start(t, baseEnv(t, q, rx, goneURL, filepath.Join(t.TempDir(), "de.db")))

	waitFor(t, "a delivered detection", func() bool { return len(rx.events()) > 0 })
	if ev := rx.events()[0]; ev.ClientMAC != "" {
		t.Errorf("client_mac = %q with no inventory", ev.ClientMAC)
	}
	if n := metric(t, addr, `detection_engine_device_lookup_failures_total{reason="unreachable"}`); n < 1 {
		t.Errorf("unreachable lookups counted %v, want >= 1", n)
	}
	if n := metric(t, addr, `detection_engine_store_durable`); n != 1 {
		t.Errorf("store_durable = %v with DB_PATH set", n)
	}
}

// TestRunFeedbackTakesClassFromStoredAlert: the web UI posts alert_id,
// matched_ioc and client_ip; the verdict is scoped to the class of the
// alert the analyst looked at, which the store still has.
func TestRunFeedbackTakesClassFromStoredAlert(t *testing.T) {
	q := startQuerylog(t, "192.168.1.42")
	rx := startReceiver(t)
	inv := startInventory(t, "192.168.1.42", "aa:bb:cc:00:00:42", "kids-tablet")
	addr, _ := start(t, baseEnv(t, q, rx, inv.url, filepath.Join(t.TempDir(), "de.db")))
	waitFor(t, "a recorded alert", func() bool { return len(getAlerts(t, addr)) > 0 })
	a := getAlerts(t, addr)[0]

	body, _ := json.Marshal(map[string]string{"alert_id": a.ID, "matched_ioc": a.MatchedIoC,
		"client_ip": a.ClientIP, "verdict": "false_positive", "timestamp": "2099-01-01T00:00:00Z"})
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/feedback", strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("X-Netsoldier-Actor", "analyst")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /feedback = %d", resp.StatusCode)
	}

	resp, err = http.Get("http://" + addr + "/feedback")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var active []map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&active)
	if len(active) != 1 || active[0]["signal_class"] != "ioc" {
		t.Fatalf("active suppressions = %v, want one scoped to class ioc", active)
	}
	if ts, _ := time.Parse(time.RFC3339Nano, active[0]["timestamp"].(string)); ts.Year() != time.Now().Year() {
		t.Errorf("verdict timestamp %v: the caller's 2099 was used", ts)
	}
}

// postJSON sends an authenticated operator POST and decodes the answer.
func postJSON(t *testing.T, addr, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, "http://"+addr+path, strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	req.Header.Set("X-Netsoldier-Actor", "analyst")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func getSuppressions(t *testing.T, addr string) []map[string]any {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/feedback")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestRunVerdictSurvivesRestartWithoutClickHouse is the lite profile: no
// ClickHouse. POST /feedback answered persisted=true while the verdict was
// only in memory, and after a restart the detection the analyst had marked
// benign reached the killswitch again. Now the verdict is in the local
// store, and the next process still suppresses it — until it is lifted.
func TestRunVerdictSurvivesRestartWithoutClickHouse(t *testing.T) {
	var mu sync.Mutex
	entries := []map[string]any{{
		"question": map[string]string{"host": "evil.example.com", "type": "A"},
		"client":   "192.168.1.42", "time": time.Now().Add(-time.Second),
	}}
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"data": entries})
	}))
	t.Cleanup(ag.Close)
	inv := startInventory(t, "192.168.1.42", "aa:bb:cc:00:00:42", "kids-tablet")
	rx := startReceiver(t)
	env := baseEnv(t, &querylog{u: ag.URL}, rx, inv.url, filepath.Join(t.TempDir(), "de.db"))

	addr, stop := start(t, env)
	waitFor(t, "a recorded alert", func() bool { return len(getAlerts(t, addr)) > 0 })
	a := getAlerts(t, addr)[0]
	status, resp := postJSON(t, addr, "/feedback", map[string]string{"alert_id": a.ID,
		"matched_ioc": a.MatchedIoC, "client_ip": a.ClientIP, "verdict": "false_positive"})
	if status != http.StatusAccepted || resp["persisted"] != true {
		t.Fatalf("POST /feedback = %d %v, want 202 persisted", status, resp)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}

	// The device looks the name up again while nothing is running.
	mu.Lock()
	entries = append([]map[string]any{{
		"question": map[string]string{"host": "evil.example.com", "type": "A"},
		"client":   "192.168.1.42", "time": time.Now(),
	}}, entries...)
	mu.Unlock()

	addr, stop = start(t, env)
	sup := getSuppressions(t, addr)
	if len(sup) != 1 || sup[0]["matched_ioc"] != a.MatchedIoC || sup[0]["analyst"] != "analyst" {
		t.Fatalf("GET /feedback after restart = %v, want the verdict", sup)
	}
	recorded, _ := time.Parse(time.RFC3339Nano, sup[0]["timestamp"].(string))
	expires, err := time.Parse(time.RFC3339Nano, fmt.Sprint(sup[0]["expires_at"]))
	if err != nil || !expires.Equal(recorded.Add(feedback.DefaultSuppressionTTL)) {
		t.Errorf("expires_at %v, want the verdict's time + the TTL (%v)", sup[0]["expires_at"], err)
	}
	suppressed := metric(t, addr, "detection_engine_alerts_suppressed_total")
	waitFor(t, "the new lookup to be detected", func() bool { return len(getAlerts(t, addr)) >= 2 })
	if n := metric(t, addr, "detection_engine_alerts_suppressed_total"); n <= suppressed {
		t.Fatalf("the detection after the restart was not suppressed (%v -> %v)", suppressed, n)
	}

	// Lifting it is explicit, authenticated, and lasts across a restart too.
	anon, err := http.Post("http://"+addr+"/feedback/lift", "application/json",
		strings.NewReader(`{"matched_ioc":"`+a.MatchedIoC+`","client_ip":"`+a.ClientIP+`","signal_class":"ioc"}`))
	if err != nil {
		t.Fatal(err)
	}
	anon.Body.Close()
	if anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated lift was answered %d", anon.StatusCode)
	}
	status, resp = postJSON(t, addr, "/feedback/lift", map[string]string{"matched_ioc": a.MatchedIoC,
		"client_ip": a.ClientIP, "signal_class": a.SignalClass})
	if status != http.StatusOK || resp["status"] != "lifted" || resp["persisted"] != true {
		t.Fatalf("POST /feedback/lift = %d %v", status, resp)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	addr, _ = start(t, env)
	if sup := getSuppressions(t, addr); len(sup) != 0 {
		t.Errorf("GET /feedback after the lift and a restart = %v", sup)
	}
}

func TestRunRefusesUnusableDBPath(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"DB_PATH": filepath.Join(blocker, "de.db"), "LISTEN_ADDR": "127.0.0.1:0"}
	err := run(context.Background(), func(k string) string { return env[k] }, nil)
	if err == nil || !strings.Contains(err.Error(), "DB_PATH") {
		t.Fatalf("run = %v, want a DB_PATH error: an explicitly configured store must not silently become memory", err)
	}
}

// TestNoPacketCaptureInTheBinary: the in-process capture derived flow
// direction from the sort order of address strings, kept an unbounded flow
// table and needed raw-socket capability. It is gone; flows come from Zeek
// conn.log. Nothing linked into the service may bring it back.
func TestNoPacketCaptureInTheBinary(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info in this test binary")
	}
	for _, dep := range info.Deps {
		if strings.Contains(dep.Path, "gopacket") || strings.Contains(dep.Path, "pcap") {
			t.Errorf("the service links %s: packet capture belongs to the sensors, not here", dep.Path)
		}
	}
	if len(info.Deps) == 0 {
		t.Error("build info lists no dependencies; the check proves nothing")
	}
}

// Without a configured AdGuard account the service must not try one of its
// own: it used to log in as admin/changeme, AdGuard's well-known default
// (audit DP-5). Half-configured polling now refuses the start, naming what
// is missing, and AdGuard is never asked.
func TestRunHasNoDefaultAdGuardCredential(t *testing.T) {
	var polls atomic.Int32
	var sawDefault atomic.Bool
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		if u, p, ok := r.BasicAuth(); ok && u == "admin" && p == "changeme" {
			sawDefault.Store(true)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(ag.Close)
	q := &querylog{u: ag.URL}
	inv := startInventory(t, "192.0.2.1", "aa:bb:cc:00:00:01", "x").url

	for _, missing := range [][]string{
		{"ADGUARD_USER", "ADGUARD_PASSWORD"},
		{"ADGUARD_PASSWORD"},
		{"ADGUARD_USER"},
		// Credentials without an address: the in-cluster name used to be
		// polled.
		{"ADGUARD_URL"},
	} {
		t.Run(strings.Join(missing, "+"), func(t *testing.T) {
			env := baseEnv(t, q, startReceiver(t), inv, filepath.Join(t.TempDir(), "de.db"))
			for _, k := range missing {
				delete(env, k)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err := run(ctx, func(k string) string { return env[k] }, func(string) {
				t.Error("the service started listening with AdGuard polling half-configured")
			})
			if err == nil || !strings.Contains(err.Error(), strings.Join(missing, "/")+" not set") {
				t.Fatalf("run = %v, want a start-up error naming %v", err, missing)
			}
		})
	}
	if polls.Load() != 0 || sawDefault.Load() {
		t.Fatalf("AdGuard was asked %d times (admin/changeme: %v) by a service that refused to start",
			polls.Load(), sawDefault.Load())
	}
}

// TestRunWithoutAdGuardPollsNothing: with no ADGUARD_* at all the service
// runs — sensor ingest and feedback do not need AdGuard — and polls nothing.
// It used to poll http://adguard-web.dns.svc:3000 as admin/changeme, a name
// that resolves to nothing outside the cluster.
func TestRunWithoutAdGuardPollsNothing(t *testing.T) {
	env := baseEnv(t, &querylog{}, startReceiver(t), startInventory(t, "192.0.2.1", "aa:bb:cc:00:00:01", "x").url,
		filepath.Join(t.TempDir(), "de.db"))
	for _, k := range []string{"ADGUARD_URL", "ADGUARD_USER", "ADGUARD_PASSWORD"} {
		delete(env, k)
	}
	env["POLL_INTERVAL"] = "20ms"
	addr, stop := start(t, env)

	pages := metric(t, addr, "detection_engine_querylog_pages_total")
	failures := metric(t, addr, "detection_engine_poll_errors_total")
	time.Sleep(300 * time.Millisecond) // a poller would have tried many times by now
	if p, f := metric(t, addr, "detection_engine_querylog_pages_total"), metric(t, addr,
		"detection_engine_poll_errors_total"); p != pages || f != failures {
		t.Fatalf("query-log polls happened without AdGuard configured: pages %v → %v, errors %v → %v",
			pages, p, failures, f)
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/healthz = %d", resp.StatusCode)
	}
	if err := stop(); err != nil {
		t.Errorf("clean shutdown returned %v", err)
	}
}

// A deployment without an OpenTelemetry collector (the core profile) turns
// tracing off with the standard switch. Before, nothing could: an empty
// endpoint fell back to the collector's in-cluster name, and the exporter
// logged a failed export every ten seconds.
func TestTracingEnabled(t *testing.T) {
	for v, want := range map[string]bool{
		"": true, "false": true, "0": true, "nonsense": true,
		"true": false, "TRUE": false, "1": false, " true ": false,
	} {
		getenv := func(k string) string {
			if k == "OTEL_SDK_DISABLED" {
				return v
			}
			return ""
		}
		if got := tracingEnabled(getenv); got != want {
			t.Errorf("OTEL_SDK_DISABLED=%q: tracingEnabled = %v, want %v", v, got, want)
		}
	}
}

// metric scrapes one sample from /metrics (0 when absent).
func metric(t *testing.T, addr, series string) float64 {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), series+" "); ok {
			f, _ := strconv.ParseFloat(v, 64)
			return f
		}
	}
	return 0
}
