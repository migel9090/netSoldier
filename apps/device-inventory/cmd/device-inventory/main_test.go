package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/agent"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/api"
	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func env(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

// DI-6 / contract section 5: no key, no service, unless explicitly allowed.
func TestConfigFailsClosedWithoutAPIKey(t *testing.T) {
	if _, err := loadConfig(env()); err == nil || !strings.Contains(err.Error(), "DEVICE_API_KEY") {
		t.Fatalf("err = %v, want a refusal naming DEVICE_API_KEY", err)
	}
	if _, err := loadConfig(env("DEVICE_API_ALLOW_UNAUTHENTICATED", "yes")); err == nil {
		t.Error("a non-boolean opt-out must not count as true")
	}
	// NETAGENT_EXPECT_CAPTURE=none isolates the API-key path from the agent
	// token requirement, which this case is not about.
	c, err := loadConfig(env("DEVICE_API_ALLOW_UNAUTHENTICATED", "true", "NETAGENT_EXPECT_CAPTURE", "none"))
	if err != nil || !c.allowUnauth || c.apiKey != "" {
		t.Errorf("explicit opt-out: %+v %v", c, err)
	}
	// The default set of expected captures needs a NETAGENT_TOKEN so the
	// agent can authenticate; with both, the defaults parse.
	c, err = loadConfig(env("DEVICE_API_KEY", "k", "NETAGENT_TOKEN", "n"))
	if err != nil || strings.Join(c.expectCapture, ",") != "dhcp,arp,lldp,mdns,ssdp" || c.listenAddr != ":8081" {
		t.Errorf("defaults: %+v %v", c, err)
	}
	// Expecting captures without a NETAGENT_TOKEN is a start-up error.
	if _, err := loadConfig(env("DEVICE_API_KEY", "k")); err == nil {
		t.Error("default captures without NETAGENT_TOKEN should fail closed")
	}
}

func TestConfigValidation(t *testing.T) {
	c, err := loadConfig(env("DEVICE_API_KEY", "k", "NETAGENT_TOKEN", "n",
		"NETAGENT_EXPECT_CAPTURE", "arp, dhcp,arp", "BINDING_TTL", "10m", "DEVICE_MAX_ROWS", "300"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.expectCapture, ",") != "arp,dhcp" || c.store.BindingTTL != 10*time.Minute ||
		c.store.MaxDevices != 300 {
		t.Errorf("parsed %+v", c)
	}
	// "none" means no agent is required and needs no token (the e2e suite
	// relies on this); the old DISCOVERY_LISTENERS name still works.
	if c, err := loadConfig(env("DEVICE_API_KEY", "k", "DISCOVERY_LISTENERS", "none")); err != nil || len(c.expectCapture) != 0 {
		t.Errorf("none: %+v %v", c.expectCapture, err)
	}
	for _, bad := range [][]string{
		{"NETAGENT_EXPECT_CAPTURE", "arp,wifi"},
		{"BINDING_TTL", "-1s"},
		{"DEVICE_MAX_ROWS", "lots"},
		{"ARP_SCAN_INTERVAL", "soon"},
		{"ARP_SCAN_SUBNET", "10.0.0.0/8"}, // wider than /16
		{"NETAGENT_HEARTBEAT_TIMEOUT", "nope"},
	} {
		if _, err := loadConfig(env("DEVICE_API_KEY", "k", "NETAGENT_TOKEN", "n", bad[0], bad[1])); err == nil {
			t.Errorf("%s=%s accepted", bad[0], bad[1])
		}
	}
}

func TestAuthMiddlewareProtectsReads(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mux := http.NewServeMux()
	api.NewHandler(db, nil).Register(mux)
	mux.HandleFunc("GET /healthz", handleHealthz)
	hb := agent.NewHeartbeat(15*time.Second, []string{"arp"}) // expected, never heard from
	mux.HandleFunc("GET /readyz", readyzHandler(hb, true))
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {})
	srv := httptest.NewServer(authMiddleware("secret", mux))
	defer srv.Close()

	do := func(method, path, token string) int {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(`{"labels":[]}`))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	for _, p := range []string{"/devices", "/devices/by-ip/192.168.1.1", "/devices/00:11:22:33:44:55"} {
		if code := do("GET", p, ""); code != http.StatusUnauthorized {
			t.Errorf("GET %s without a token: %d, want 401", p, code)
		}
		if code := do("GET", p, "wrong"); code != http.StatusUnauthorized {
			t.Errorf("GET %s with a wrong token: %d, want 401", p, code)
		}
	}
	if code := do("PUT", "/devices/00:11:22:33:44:55/labels", ""); code != http.StatusUnauthorized {
		t.Errorf("PUT without a token: %d", code)
	}
	if code := do("GET", "/devices", "secret"); code != http.StatusOK {
		t.Errorf("GET /devices with the token: %d", code)
	}
	for _, p := range []string{"/healthz", "/metrics"} {
		if code := do("GET", p, ""); code != http.StatusOK {
			t.Errorf("%s must stay open: %d", p, code)
		}
	}
	if code := do("GET", "/readyz", ""); code != http.StatusServiceUnavailable {
		t.Errorf("/readyz with no listener up: %d, want 503", code)
	}

	open := httptest.NewServer(authMiddleware("", mux))
	defer open.Close()
	resp, _ := http.Get(open.URL + "/devices")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("explicitly unauthenticated mode: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// DI-4 (code half) / contract 8.1: readiness follows the agent's heartbeat,
// liveness does not. Not ready until a fresh heartbeat shows every expected
// capture up; ready once one arrives; and with no captures expected
// (NETAGENT_EXPECT_CAPTURE=none) ready regardless.
func TestReadyzReflectsHeartbeat(t *testing.T) {
	hb := agent.NewHeartbeat(15*time.Second, []string{"arp", "dhcp"})
	get := func(requireAgent bool) (int, map[string]any) {
		rec := httptest.NewRecorder()
		readyzHandler(hb, requireAgent)(rec, httptest.NewRequest("GET", "/readyz", nil))
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}
	if code, body := get(true); code != 503 || body["status"] != "not ready" {
		t.Errorf("before any heartbeat: %d %v", code, body)
	}
	// A heartbeat with only arp up is still not ready.
	hb.Observe("soc-node-1", "eth0", map[string]bool{"arp": true}, 0)
	if code, _ := get(true); code != 503 {
		t.Errorf("partial capture should not be ready: %d", code)
	}
	// Both up: ready.
	hb.Observe("soc-node-1", "eth0", map[string]bool{"arp": true, "dhcp": true}, 0)
	if code, body := get(true); code != 200 || body["status"] != "ready" {
		t.Errorf("both captures up should be ready: %d %v", code, body)
	}
	// With no agent required, an empty-heartbeat tracker is ready at once.
	none := agent.NewHeartbeat(15*time.Second, nil)
	rec := httptest.NewRecorder()
	readyzHandler(none, false)(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 {
		t.Errorf("no-agent mode should be ready immediately: %d", rec.Code)
	}
}

type chCapture struct {
	mu      sync.Mutex
	inserts map[string][]string
	fail    bool
}

func (c *chCapture) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		http.Error(w, "Code: 497. DB::Exception: writer: Not enough privileges", http.StatusForbidden)
		return
	}
	q := r.URL.Query().Get("query")
	table := strings.Fields(q)[2]
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		c.inserts[table] = append(c.inserts[table], line)
	}
}

func (c *chCapture) rows(table string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.inserts[table]...)
}

// DI-5: the devices table was never written. Sightings now produce device
// snapshots and events, conflicts included.
func TestSightingsReachClickHouse(t *testing.T) {
	cap := &chCapture{inserts: map[string][]string{}}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	db, err := store.OpenWithOptions(filepath.Join(t.TempDir(), "d.db"), store.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	w := newCHWriter(ch.NewClient(srv.URL, "netsoldier", "writer", "pw"), 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()

	router := "00:11:24:aa:bb:01"
	handleSighting(db, w, discovery.Sighting{Source: discovery.SourceDHCP, MAC: router, IP: "192.168.77.1",
		Name: "gateway", Fingerprint: "1,3,6,15", VendorClass: "udhcp 1.36"})
	now = now.Add(20 * time.Second)
	handleSighting(db, w, discovery.Sighting{Source: discovery.SourceARP, MAC: router, IP: "192.168.77.1"})
	handleSighting(db, w, discovery.Sighting{Source: discovery.SourceARP, MAC: "02:de:ad:be:ef:01", IP: "192.168.77.1"})
	cancel()
	<-done

	devices := cap.rows("devices")
	// The router's snapshot and the attacker's new row; the refused claim
	// changes no device.
	if len(devices) != 2 || !strings.Contains(devices[0], `"mac":"00:11:24:aa:bb:01"`) ||
		!strings.Contains(devices[0], `"os":"Linux"`) || !strings.Contains(devices[0], `"vendor":"Apple"`) {
		t.Errorf("devices rows: %v", devices)
	}
	var rec ch.DeviceRecord
	if err := json.Unmarshal([]byte(devices[0]), &rec); err != nil || len(rec.UpdatedAt) != len(ch.SecondsLayout) {
		t.Errorf("snapshot timestamps must be DateTime (seconds): %+v %v", rec, err)
	}
	events := strings.Join(cap.rows("device_events"), "\n")
	if strings.Contains(devices[1], `"ip":"192.168.77.1"`) {
		t.Errorf("attacker snapshot carries the router's address: %s", devices[1])
	}
	for _, want := range []string{`"event_type":"new"`, `"protocol":"dhcp"`, `"event_type":"conflict"`, `"event_type":"seen"`} {
		if !strings.Contains(events, want) {
			t.Errorf("events missing %s: %s", want, events)
		}
	}
	var ev ch.DeviceEvent
	_ = json.Unmarshal([]byte(cap.rows("device_events")[0]), &ev)
	if len(ev.Timestamp) != len(ch.MillisLayout) {
		t.Errorf("event timestamp %q should carry milliseconds", ev.Timestamp)
	}
}

func TestClickHouseWriteFailureIsCountedNotFatal(t *testing.T) {
	cap := &chCapture{inserts: map[string][]string{}, fail: true}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()
	dropped := testutil.ToFloat64(metrics.EventsDropped)
	failed := testutil.ToFloat64(metrics.ClickHouseErrors.WithLabelValues("insert", "device_events"))
	w := newCHWriter(ch.NewClient(srv.URL, "netsoldier", "writer", "pw"), 2)
	ts := time.Now()
	w.event(ts, "aa:bb:cc:dd:ee:01", "", "", "", "arp", "seen")
	w.event(ts, "aa:bb:cc:dd:ee:02", "", "", "", "arp", "seen")
	w.event(ts, "aa:bb:cc:dd:ee:03", "", "", "", "arp", "seen") // queue full: dropped and counted
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.Run(ctx) // drains, flushes, logs the failure, returns
	if d := testutil.ToFloat64(metrics.EventsDropped) - dropped; d != 1 {
		t.Errorf("events_dropped_total grew by %v, want 1", d)
	}
	if f := testutil.ToFloat64(metrics.ClickHouseErrors.WithLabelValues("insert", "device_events")) - failed; f != 1 {
		t.Errorf("clickhouse_errors_total{insert,device_events} grew by %v, want 1", f)
	}
	var nilWriter *chWriter
	nilWriter.event(time.Now(), "x", "", "", "", "", "")
	newCHWriter(nil, 1).device(&store.Device{})
}
