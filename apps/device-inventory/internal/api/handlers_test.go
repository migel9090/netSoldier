package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
)

func newTestAPI(t *testing.T, chClient *ch.Client) (*httptest.Server, *store.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	mux := http.NewServeMux()
	NewHandler(db, chClient).Register(mux)
	mux.Handle("GET /topology", NewTopologyHandler(db, chClient))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, db
}

func seen(t *testing.T, db *store.Store, s discovery.Sighting) {
	t.Helper()
	res, err := db.Observe(s)
	if err != nil || res.Outcome != store.Applied {
		t.Fatalf("observe %+v: %v %s", s, err, res.Outcome)
	}
}

func arp(mac, ip string) discovery.Sighting {
	return discovery.Sighting{Source: discovery.SourceARP, MAC: mac, IP: ip}
}

func get(t *testing.T, url string) (int, http.Header, []byte) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func getJSON[T any](t *testing.T, url string) T {
	t.Helper()
	code, _, body := get(t, url)
	if code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", url, code, body)
	}
	var v T
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}

func put(t *testing.T, url, body string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestListDevicesEmptyIsAnArray(t *testing.T) {
	srv, _ := newTestAPI(t, nil)
	code, hdr, body := get(t, srv.URL+"/devices")
	if code != 200 || strings.TrimSpace(string(body)) != "[]" || hdr.Get("X-Total-Count") != "0" {
		t.Errorf("got %d %q total=%q", code, body, hdr.Get("X-Total-Count"))
	}
}

func TestListDevicesPagination(t *testing.T) {
	srv, db := newTestAPI(t, nil)
	for i := 0; i < 7; i++ {
		seen(t, db, arp(fmt.Sprintf("00:11:22:33:44:%02x", i), fmt.Sprintf("192.168.1.%d", 10+i)))
	}
	code, hdr, body := get(t, srv.URL+"/devices?limit=3&offset=5")
	var page []store.Device
	_ = json.Unmarshal(body, &page)
	if code != 200 || len(page) != 2 || hdr.Get("X-Total-Count") != "7" {
		t.Errorf("limit=3&offset=5: %d, %d rows, total %q", code, len(page), hdr.Get("X-Total-Count"))
	}
	if all := getJSON[[]store.Device](t, srv.URL+"/devices?limit=5000"); len(all) != 7 {
		t.Errorf("limit above the max is capped, not refused: %d rows", len(all))
	}
	for _, q := range []string{"limit=abc", "limit=-1", "limit=0", "offset=-3"} {
		if code, _, _ := get(t, srv.URL+"/devices?"+q); code != http.StatusBadRequest {
			t.Errorf("?%s: %d, want 400", q, code)
		}
	}
}

func TestGetDevice(t *testing.T) {
	srv, db := newTestAPI(t, nil)
	seen(t, db, discovery.Sighting{Source: discovery.SourceDHCP, MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.1.100",
		Name: "sensor-1", Fingerprint: "1,3,6", VendorClass: "vc1", OS: "FreeRTOS", DeviceType: "iot"})

	d := getJSON[store.Device](t, srv.URL+"/devices/aa:bb:cc:dd:ee:ff")
	if d.MAC != "aa:bb:cc:dd:ee:ff" || d.Hostname != "sensor-1" || d.OS != "FreeRTOS" || d.HostnameSource != "dhcp" {
		t.Errorf("unexpected device: %+v", d)
	}
	// From the auditor's TestAuditSetLabelsUnbounded: the same device in
	// upper case (or with dashes) used to be a 404.
	for _, alias := range []string{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff"} {
		if code, _, _ := get(t, srv.URL+"/devices/"+alias); code != 200 {
			t.Errorf("GET /devices/%s: %d, want 200", alias, code)
		}
	}
	if code, _, _ := get(t, srv.URL+"/devices/02:ff:ff:ff:ff:fe"); code != 404 {
		t.Errorf("unknown device: %d, want 404", code)
	}
	if code, _, _ := get(t, srv.URL+"/devices/not-a-mac"); code != 400 {
		t.Errorf("invalid mac: %d, want 400", code)
	}
}

func TestGetDeviceByIP(t *testing.T) {
	srv, db := newTestAPI(t, nil)
	seen(t, db, arp("00:11:22:33:44:55", "192.168.1.50"))

	d := getJSON[store.Device](t, srv.URL+"/devices/by-ip/192.168.1.50")
	if d.MAC != "00:11:22:33:44:55" || d.IPState != store.IPTentative {
		t.Errorf("by-ip: %+v", d)
	}
	if d := getJSON[store.Device](t, srv.URL+"/devices/by-ip/::ffff:192.168.1.50"); d.MAC != "00:11:22:33:44:55" {
		t.Errorf("v4-mapped address should resolve: %+v", d)
	}
	if code, _, _ := get(t, srv.URL+"/devices/by-ip/192.168.1.51"); code != 404 {
		t.Errorf("unheld address: %d, want 404", code)
	}
	if code, _, _ := get(t, srv.URL+"/devices/by-ip/not-an-ip"); code != 400 {
		t.Errorf("invalid ip: %d, want 400", code)
	}
}

func TestSetLabels(t *testing.T) {
	srv, db := newTestAPI(t, nil)
	seen(t, db, arp("aa:bb:cc:dd:ee:ff", "192.168.1.100"))

	var changed *store.Device
	// Register a second handler to observe the callback.
	h := NewHandler(db, nil)
	h.OnLabels = func(d *store.Device) { changed = d }
	mux := http.NewServeMux()
	h.Register(mux)
	srv2 := httptest.NewServer(mux)
	defer srv2.Close()

	code, body := put(t, srv2.URL+"/devices/AA:BB:CC:DD:EE:FF/labels", `{"labels":["critical","iot"]}`)
	if code != 200 {
		t.Fatalf("PUT: %d %s", code, body)
	}
	var d store.Device
	_ = json.Unmarshal(body, &d)
	if strings.Join(d.Labels, ",") != "critical,iot" || changed == nil || changed.MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("labels %v, callback %+v", d.Labels, changed)
	}
	if code, _ := put(t, srv.URL+"/devices/02:ff:ff:ff:ff:fe/labels", `{"labels":["x"]}`); code != 404 {
		t.Errorf("unknown device: %d", code)
	}
	if code, _ := put(t, srv.URL+"/devices/aa:bb:cc:dd:ee:ff/labels", `{"labels":`); code != 400 {
		t.Errorf("broken JSON: %d", code)
	}
}

// DI-6, from the auditor's TestAuditSetLabelsUnbounded: a 32 MiB label was
// accepted, stored and served with every later GET /devices.
func TestSetLabelsLimits(t *testing.T) {
	srv, db := newTestAPI(t, nil)
	seen(t, db, arp("aa:bb:cc:dd:ee:ff", "192.168.1.100"))
	url := srv.URL + "/devices/aa:bb:cc:dd:ee:ff/labels"

	big := fmt.Sprintf(`{"labels":[%q]}`, strings.Repeat("A", 32<<20))
	if code, _ := put(t, url, big); code != http.StatusRequestEntityTooLarge {
		t.Errorf("32 MiB body: %d, want 413", code)
	}
	tooMany := make([]string, store.MaxLabels+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("l%d", i)
	}
	b, _ := json.Marshal(map[string]any{"labels": tooMany})
	for name, body := range map[string]string{
		"too many":  string(b),
		"too long":  fmt.Sprintf(`{"labels":[%q]}`, strings.Repeat("a", store.MaxLabelLen+1)),
		"control":   `{"labels":["a\u0000b"]}`,
		"empty one": `{"labels":[""]}`,
	} {
		if code, _ := put(t, url, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	if d, _ := db.GetDevice("aa:bb:cc:dd:ee:ff"); len(d.Labels) != 0 {
		t.Errorf("rejected bodies must not store labels: %v", d.Labels)
	}
}

func TestDeviceViewsWithoutClickHouse(t *testing.T) {
	srv, db := newTestAPI(t, nil)
	seen(t, db, arp("aa:bb:cc:dd:ee:ff", "192.168.1.100"))
	for _, view := range []string{"connections", "dns", "alerts"} {
		code, _, body := get(t, srv.URL+"/devices/aa:bb:cc:dd:ee:ff/"+view)
		if code != 200 || strings.TrimSpace(string(body)) != "[]" {
			t.Errorf("%s without ClickHouse: %d %s", view, code, body)
		}
	}
	if code, _, _ := get(t, srv.URL+"/devices/aa:bb:cc:dd:ee:ff/nope"); code != 404 {
		t.Errorf("unknown view: %d", code)
	}
	if code, _, _ := get(t, srv.URL+"/devices/not-a-mac/alerts"); code != 400 {
		t.Errorf("invalid mac: %d", code)
	}
}

// fakeClickHouse answers like ClickHouse's HTTP interface does with
// output_format_json_quote_64bit_integers=1 (the default): UInt64 values as
// strings. It checks that credentials arrive on every call.
func fakeClickHouse(t *testing.T, fail bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-ClickHouse-User") != "reader" || r.Header.Get("X-ClickHouse-Key") != "pw" {
			http.Error(w, "Code: 516. DB::Exception: Authentication failed", http.StatusUnauthorized)
			return
		}
		if fail {
			http.Error(w, "Code: 60. DB::Exception: Unknown table", http.StatusNotFound)
			return
		}
		q := r.URL.Query().Get("query")
		switch {
		case strings.Contains(q, "FROM zeek_ssl"): // the connection history
			fmt.Fprint(w, `{"meta":[],"data":[{"timestamp":"2026-11-16 12:00:00","dst_ip":"1.1.1.1","dst_domain":"one.one",
				"dst_port":443,"protocol":6,"bytes_in":"18446744073709551615","bytes_out":"42","duration_ms":"7",
				"service":"ssl"}],"rows":1}`)
		case strings.Contains(q, "FROM alerts"):
			if r.URL.Query().Get("param_mac") != "aa:bb:cc:dd:ee:ff" || r.URL.Query().Get("param_ip") != "192.168.1.100" {
				http.Error(w, "Code: 456. DB::Exception: Substitution `mac` is not set", http.StatusBadRequest)
				return
			}
			fmt.Fprint(w, `{"data":[{"timestamp":"2026-11-16 12:00:00","id":"DET-x-1","summary":"DNS query for c2.example",
				"domain":"c2.example","query_type":"A","matched_ioc":"c2.example","severity":"high","source":"threatfox",
				"signal_class":"ioc","threat":"","suppressed":1}]}`)
		case strings.Contains(q, "FROM network_flows"):
			fmt.Fprint(w, `{"data":[{"src_ip":"192.168.1.100","dst_ip":"1.1.1.1","total_bytes":"1000",
				"total_packets":"10","flow_count":"2"}]}`)
		default:
			fmt.Fprint(w, `{"data":[]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// DI-5: quoted UInt64 values made /connections and /topology silently empty.
func TestClickHouseViewsDecodeQuotedUInt64(t *testing.T) {
	chSrv := fakeClickHouse(t, false)
	srv, db := newTestAPI(t, ch.NewClient(chSrv.URL, "netsoldier", "reader", "pw"))
	seen(t, db, arp("aa:bb:cc:dd:ee:ff", "192.168.1.100"))

	code, _, body := get(t, srv.URL+"/devices/aa:bb:cc:dd:ee:ff/connections")
	if code != 200 || !strings.Contains(string(body), `"bytes_in":18446744073709551615`) || !strings.Contains(string(body), `"bytes_out":42`) ||
		!strings.Contains(string(body), `"duration_ms":7`) {
		t.Errorf("connections: %d %s", code, body)
	}

	// Alerts are looked up by the device's MAC as well as its address, and
	// carry what detection-engine adds (migration 030).
	code, _, body = get(t, srv.URL+"/devices/aa:bb:cc:dd:ee:ff/alerts")
	if code != 200 || !strings.Contains(string(body), `"summary":"DNS query for c2.example"`) ||
		!strings.Contains(string(body), `"suppressed":true`) {
		t.Errorf("alerts: %d %s", code, body)
	}

	topo := getJSON[topoResponse](t, srv.URL+"/topology")
	if len(topo.Edges) != 1 || topo.Edges[0].TotalBytes != 1000 || topo.Edges[0].FlowCount != 2 {
		t.Errorf("topology edges: %+v", topo.Edges)
	}
	if len(topo.Nodes) != 2 {
		t.Errorf("topology nodes: %+v", topo.Nodes)
	}
}

// DI-5: a failing ClickHouse used to look like "no data" (logged at Debug).
func TestClickHouseFailureIsAnError(t *testing.T) {
	chSrv := fakeClickHouse(t, true)
	srv, db := newTestAPI(t, ch.NewClient(chSrv.URL, "netsoldier", "reader", "pw"))
	seen(t, db, arp("aa:bb:cc:dd:ee:ff", "192.168.1.100"))
	for _, p := range []string{"/devices/aa:bb:cc:dd:ee:ff/connections", "/devices/aa:bb:cc:dd:ee:ff/dns",
		"/devices/aa:bb:cc:dd:ee:ff/alerts", "/topology"} {
		if code, _, _ := get(t, srv.URL+p); code != http.StatusBadGateway {
			t.Errorf("GET %s with a failing ClickHouse: %d, want 502", p, code)
		}
	}
}

func TestTopologyUsesTheCurrentHolder(t *testing.T) {
	srv, db := newTestAPI(t, nil)
	seen(t, db, discovery.Sighting{Source: discovery.SourceDHCP, MAC: "00:11:22:00:00:02", IP: "192.168.1.50", Name: "current-holder"})
	topo := getJSON[topoResponse](t, srv.URL+"/topology?hours=2")
	if len(topo.Nodes) != 1 || topo.Nodes[0].Label != "current-holder" || topo.Edges == nil {
		t.Errorf("topology: %+v", topo)
	}
}
