package abusech

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// TestAuditThreatFoxUnboundedBody (TI-4): a feed endpoint that answers 200
// and keeps streaming well-formed rows (~230 MiB here). The old client
// decoded it all into memory; now the read stops at the body cap, the error
// says so, and the heap stays bounded.
func TestAuditThreatFoxUnboundedBody(t *testing.T) {
	var sent atomic.Int64
	var gotAuth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Auth-Key"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"query_status":"ok","data":[`)
		row := `{"ioc":"` + strings.Repeat("a", 200) + `.example","ioc_type":"domain","malware_printable":"` +
			strings.Repeat("m", 300) + `","confidence_level":100,"tags":["x"]},`
		chunk := strings.Repeat(row, 1000)
		for i := 0; i < 400; i++ {
			n, err := fmt.Fprint(w, chunk)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
		fmt.Fprint(w, `{"ioc":"z.example","ioc_type":"domain"}]}`)
	}))
	defer srv.Close()

	c := NewThreatFoxClient(WithAuthKey("test-key"))
	c.apiURL = srv.URL
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	inds, err := c.Fetch(context.Background(), 7)
	runtime.ReadMemStats(&after)
	grew := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("Fetch -> %d indicators, err=%v, in %s; server wrote %d MiB before the client hung up; heap grew by %d MiB",
		len(inds), err, time.Since(start).Round(time.Millisecond), sent.Load()>>20, grew>>20)

	if !errors.Is(err, feedhttp.ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
	if grew > 96<<20 {
		t.Errorf("heap grew by %d MiB reading a capped body", grew>>20)
	}
	if got, _ := gotAuth.Load().(string); got != "test-key" {
		t.Errorf("Auth-Key header = %q, want the configured key", got)
	}
	if len(inds) == 0 {
		t.Error("rows decoded before the cap should be returned for the partial-result policy")
	}
}

// threatFoxFixture follows the get_iocs example at
// https://threatfox.abuse.ch/api/ (field names and formats as documented).
const threatFoxFixture = `{
  "query_status": "ok",
  "data": [
    {"id": "41", "ioc": "gaga.com", "threat_type": "botnet_cc",
     "threat_type_desc": "Indicator that identifies a botnet command&control server (C&C)",
     "ioc_type": "domain", "ioc_type_desc": "Domain that is used for botnet Command&control (C&C)",
     "malware": "win.dridex", "malware_printable": "Dridex", "malware_alias": null,
     "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.dridex",
     "confidence_level": 50, "first_seen": "2020-12-08 13:36:27 UTC", "last_seen": null,
     "reporter": "abuse_ch", "reference": "https://twitter.com/JAMESWT_MHT/status/1336229725082177536",
     "tags": ["exe", "test"]},
    {"id": "42", "ioc": "198.51.100.23:443", "ioc_type": "ip:port", "malware_printable": "Cobalt Strike",
     "confidence_level": 100, "first_seen": "2026-11-15 08:00:00 UTC", "last_seen": "2026-11-16 07:00:00 UTC",
     "reference": null, "tags": null},
    {"id": "43", "ioc": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "ioc_type": "sha1_hash",
     "confidence_level": 75, "first_seen": "2026-11-15 08:00:00 UTC"},
    {"id": "44", "ioc": "bad.example", "ioc_type": "domain", "confidence_level": "high"}
  ]
}`

// TestThreatFoxFixture (TI-8): the documented request (POST get_iocs with the
// Auth-Key header) and response fields. The old client read first_seen_utc /
// last_seen_utc, which the API does not send.
func TestThreatFoxFixture(t *testing.T) {
	var req struct {
		Query string `json:"query"`
		Days  int    `json:"days"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Auth-Key") != "k" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewDecoder(r.Body).Decode(&req)
		fmt.Fprint(w, threatFoxFixture)
	}))
	defer srv.Close()

	c := NewThreatFoxClient(WithAuthKey("k"))
	c.apiURL = srv.URL
	inds, err := c.Fetch(context.Background(), 30) // out of range: clamped to 7
	if err != nil {
		t.Fatal(err)
	}
	if req.Query != "get_iocs" || req.Days != 7 {
		t.Errorf("request = %+v", req)
	}
	// sha1_hash is unsupported (skipped, not invalid); the "high" confidence
	// row is malformed and skipped.
	if len(inds) != 2 {
		t.Fatalf("got %d indicators: %+v", len(inds), inds)
	}
	d := inds[0]
	if d.Type != ioc.TypeDomain || d.Value != "gaga.com" || d.Threat != "Dridex" || d.Confidence != 50 ||
		d.FirstSeen.IsZero() || !d.LastSeen.IsZero() || len(d.Tags) != 2 || !strings.HasPrefix(d.Reference, "https://") {
		t.Errorf("domain row = %+v", d)
	}
	if ip := inds[1]; ip.Type != ioc.TypeIP || ip.Value != "198.51.100.23:443" || ip.LastSeen.IsZero() {
		t.Errorf("ip row = %+v", ip)
	}
}

func TestThreatFoxStatuses(t *testing.T) {
	for _, c := range []struct {
		name, body string
		status     int
		wantErr    string
		wantRows   int
	}{
		{"no result", `{"query_status":"no_result","data":"Your search did not yield any results"}`, 200, "", 0},
		{"bad key", `{"query_status":"unknown_auth_key"}`, 200, "unknown_auth_key", 0},
		{"rejected", `forbidden`, 403, "credentials rejected", 0},
		{"not json", `<html>maintenance</html>`, 200, "decode", 0},
		{"all malformed", `{"query_status":"ok","data":[{"ioc":"a.example","ioc_type":"domain","confidence_level":"x"}]}`, 200, "malformed", 0},
		{"object data", `{"query_status":"ok","extra":{"a":[1,{"b":2}]},"data":{"x":1}}`, 200, "", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				io.WriteString(w, c.body)
			}))
			defer srv.Close()
			tf := NewThreatFoxClient()
			tf.apiURL = srv.URL
			inds, err := tf.Fetch(context.Background(), 3)
			if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Errorf("err = %v, want %q", err, c.wantErr)
			}
			if len(inds) != c.wantRows {
				t.Errorf("rows = %d", len(inds))
			}
		})
	}
}

// urlhausFixture follows the recent-URLs example at https://urlhaus-api.abuse.ch/.
const urlhausFixture = `{
    "query_status": "ok",
    "urls": [
        {
            "id": "223622",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/223622\/",
            "url": "http:\/\/45.61.49.78\/razor\/r4z0r.mips",
            "url_status": "offline",
            "host": "45.61.49.78",
            "date_added": "2019-08-10 09:02:05 UTC",
            "threat": "malware_download",
            "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
            "reporter": "zbetcheckin",
            "larted": "true",
            "tags": ["elf", "mirai"]
        },
        {
            "id": "223623",
            "urlhaus_reference": "https:\/\/urlhaus.abuse.ch\/url\/223623\/",
            "url": "http:\/\/Evil-Host.example\/x.exe",
            "url_status": "online",
            "host": "evil-host.example",
            "date_added": "2019-08-10 09:03:00 UTC",
            "threat": "malware_download",
            "blacklists": {},
            "reporter": "abuse_ch",
            "larted": "false",
            "tags": null
        }
    ]
}`

// TestURLhausFixture (TI-8): the documented call is a GET with the limit as
// a path segment; the old client POSTed a form, which the API refuses with
// "http_get_expected", and read "dateadded"/"urlhaus_link".
func TestURLhausFixture(t *testing.T) {
	var gotPath, gotMethod, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotKey = r.URL.Path, r.Method, r.Header.Get("Auth-Key")
		if r.Method != http.MethodGet {
			fmt.Fprint(w, `{"query_status":"http_get_expected"}`)
			return
		}
		fmt.Fprint(w, urlhausFixture)
	}))
	defer srv.Close()

	c := NewURLhausClient(WithAuthKey("k"))
	c.apiURL = srv.URL + "/v1/urls/recent/"
	inds, err := c.Fetch(context.Background(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/urls/recent/limit/5/" || gotKey != "k" {
		t.Errorf("request %s %s Auth-Key=%q", gotMethod, gotPath, gotKey)
	}
	// two URLs plus the domain of the second (the first host is an address)
	if len(inds) != 3 {
		t.Fatalf("got %d indicators: %+v", len(inds), inds)
	}
	u := inds[0]
	if u.Type != ioc.TypeURL || u.FirstSeen.IsZero() || u.Reference != "https://urlhaus.abuse.ch/url/223622/" ||
		len(u.Tags) != 2 || u.Threat != "malware_download" {
		t.Errorf("url row = %+v", u)
	}
	if d := inds[2]; d.Type != ioc.TypeDomain || d.Value != "evil-host.example" {
		t.Errorf("domain row = %+v", d)
	}
}

func TestURLhausStatuses(t *testing.T) {
	for body, wantErr := range map[string]bool{
		`{"query_status":"no_results"}`:            false,
		`{"query_status":"http_get_expected"}`:     true,
		`{"query_status":"ok","urls":[{"url":7}]}`: true, // every row malformed
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, body)
		}))
		c := NewURLhausClient()
		c.apiURL = srv.URL
		inds, err := c.Fetch(context.Background(), 0)
		if (err != nil) != wantErr || len(inds) != 0 {
			t.Errorf("%s: inds=%d err=%v", body, len(inds), err)
		}
		srv.Close()
	}
}

const feodoBanner = "################################################################\n" +
	"# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (CSV)          #\n" +
	"################################################################\n"

// TestAuditFeodoQuotedCSV (TI-8): the quoted six-column dialect. The old
// hand-rolled splitter produced `"203.0.113.10":"443"`, every row was
// rejected, and the source still counted as successful.
func TestAuditFeodoQuotedCSV(t *testing.T) {
	body := feodoBanner +
		"\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n" +
		"\"2026-10-01 08:11:02\",\"203.0.113.10\",\"443\",\"online\",\"2026-11-15\",\"QakBot\"\n" +
		"\"2026-10-03 11:00:00\",\"203.0.113.11\",\"8080\",\"offline\",\"2026-11-10\",\"Emotet\"\n" +
		"\"2026-10-04 11:00:00\",\"2001:db8::7\",\"443\",\"online\",\"2026-11-16\",\"Pikabot, \"\"v2\"\"\"\n"
	inds, err := parseFeodoCSV(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(inds) != 2 {
		t.Fatalf("want the two online C2s, got %+v", inds)
	}
	for _, i := range inds {
		v, verr := ioc.Validate(i)
		if verr != nil {
			t.Errorf("%q does not validate: %v", i.Value, verr)
		}
		if i.FirstSeen.IsZero() || i.LastSeen.IsZero() {
			t.Errorf("%q: dates not parsed", i.Value)
		}
		t.Logf("value=%q -> %q threat=%q", i.Value, v.Value, i.Threat)
	}
	if inds[0].Threat != "QakBot" || inds[1].Value != "[2001:db8::7]:443" || inds[1].Threat != `Pikabot, "v2"` {
		t.Errorf("rows = %+v", inds)
	}
}

func TestFeodoDialects(t *testing.T) {
	for _, c := range []struct {
		name     string
		body     string
		want     int
		wantErr  bool
		wantPart bool
	}{
		{"commented header", feodoBanner +
			"# \"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n" +
			"\"2026-10-01 08:11:02\",\"203.0.113.10\",\"443\",\"online\",\"2026-11-15\",\"QakBot\"\n" +
			"# END 1 entries\n", 1, false, false},
		{"documented five columns", "first_seen_utc,dst_ip,dst_port,last_online,malware\n" +
			"2026-10-01 08:11:02,203.0.113.10,443,2026-11-15,QakBot\tx\ty\n", 1, false, false},
		{"header only: an empty dataset", feodoBanner +
			"\"first_seen_utc\",\"dst_ip\",\"dst_port\",\"c2_status\",\"last_online\",\"malware\"\n", 0, false, false},
		{"no header", "\"2026-10-01 08:11:02\",\"203.0.113.10\",\"443\",\"online\",\"2026-11-15\",\"QakBot\"\n", 0, true, false},
		{"html", "<html><body>maintenance</body></html>\n", 0, true, false},
		{"empty body", "", 0, true, false},
		{"all malformed", "dst_ip,dst_port\n\"unterminated,1\n", 0, true, false},
		{"some malformed", "dst_ip,dst_port\n\"unterminated,1\n203.0.113.10,443\n", 1, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			inds, err := parseFeodoCSV(strings.NewReader(c.body))
			if (err != nil) != c.wantErr || len(inds) != c.want {
				t.Errorf("got %d rows, err=%v", len(inds), err)
			}
		})
	}
}

// TestFeodoTruncatedBodyKeepsCompleteRowsOnly: at the body cap the rows read
// so far are returned with the error, and the cut-off last row is not — a
// truncated "203.0.113.10" would be the different, valid "203.0.113.1".
func TestFeodoTruncatedBodyKeepsCompleteRowsOnly(t *testing.T) {
	body := "dst_ip,dst_port\n203.0.113.20,443\n203.0.113.10,443\n"
	cut := strings.Index(body, "203.0.113.10") + len("203.0.113.1")
	inds, err := parseFeodoCSV(feedhttp.LimitBody(strings.NewReader(body), int64(cut)))
	if !errors.Is(err, feedhttp.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if len(inds) != 1 || inds[0].Value != "203.0.113.20:443" {
		t.Errorf("rows = %+v", inds)
	}
}

func TestFeodoFetch(t *testing.T) {
	var gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("Auth-Key")
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "dst_ip,dst_port\n203.0.113.10,443\n")
	}))
	defer srv.Close()

	c := NewFeodoClient(WithAuthKey("k"), WithMaxBodyBytes(1<<20))
	c.csvURL = srv.URL + "/ipblocklist.csv"
	if inds, err := c.Fetch(context.Background()); err != nil || len(inds) != 1 || gotKey != "k" {
		t.Errorf("inds=%d err=%v key=%q", len(inds), err, gotKey)
	}
	c.csvURL = srv.URL + "/missing"
	if _, err := c.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("err = %v", err)
	}
	if !strings.HasSuffix(NewFeodoClient().csvURL, "/downloads/ipblocklist.csv") {
		t.Error("Feodo must use the CSV dataset documented on its blocklist page")
	}
}

func TestParseAbusechTime(t *testing.T) {
	for in, want := range map[string]string{
		"2020-12-08 13:36:27 UTC": "2020-12-08T13:36:27Z",
		"2020-12-08 13:36:27":     "2020-12-08T13:36:27Z",
		"2020-12-08":              "2020-12-08T00:00:00Z",
	} {
		if got := parseAbusechTime(in).Format(time.RFC3339); got != want {
			t.Errorf("parseAbusechTime(%q) = %s", in, got)
		}
	}
	if !parseAbusechTime("yesterday").IsZero() {
		t.Error("garbage should parse to the zero time")
	}
}
