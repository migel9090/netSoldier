package detection

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
)

// fakeQueryLog behaves like AdGuard Home's /control/querylog: newest-first,
// truncated to ?limit=N.
type fakeQueryLog struct {
	mu      sync.Mutex
	entries []map[string]any // oldest first
}

func (f *fakeQueryLog) add(host, client string, ts time.Time, answers ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ans []map[string]any
	for _, a := range answers {
		typ := "A"
		if strings.Contains(a, ":") {
			typ = "AAAA"
		}
		ans = append(ans, map[string]any{"value": a, "type": typ, "ttl": 60})
	}
	f.entries = append(f.entries, map[string]any{
		"question": map[string]string{"name": host, "type": "A"},
		"client":   client, "time": ts, "answer": ans,
	})
}

func (f *fakeQueryLog) handler(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for i := len(f.entries) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, f.entries[i])
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
}

func newTestEngine(t *testing.T, f *fakeQueryLog, iocs []iocmatch.IoC) (*Engine, *[]Alert) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	m := iocmatch.New()
	m.Add(iocs)
	e := New(adguard.NewClient(srv.URL, "u", "p"), m, time.Second)
	var got []Alert
	e.OnAlert = func(a Alert) { got = append(got, a) }
	return e, &got
}

var idRe = regexp.MustCompile(events.DetectionIDPattern)

// TestLegacyHostFieldIsNotRead: AdGuard Home names the question "name".
// The client also read "host", which only this project's test doubles ever
// sent; an entry with nothing but "host" is not a lookup of that name.
func TestLegacyHostFieldIsNotRead(t *testing.T) {
	f := &fakeQueryLog{}
	e, got := newTestEngine(t, f, []iocmatch.IoC{{Value: "evil-ioc.com", Type: "domain", Source: "threatfox", Confidence: 95}})
	f.mu.Lock()
	f.entries = append(f.entries, map[string]any{
		"question": map[string]string{"host": "evil-ioc.com", "type": "A"},
		"client":   "192.168.1.66", "time": time.Now().Add(time.Second),
	})
	f.mu.Unlock()
	f.add("evil-ioc.com", "192.168.1.67", time.Now().Add(2*time.Second))
	e.poll(context.Background())
	if len(*got) != 1 || (*got)[0].ClientIP != "192.168.1.67" {
		t.Fatalf("alerts %+v: want one, for the entry that names its question", *got)
	}
}

// TestDomainMatchCarriesTypedTarget: the queried FQDN stays in Domain as
// context, and the target is the feed's indicator.
func TestDomainMatchCarriesTypedTarget(t *testing.T) {
	f := &fakeQueryLog{}
	e, got := newTestEngine(t, f, []iocmatch.IoC{{Value: "evil-ioc.com", Type: "domain", Source: "threatfox", Confidence: 95}})
	f.add("A.Evil-IoC.com.", "192.168.1.66", time.Now().Add(time.Second))
	e.poll(context.Background())

	if len(*got) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*got))
	}
	a := (*got)[0]
	if a.Domain != "a.evil-ioc.com" {
		t.Errorf("domain = %q, want the queried name", a.Domain)
	}
	if a.Target == nil || *a.Target != (events.Target{Type: events.TargetDomain, Value: "evil-ioc.com"}) {
		t.Errorf("target = %+v, want the listed indicator", a.Target)
	}
	if a.MatchedIoC != "evil-ioc.com" || a.IoCType != events.IndicatorDomain {
		t.Errorf("matched = %q/%q", a.MatchedIoC, a.IoCType)
	}
	want := events.Signal{Class: SignalIoC, Confidence: 95, Indicator: "evil-ioc.com",
		IndicatorType: events.IndicatorDomain, Source: "threatfox"}
	if len(a.Signals) != 1 || a.Signals[0] != want {
		t.Errorf("signals = %+v, want %+v", a.Signals, want)
	}
	if !strings.Contains(a.Summary, "a.evil-ioc.com") || !strings.Contains(a.Summary, "threatfox") {
		t.Errorf("summary %q should say what was queried and who listed it", a.Summary)
	}
	if !idRe.MatchString(a.ID) {
		t.Errorf("id %q does not match %s", a.ID, events.DetectionIDPattern)
	}
}

// TestAnswerMatchTargetsTheAddress: a DNS answer that hits an IP IoC used to
// produce domain "cdn.legit.example (→203.0.113.7)", which the killswitch
// then tried (and failed) to turn into a sinkhole rule. The name is a shared
// CDN host; what the feed listed is the address.
func TestAnswerMatchTargetsTheAddress(t *testing.T) {
	f := &fakeQueryLog{}
	e, got := newTestEngine(t, f, []iocmatch.IoC{
		{Value: "203.0.113.7", Type: "ip", Source: "feodo", Confidence: 90},
		{Value: "198.51.100.0/24", Type: "ip", Source: "spamhaus", Confidence: 80},
		{Value: "2001:db8::7", Type: "ip", Source: "feodo", Confidence: 90},
	})
	ts := time.Now().Add(time.Second)
	f.add("cdn.legit.example", "192.168.1.66", ts, "203.0.113.7")
	f.add("other.example", "192.168.1.66", ts.Add(time.Millisecond), "198.51.100.44")
	f.add("v6.example", "192.168.1.66", ts.Add(2*time.Millisecond), "2001:DB8::7")
	e.poll(context.Background())

	if len(*got) != 3 {
		t.Fatalf("expected 3 alerts, got %d", len(*got))
	}
	byDomain := map[string]Alert{}
	for _, a := range *got {
		byDomain[a.Domain] = a
		if strings.ContainsAny(a.Domain, " (→") {
			t.Errorf("domain %q is decorated", a.Domain)
		}
	}

	exact := byDomain["cdn.legit.example"]
	if exact.Target == nil || *exact.Target != (events.Target{Type: events.TargetIP, Value: "203.0.113.7"}) {
		t.Errorf("exact match target = %+v, want ip 203.0.113.7", exact.Target)
	}
	if exact.IoCType != events.IndicatorIP || exact.Signals[0].Indicator != "203.0.113.7" {
		t.Errorf("exact match evidence = %s %+v", exact.IoCType, exact.Signals)
	}

	cidr := byDomain["other.example"]
	if cidr.Target == nil || cidr.Target.Value != "198.51.100.44" {
		t.Errorf("CIDR match target = %+v, want the answered address", cidr.Target)
	}
	if cidr.IoCType != events.IndicatorCIDR || cidr.Signals[0].Indicator != "198.51.100.0/24" ||
		cidr.Signals[0].IndicatorType != events.IndicatorCIDR {
		t.Errorf("a CIDR feed entry attests the range, got %s %+v", cidr.IoCType, cidr.Signals)
	}

	v6 := byDomain["v6.example"]
	if v6.Target == nil || v6.Target.Value != "2001:db8::7" {
		t.Errorf("IPv6 target = %+v, want canonical 2001:db8::7", v6.Target)
	}
}

func TestClientAddressIsCanonical(t *testing.T) {
	f := &fakeQueryLog{}
	e, got := newTestEngine(t, f, []iocmatch.IoC{{Value: "evil-ioc.com", Type: "domain", Confidence: 95}})
	f.add("evil-ioc.com", "::ffff:192.168.1.66", time.Now().Add(time.Second))
	e.poll(context.Background())
	if len(*got) != 1 || (*got)[0].ClientIP != "192.168.1.66" {
		t.Fatalf("client ip = %+v, want canonical 192.168.1.66", *got)
	}
	// Defaults for an indicator with no metadata.
	if a := (*got)[0]; a.Source != "local" || a.Severity == "" {
		t.Errorf("defaults not applied: %+v", a)
	}
}

// TestIDsAreUniqueAcrossRestarts: the old counter started at DET-1 in every
// process, so two boots produced the same ids for different detections.
func TestIDsAreUniqueAcrossRestarts(t *testing.T) {
	a, b := defaultIDPrefix(), defaultIDPrefix()
	if a == b {
		t.Fatalf("two processes starting together drew the same prefix %q", a)
	}
	for _, p := range []string{a, b} {
		if !events.ValidIDPrefix(p) {
			t.Errorf("generated prefix %q is not alphanumeric", p)
		}
	}

	first, second := NewID(), NewID()
	if first == second {
		t.Fatalf("NewID repeated %q", first)
	}
	for _, id := range []string{first, second} {
		if !idRe.MatchString(id) || !strings.HasPrefix(id, "DET-"+IDPrefix()+"-") {
			t.Errorf("id %q does not carry the instance prefix %q", id, IDPrefix())
		}
	}
}

func TestSetIDPrefix(t *testing.T) {
	old := IDPrefix()
	t.Cleanup(func() { _ = SetIDPrefix(old) })

	if err := SetIDPrefix("sensor1"); err != nil {
		t.Fatal(err)
	}
	if id := NewID(); !strings.HasPrefix(id, "DET-sensor1-") {
		t.Errorf("id %q ignores the configured prefix", id)
	}
	for _, bad := range []string{"", "pod-name-7d9", "a.b"} {
		if err := SetIDPrefix(bad); err == nil {
			t.Errorf("prefix %q must be refused: ids would not match the contract", bad)
		}
	}
	if IDPrefix() != "sensor1" {
		t.Errorf("a refused prefix must not replace the current one, got %q", IDPrefix())
	}
}

func TestIngestAssignsID(t *testing.T) {
	e := New(adguard.NewClient("http://127.0.0.1:1", "u", "p"), iocmatch.New(), time.Second)
	var got Alert
	e.OnAlert = func(a Alert) { got = a }
	e.Ingest(Alert{ClientIP: "192.168.1.5", SignalClass: SignalBeacon})
	if !idRe.MatchString(got.ID) || got.Severity == "" {
		t.Errorf("ingested alert = %+v", got)
	}
}

// TestResolveClientEnrichesEveryAlert: the hook existed but nothing set it,
// so every detection went out without a MAC. With it set, querylog and
// sensor detections both carry the device identity.
func TestResolveClientEnrichesEveryAlert(t *testing.T) {
	f := &fakeQueryLog{}
	e, got := newTestEngine(t, f, []iocmatch.IoC{{Value: "evil-ioc.com", Type: "domain", Confidence: 95}})
	var asked []string
	e.ResolveClient = func(ip string) (string, string) {
		asked = append(asked, ip)
		return "aa:bb:cc:dd:ee:66", "kids-tablet"
	}
	f.add("evil-ioc.com", "::ffff:192.168.1.66", time.Now().Add(time.Second))
	e.poll(context.Background())
	e.Ingest(Alert{ClientIP: "192.168.1.67", SignalClass: SignalBeacon})
	e.Ingest(Alert{ClientIP: "192.168.1.68", ClientMAC: "aa:bb:cc:dd:ee:68", SignalClass: SignalBeacon})

	if len(*got) != 3 {
		t.Fatalf("alerts = %d", len(*got))
	}
	for _, a := range (*got)[:2] {
		if a.ClientMAC != "aa:bb:cc:dd:ee:66" || a.ClientName != "kids-tablet" {
			t.Errorf("alert %s for %s carries mac=%q name=%q", a.ID, a.ClientIP, a.ClientMAC, a.ClientName)
		}
	}
	if got := strings.Join(asked, ","); got != "192.168.1.66,192.168.1.67" {
		t.Errorf("looked up %s; want canonical addresses, and no lookup when the sensor knew the MAC", got)
	}
}

// TestDNSAnswersCarryTheClient: the TLS heuristics need to know which
// device resolved an address, not just that some device did.
func TestDNSAnswersCarryTheClient(t *testing.T) {
	f := &fakeQueryLog{}
	e, _ := newTestEngine(t, f, nil)
	var seen []string
	e.OnDNSAnswer = func(client, ip, domain string, ttl int) {
		seen = append(seen, client+" "+ip+" "+domain)
	}
	f.add("cdn.example.", "192.168.1.66", time.Now().Add(time.Second), "203.0.113.5", "2001:db8::5")
	e.poll(context.Background())
	if got := strings.Join(seen, "|"); got != "192.168.1.66 203.0.113.5 cdn.example|192.168.1.66 2001:db8::5 cdn.example" {
		t.Errorf("answers seen: %q", got)
	}
}

func TestClampConfidence(t *testing.T) {
	for in, want := range map[int]int{-5: 0, 0: 0, 55: 55, 100: 100, 250: 100} {
		if got := ClampConfidence(in); got != want {
			t.Errorf("ClampConfidence(%d) = %d, want %d", in, got, want)
		}
	}
}
