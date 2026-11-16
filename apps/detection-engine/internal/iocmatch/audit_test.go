package iocmatch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestAuditBroadIndicatorsRefused (DE-15): the matcher's validator mirrored
// threat-intel-sync's weak rules, so it backstopped nothing. Every candidate
// the auditor loaded — catch-all and private CIDRs, the gateway, public
// suffixes missing from the hand-written list — is now refused, and none of
// the benign lookups matches.
func TestAuditBroadIndicatorsRefused(t *testing.T) {
	m := New()
	in := []IoC{
		{Type: "ip", Value: "0.0.0.0/1"}, {Type: "ip", Value: "128.0.0.0/1"},
		{Type: "ip", Value: "2000::/3"},
		{Type: "ip", Value: "10.0.0.0/8"}, {Type: "ip", Value: "192.168.0.0/16"},
		{Type: "ip", Value: "0.0.0.0/8"}, {Type: "ip", Value: "0.0.0.0"}, {Type: "ip", Value: "127.0.0.1"},
		{Type: "ip", Value: "192.168.1.1"}, {Type: "ip", Value: "224.0.0.251"},
		{Type: "domain", Value: "co.kr"}, {Type: "domain", Value: "com.tw"},
		{Type: "domain", Value: "edu.pl"}, {Type: "domain", Value: "waw.pl"},
		{Type: "domain", Value: "com.ua"}, {Type: "domain", Value: "in-addr.arpa"},
		{Type: "domain", Value: "s3.amazonaws.com"}, {Type: "domain", Value: "googleusercontent.com"},
		{Type: "domain", Value: "blogspot.com"}, {Type: "domain", Value: "trycloudflare.com"},
		{Type: "domain", Value: "core.windows.net"}, {Type: "domain", Value: "*.*.*"},
		{Type: "ja3", Value: "abc123"}, {Type: "md5", Value: "not-a-hash;rm"},
	}
	for i := range in {
		in[i].Confidence = 95
	}
	if added, rejected := m.Add(in); added != 0 || rejected != len(in) {
		t.Errorf("added=%d rejected=%d, want 0/%d", added, rejected, len(in))
	}
	st := m.Replace(in)
	if st.Accepted != 0 || st.Invalid != len(in) || st.Unsupported != 0 {
		t.Errorf("Replace stats = %+v", st)
	}
	for _, ip := range []string{"8.8.8.8", "142.250.74.14", "2a00:1450:4001:81b::200e", "192.168.1.1", "0.0.0.0", "127.0.0.1"} {
		if ioc, ok := m.MatchIP(ip); ok {
			t.Errorf("MatchIP(%s) matched %q", ip, ioc.Value)
		}
	}
	for _, d := range []string{"www.naver.co.kr", "uw.edu.pl", "1.1.168.192.in-addr.arpa",
		"my-bucket.s3.amazonaws.com", "lh3.googleusercontent.com", "x.blogspot.com",
		"login.microsoftonline.core.windows.net"} {
		if ioc, ok := m.MatchDomain(d); ok {
			t.Errorf("MatchDomain(%s) matched %q", d, ioc.Value)
		}
	}
}

// TestAuditNormalisation (DE-20): no IDN normalisation on either side meant
// a U-label indicator never matched the A-label a resolver logs, and the
// other way round; IPv4-mapped spellings missed too.
func TestAuditNormalisation(t *testing.T) {
	aLabel, err := ValidateDomainIndicator("münchen-c2.example")
	if err != nil || !strings.HasPrefix(aLabel, "xn--") {
		t.Fatalf("A-label of münchen-c2.example: %q, %v", aLabel, err)
	}
	m := New()
	st := m.Replace([]IoC{
		{Type: "domain", Value: "bücher-c2.example", Confidence: 95}, // U-label spelling in the feed
		{Type: "domain", Value: aLabel, Confidence: 95},              // A-label spelling in the feed
		{Type: "ip", Value: "203.0.113.7", Confidence: 95},
		{Type: "ip", Value: "2001:DB8::0001", Confidence: 95},
		{Type: "ip", Value: "::ffff:198.51.100.0/120", Confidence: 95}, // v4-mapped prefix
	})
	if st.Accepted != 5 {
		t.Fatalf("stats = %+v", st)
	}
	for _, q := range []string{
		"xn--bcher-c2-65a.example", // what a resolver/AdGuard logs for bücher-c2.example
		"bücher-c2.example", "BÜCHER-C2.example", "sub.bücher-c2.example.",
		"münchen-c2.example", strings.ToUpper(aLabel) + ".",
	} {
		if _, ok := m.MatchDomain(q); !ok {
			t.Errorf("MatchDomain(%q) missed", q)
		}
	}
	for _, q := range []string{"::ffff:203.0.113.7", "0:0:0:0:0:ffff:cb00:7107", "2001:db8:0:0:0:0:0:1",
		"198.51.100.9", "::ffff:198.51.100.9", "203.0.113.7 "} {
		if _, ok := m.MatchIP(q); !ok {
			t.Errorf("MatchIP(%q) missed", q)
		}
	}
	if _, ok := m.MatchIP("203.000.113.007"); ok {
		t.Error("an ambiguous leading-zero address must not be guessed at")
	}
}

// TestAuditSyncIsAddOnly (DE-16): SyncLoop only ever added. An indicator
// withdrawn upstream kept matching until the pod restarted, a lowered
// confidence never took effect, and the valid url / cert-sha256 rows were
// counted as invalid, which would keep the feed-poisoning alert firing.
func TestAuditSyncIsAddOnly(t *testing.T) {
	var body atomic.Value
	body.Store(`[{"Type":"domain","Value":"mistakenly-listed.example","Source":"threatfox","Confidence":100},
	          {"Type":"domain","Value":"other.example","Source":"threatfox","Confidence":100},
	          {"Type":"url","Value":"http://x.example/a.exe","Source":"urlhaus"},
	          {"Type":"cert-sha256","Value":"aa","Source":"misp"}]`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body.Load())
	}))
	defer srv.Close()

	m := New()
	m.Add([]IoC{{Type: "domain", Value: "static-list.example", Confidence: 80}})
	invalidBefore := metricValue("detection_engine_ioc_sync_failures_total", "reason", "invalid_indicator")
	unsupportedBefore := metricValue("detection_engine_ioc_sync_unsupported_total", "type", "url")

	syncOnce(context.Background(), m, srv.URL)
	if _, ok := m.MatchDomain("mistakenly-listed.example"); !ok {
		t.Fatal("first sync did not load")
	}
	if got := metricValue("detection_engine_ioc_sync_failures_total", "reason", "invalid_indicator") - invalidBefore; got != 0 {
		t.Errorf("valid but unsupported types were counted as invalid (%v)", got)
	}
	if got := metricValue("detection_engine_ioc_sync_unsupported_total", "type", "url") - unsupportedBefore; got != 1 {
		t.Errorf("unsupported url counter rose by %v, want 1", got)
	}

	// upstream withdraws the false positive and lowers the other's confidence
	body.Store(`[{"Type":"domain","Value":"other.example","Source":"threatfox","Confidence":50}]`)
	syncOnce(context.Background(), m, srv.URL)
	if _, ok := m.MatchDomain("mistakenly-listed.example"); ok {
		t.Error("a withdrawn indicator still matches after the re-sync")
	}
	if ioc, _ := m.MatchDomain("other.example"); ioc.Confidence != 50 || ioc.Severity != "medium" {
		t.Errorf("lowered confidence did not take effect: %+v", ioc)
	}
	if _, ok := m.MatchDomain("static-list.example"); !ok {
		t.Error("the static list must survive a feed sync")
	}
	if got := metricValue("detection_engine_ioc_sync_indicators"); got != 1 {
		t.Errorf("ioc_sync_indicators = %v, want the 1 indicator now loaded", got)
	}
	if m.Size() != 2 {
		t.Errorf("Size() = %d, want static 1 + feed 1", m.Size())
	}
}

// TestSyncKeepsCurrentSetOnBadExport: a threat-intel-sync that is not ready
// (503), answers an empty list, sends nothing usable or an oversized or
// broken body must not empty the matcher. The detection-engine used to
// record "successful sync of 0 indicators" after a restart during an outage.
func TestSyncKeepsCurrentSetOnBadExport(t *testing.T) {
	var status atomic.Int32
	var body atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(int(status.Load()))
		fmt.Fprint(w, body.Load())
	}))
	defer srv.Close()

	m := New()
	status.Store(200)
	body.Store(`[{"Type":"domain","Value":"c2.evil.example","Confidence":90}]`)
	syncOnce(context.Background(), m, srv.URL)

	for _, c := range []struct {
		reason string
		status int32
		body   string
	}{
		{"not_ready", 503, "threat intel not ready: no successful sync yet"},
		{"status", 500, "boom"},
		{"empty", 200, "[]"},
		{"nothing_accepted", 200, `[{"Type":"domain","Value":"com","Confidence":90},{"Type":"ip","Value":"0.0.0.0/1"}]`},
		{"decode", 200, `[{"Type":"domain","Value":"truncated.example"`},
		{"decode", 200, `{"not":"an array"}`},
	} {
		before := metricValue("detection_engine_ioc_sync_failures_total", "reason", c.reason)
		status.Store(c.status)
		body.Store(c.body)
		syncOnce(context.Background(), m, srv.URL)
		if _, ok := m.MatchDomain("c2.evil.example"); !ok {
			t.Errorf("%s: the current set was replaced", c.reason)
		}
		if got := metricValue("detection_engine_ioc_sync_failures_total", "reason", c.reason) - before; got != 1 {
			t.Errorf("%s: failure counter rose by %v", c.reason, got)
		}
	}
}

func TestSyncRefusesOversizedExport(t *testing.T) {
	defer func(old int64) { maxSyncBytes = old }(maxSyncBytes)
	maxSyncBytes = 1 << 20
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[")
		row := `{"Type":"domain","Value":"` + strings.Repeat("a", 60) + `.example","Threat":"` + strings.Repeat("t", 900) + `"},`
		for i := 0; i < int(maxSyncBytes)/len(row)+10; i++ {
			if _, err := fmt.Fprint(w, row); err != nil {
				return
			}
		}
		fmt.Fprint(w, `{"Type":"domain","Value":"z.example"}]`)
	}))
	defer srv.Close()
	m := New()
	before := metricValue("detection_engine_ioc_sync_failures_total", "reason", "too_large")
	syncOnce(context.Background(), m, srv.URL)
	if got := metricValue("detection_engine_ioc_sync_failures_total", "reason", "too_large") - before; got != 1 || m.Size() != 0 {
		t.Errorf("too_large rose by %v, size %d", got, m.Size())
	}
}

// TestReplaceIsAtomicUnderConcurrentLookups: lookups racing a swap see a
// complete set, old or new. Run with -race.
func TestReplaceIsAtomicUnderConcurrentLookups(t *testing.T) {
	m := New()
	setA := []IoC{{Type: "domain", Value: "a.example", Confidence: 90}, {Type: "ip", Value: "198.51.100.0/24", Confidence: 90}}
	setB := []IoC{{Type: "domain", Value: "b.example", Confidence: 90}, {Type: "ip", Value: "203.0.113.0/24", Confidence: 90}}
	m.Replace(setA)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if n := m.Size(); n != 2 {
					t.Errorf("Size() = %d during a swap: a half-built or merged set was visible", n)
					return
				}
				m.MatchDomain("x.a.example")
				m.MatchIP("198.51.100.7")
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if i%2 == 0 {
			m.Replace(setB)
		} else {
			m.Replace(setA)
		}
	}
	close(stop)
	wg.Wait()
}

func TestCIDRMostSpecificAndPrecedence(t *testing.T) {
	m := New()
	m.Add([]IoC{{Type: "ip", Value: "198.51.100.0/24", Confidence: 95, Source: "static"}})
	m.Replace([]IoC{
		{Type: "ip", Value: "198.51.0.0/16", Confidence: 60, Source: "wide"},
		{Type: "ip", Value: "198.51.100.128/25", Confidence: 70, Source: "narrow"},
		{Type: "ip", Value: "2001:db8::/32", Confidence: 70, Source: "v6"},
		{Type: "ip", Value: "198.51.100.200", Confidence: 10, Source: "exact"},
	})
	for ip, want := range map[string]string{
		"198.51.100.200": "exact", "198.51.100.130": "static", "198.51.1.1": "wide", "2001:db8::5": "v6",
	} {
		if ioc, ok := m.MatchIP(ip); !ok || ioc.Source != want {
			t.Errorf("MatchIP(%s) = %q, want %q", ip, ioc.Source, want)
		}
	}
	if m.CIDRCount() != 4 {
		t.Errorf("CIDRCount = %d", m.CIDRCount())
	}
	if _, ok := m.MatchIP("not-an-ip"); ok {
		t.Error("garbage matched")
	}
}

func TestFreeTextCleanedAtMatchBoundary(t *testing.T) {
	m := New()
	m.Replace([]IoC{{Type: "domain", Value: "c2.evil.example", Confidence: 90,
		Threat: "Mozi\n{\"forged\":true}\t", Source: "feed\x1b[31m", Tags: []string{"c2\n", "c2"}}})
	ioc, _ := m.MatchDomain("c2.evil.example")
	if strings.ContainsAny(ioc.Threat+ioc.Source+strings.Join(ioc.Tags, ""), "\n\t\x1b") || len(ioc.Tags) != 1 {
		t.Errorf("control characters reached the alert path: %+v", ioc)
	}
	if st := m.Replace([]IoC{{Type: "domain", Value: "c2.evil.example", Confidence: 101}}); st.Invalid != 1 {
		t.Errorf("out-of-range confidence accepted: %+v", st)
	}
}

// metricValue reads one series from the default registry. It stands in for
// prometheus/testutil, which would add a module dependency for tests only.
func metricValue(name string, labels ...string) float64 {
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	next:
		for _, m := range mf.GetMetric() {
			for i := 0; i+1 < len(labels); i += 2 {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == labels[i] && lp.GetValue() == labels[i+1] {
						found = true
					}
				}
				if !found {
					continue next
				}
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue()
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue()
			}
		}
	}
	return 0
}
