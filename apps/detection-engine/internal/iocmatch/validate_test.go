package iocmatch

import (
	"fmt"
	"strings"
	"testing"
)

// TestRejectsBareSuffixIndicators is the regression test for the worst
// feed-poisoning outcome. MatchDomain walks every parent of a queried name,
// so an indicator of "com" matched EVERY .com lookup; with auto-block at
// critical/90 that is a DNS sinkhole on the entire internet, from one
// malformed feed row.
func TestRejectsBareSuffixIndicators(t *testing.T) {
	unsafe := []string{
		"com", "net", "org", "pl", "io", "co.uk", "com.pl", "duckdns.org",
		"amazonaws.com", "github.io", "vercel.app",
		".", "", "   ", "*",
	}
	for _, v := range unsafe {
		if got, err := ValidateDomainIndicator(v); err == nil {
			t.Errorf("ValidateDomainIndicator(%q) accepted %q — this would match every "+
				"name under that suffix", v, got)
		}
	}
}

func TestAcceptsRealIndicators(t *testing.T) {
	safe := map[string]string{
		"evil.com":              "evil.com",
		"EVIL.COM":              "evil.com",
		"evil.com.":             "evil.com",
		"*.evil.com":            "evil.com",
		"  c2.evil.com  ":       "c2.evil.com",
		"a.b.c.d.example":       "a.b.c.d.example",
		"xn--80ak6aa92e.com":    "xn--80ak6aa92e.com",
		"victim.duckdns.org":    "victim.duckdns.org",
		"malware.herokuapp.com": "malware.herokuapp.com",
	}
	for in, want := range safe {
		got, err := ValidateDomainIndicator(in)
		if err != nil {
			t.Errorf("ValidateDomainIndicator(%q) rejected a legitimate indicator: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ValidateDomainIndicator(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRejectsMalformedIndicators(t *testing.T) {
	bad := []string{
		"evil..com",
		"-evil.com",
		"evil-.com",
		"evil .com",
		"evil.com/path",
		"http://evil.com",
		"evil.com:8080",
		"user@evil.com",
		"evil\n.com",
		strings.Repeat("a", 64) + ".example",
		strings.Repeat("a.", 200) + "example",
	}
	for _, v := range bad {
		if _, err := ValidateDomainIndicator(v); err == nil {
			t.Errorf("ValidateDomainIndicator(%q) should have been rejected", v)
		}
	}
}

// TestAddRejectsPoisonedFeed exercises the trust boundary end to end: a feed
// batch mixing good rows with a bare TLD must load the good rows and drop the
// dangerous one, and the dangerous one must not match anything afterwards.
func TestAddRejectsPoisonedFeed(t *testing.T) {
	m := New()
	added, rejected := m.Add([]IoC{
		{Value: "c2.evil.example", Type: "domain", Confidence: 95, Source: "feed"},
		{Value: "com", Type: "domain", Confidence: 100, Source: "broken-feed"},
		{Value: "pl", Type: "domain", Confidence: 100, Source: "broken-feed"},
		{Value: "", Type: "domain", Confidence: 100, Source: "broken-feed"},
	})

	if added != 1 {
		t.Errorf("added = %d, want 1", added)
	}
	if rejected != 3 {
		t.Errorf("rejected = %d, want 3", rejected)
	}

	if _, ok := m.MatchDomain("c2.evil.example"); !ok {
		t.Error("the legitimate indicator should still match")
	}
	for _, benign := range []string{
		"google.com", "news.bbc.co.uk", "allegro.pl", "bank.example.com",
	} {
		if ioc, ok := m.MatchDomain(benign); ok {
			t.Errorf("benign domain %q matched poisoned indicator %q", benign, ioc.Value)
		}
	}
}

func TestAddRejectsCatchAllCIDR(t *testing.T) {
	m := New()
	_, rejected := m.Add([]IoC{
		{Value: "0.0.0.0/0", Type: "ip", Confidence: 100, Source: "broken-feed"},
		{Value: "::/0", Type: "ip", Confidence: 100, Source: "broken-feed"},
		{Value: "not-a-cidr/x", Type: "ip", Confidence: 100, Source: "broken-feed"},
	})
	if rejected != 3 {
		t.Errorf("rejected = %d, want 3", rejected)
	}
	if _, ok := m.MatchIP("8.8.8.8"); ok {
		t.Error("a catch-all CIDR must not be loaded: it would match every address")
	}
}

// TestAddIsIdempotentForCIDRs is the regression test for the memory leak.
// SyncLoop re-adds the full feed every IOC_SYNC_INTERVAL (5m in the deployed
// overlay). The CIDR list was a slice that Add() appended to unconditionally,
// so Spamhaus DROP's ~1000 prefixes grew by ~288k entries a day while MatchIP
// scanned all of them linearly for every DNS answer.
func TestAddIsIdempotentForCIDRs(t *testing.T) {
	m := New()
	feed := []IoC{
		{Value: "192.0.2.0/24", Type: "ip", Confidence: 80, Source: "spamhaus"},
		{Value: "198.51.100.0/24", Type: "ip", Confidence: 80, Source: "spamhaus"},
		{Value: "203.0.113.0/24", Type: "ip", Confidence: 80, Source: "spamhaus"},
	}

	for i := 0; i < 50; i++ { // ~4 hours of 5-minute re-syncs
		m.Add(feed)
	}

	if got := m.CIDRCount(); got != len(feed) {
		t.Fatalf("CIDRCount() = %d after 50 re-syncs, want %d — the CIDR set must be "+
			"deduplicated like every other indicator type", got, len(feed))
	}
	if got := m.Size(); got != len(feed) {
		t.Errorf("Size() = %d, want %d", got, len(feed))
	}
	if _, ok := m.MatchIP("192.0.2.55"); !ok {
		t.Error("deduplicated CIDR should still match")
	}
}

func TestAddIsIdempotentForAllTypes(t *testing.T) {
	m := New()
	feed := []IoC{
		{Value: "evil.example", Type: "domain", Confidence: 90},
		{Value: "192.0.2.10", Type: "ip", Confidence: 90},
		{Value: "192.0.2.0/24", Type: "ip", Confidence: 90},
		{Value: "d41d8cd98f00b204e9800998ecf8427e", Type: "md5", Confidence: 90},
	}
	for i := 0; i < 20; i++ {
		m.Add(feed)
	}
	if got := m.Size(); got != len(feed) {
		t.Errorf("Size() = %d after repeated syncs, want %d", got, len(feed))
	}
}

// TestIPNormalization covers the missed-detection case: raw string keys meant
// 2001:DB8::1 and 2001:db8::1 were different indicators.
func TestIPNormalization(t *testing.T) {
	m := New()
	m.Add([]IoC{
		{Value: "2001:DB8::1", Type: "ip", Confidence: 90, Source: "feed"},
		{Value: "192.0.2.5:443", Type: "ip", Confidence: 90, Source: "feed"},
	})

	for _, probe := range []string{"2001:db8::1", "2001:DB8:0:0:0:0:0:1"} {
		if _, ok := m.MatchIP(probe); !ok {
			t.Errorf("MatchIP(%q) should match the normalized indicator", probe)
		}
	}
	if _, ok := m.MatchIP("192.0.2.5"); !ok {
		t.Error("host:port indicator should match the bare host")
	}
}

func TestAddReportsUnknownType(t *testing.T) {
	m := New()
	added, rejected := m.Add([]IoC{{Value: "x", Type: "mystery", Confidence: 50}})
	if added != 0 || rejected != 1 {
		t.Errorf("added=%d rejected=%d, want 0/1", added, rejected)
	}
}

func TestExportURLAcceptsEitherSpelling(t *testing.T) {
	want := "http://threat-intel-sync:8083/export/json"
	for _, in := range []string{
		"http://threat-intel-sync:8083",
		"http://threat-intel-sync:8083/",
		"http://threat-intel-sync:8083/export/json",
		"  http://threat-intel-sync:8083/export/json/  ",
	} {
		if got := exportURL(in); got != want {
			t.Errorf("exportURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func ExampleValidateDomainIndicator() {
	_, err := ValidateDomainIndicator("com")
	fmt.Println(err != nil)
	// Output: true
}
