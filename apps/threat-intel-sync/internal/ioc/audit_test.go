package ioc

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Regression tests for the 2026-11 audit findings that live in the store.
// Each reproduces the auditor's scenario and fails on the old code.

// TestAuditValidateBypass (TI-2): every candidate the auditor got through the
// old deny-list validator must now be refused at ingest, and the legitimate
// ones beside them kept.
func TestAuditValidateBypass(t *testing.T) {
	refused := []Indicator{
		{Type: TypeDomain, Value: "*.*.*"},
		{Type: TypeDomain, Value: "*.*.com"},
		{Type: TypeDomain, Value: "*.*.co.uk"},
		{Type: TypeDomain, Value: "com.*"},
		{Type: TypeDomain, Value: "co.kr"},
		{Type: TypeDomain, Value: "com.ar"},
		{Type: TypeDomain, Value: "blogspot.com"},
		{Type: TypeDomain, Value: "s3.amazonaws.com"},
		{Type: TypeDomain, Value: "blob.core.windows.net"},
		{Type: TypeDomain, Value: "evil.example^$dnsrewrite=203.0.113.9"},
		{Type: TypeDomain, Value: "a.b|c^$important"},
		{Type: TypeDomain, Value: "x.y\x00z"},
		{Type: TypeDomain, Value: "1.2.3.4"},
		{Type: TypeIP, Value: "0.0.0.0/1"},
		{Type: TypeIP, Value: "128.0.0.0/1"},
		{Type: TypeIP, Value: "::/1"},
		{Type: TypeIP, Value: "10.0.0.0/8"},
		{Type: TypeIP, Value: "192.168.0.0/16"},
		{Type: TypeIP, Value: "127.0.0.0/8"},
		{Type: TypeIP, Value: "192.168.1.1"},
		{Type: TypeIP, Value: "255.255.255.255"},
		{Type: TypeIP, Value: "224.0.0.251"},
		{Type: TypeMD5, Value: "not-a-hash;rm"},
		{Type: TypeSHA256, Value: "zz"},
		{Type: TypeURL, Value: "http://x/\tIntel::URL\n0.0.0.0/0\tIntel::SUBNET\tx\t-\t-"},
	}
	for _, c := range refused {
		if v, err := Validate(c); err == nil {
			t.Errorf("Validate(%s %q) accepted %q", c.Type, c.Value, v.Value)
		}
	}

	s := NewStore()
	accepted, rejected := s.UpsertAll(append(refused,
		// A public address, not a public resolver: 8.8.8.8 used to stand
		// here, and is now refused by the never-block list (step 134).
		Indicator{Type: TypeIP, Value: "203.0.113.50", Source: "feed"},
		Indicator{Type: TypeDomain, Value: "c2.evil.example", Source: "feed"},
	))
	if accepted != 2 || rejected != len(refused) {
		t.Errorf("UpsertAll accepted=%d rejected=%d, want 2/%d", accepted, rejected, len(refused))
	}
}

// TestAuditFreeTextIsCleanedAtIngest (TI-1, ingest half): control characters
// in Threat, Reference, Source and Tags never reach the store.
func TestAuditFreeTextIsCleanedAtIngest(t *testing.T) {
	s := NewStore()
	s.UpsertAll([]Indicator{
		{Type: TypeIP, Value: "203.0.113.7", Source: "threatfox",
			Threat: "Mozi\t-\n0.0.0.0/0\tIntel::SUBNET\tthreatfox\tinjected"},
		{Type: TypeIP, Value: "203.0.113.8", Source: "threatfox",
			Reference: "https://x/\n192.168.1.1\tIntel::ADDR\tthreatfox\tinjected-gateway\t-",
			Tags:      []string{"c2\nx", "\x1b[31m"}},
	})
	for _, ind := range s.All() {
		for _, f := range append([]string{ind.Source, ind.Threat, ind.Reference}, ind.Tags...) {
			if strings.ContainsAny(f, "\t\n\r\x00\x1b") {
				t.Errorf("%s: control character survived ingest in %q", ind.Value, f)
			}
		}
	}
}

// TestAuditTTLSemantics (TI-7): expiry is measured from the last time a feed
// asserted the indicator. The auditor's three rows: a Feodo C2 still on the
// list but "last online" 45 days ago, a MISP attribute last edited 31 days
// ago and still published, and an undated Spamhaus range that is later
// delisted. The old store pruned the first two every cycle (they flapped in
// and out of every export) and kept the third forever.
func TestAuditTTLSemantics(t *testing.T) {
	ttl := 30 * 24 * time.Hour
	start := time.Now().UTC()
	clock := start
	s := NewStore(WithClock(func() time.Time { return clock }))

	feodoRow := Indicator{Type: TypeIP, Value: "203.0.113.10", Source: "feodo", Confidence: 90,
		FirstSeen: start.Add(-400 * 24 * time.Hour), LastSeen: start.Add(-45 * 24 * time.Hour)}
	mispRow := Indicator{Type: TypeDomain, Value: "apt.c2.example", Source: "misp",
		FirstSeen: start.Add(-31 * 24 * time.Hour)}
	dropRow := Indicator{Type: TypeIP, Value: "198.51.100.0/24", Source: "spamhaus-drop", Confidence: 95}

	cycle := func(withDrop bool) {
		s.UpsertFeed("feodo", []Indicator{feodoRow})
		s.UpsertFeed("misp", []Indicator{mispRow})
		if withDrop {
			s.UpsertFeed("spamhaus", []Indicator{dropRow})
		}
		for _, f := range []string{"feodo", "misp", "spamhaus"} {
			s.MarkFeedSuccess(f, clock)
		}
		s.PruneExpired(clock.Add(-ttl))
	}

	for day := 0; day < 3; day++ {
		cycle(true)
		for _, v := range []string{"203.0.113.10", "apt.c2.example", "198.51.100.0/24"} {
			if !has(s, v) {
				t.Fatalf("day %d: %s is still asserted every cycle but was pruned", day, v)
			}
		}
		clock = clock.Add(24 * time.Hour)
	}

	// Spamhaus delists the range; feodo and misp keep asserting their rows.
	for day := 0; day < 29; day++ {
		cycle(false)
		clock = clock.Add(24 * time.Hour)
	}
	if !has(s, "198.51.100.0/24") {
		t.Fatal("a delisted range must survive until the TTL since its last assertion has passed")
	}
	clock = clock.Add(2 * 24 * time.Hour)
	cycle(false)
	if has(s, "198.51.100.0/24") {
		t.Error("the delisted Spamhaus range is still served 32 days after its last assertion")
	}
	if !has(s, "203.0.113.10") || !has(s, "apt.c2.example") {
		t.Error("rows still asserted every cycle were pruned")
	}
}

// TestPruneExpiredSparesUnreachableFeeds: a feed that has not answered since
// it last asserted its indicators keeps them, however long the outage.
func TestPruneExpiredSparesUnreachableFeeds(t *testing.T) {
	start := time.Now().UTC()
	clock := start
	s := NewStore(WithClock(func() time.Time { return clock }))
	s.UpsertFeed("misp", []Indicator{{Type: TypeDomain, Value: "apt.c2.example", Source: "misp"}})
	s.MarkFeedSuccess("misp", clock)

	clock = start.Add(90 * 24 * time.Hour) // MISP unreachable for 90 days
	if n := s.PruneExpired(clock.Add(-30 * 24 * time.Hour)); n != 0 || !has(s, "apt.c2.example") {
		t.Fatalf("an outage aged out the unreachable feed's indicators (pruned %d)", n)
	}
	s.MarkFeedSuccess("misp", clock) // MISP answers, without the indicator
	if n := s.PruneExpired(clock.Add(-30 * 24 * time.Hour)); n != 1 || has(s, "apt.c2.example") {
		t.Errorf("once the feed answered without it, the indicator should expire (pruned %d)", n)
	}
}

// TestLoweredConfidenceTakesEffect: each feed's assertion is replaced on
// every upsert, so a feed lowering its confidence is honoured instead of the
// maximum ever seen, and a withdrawn assertion stops counting.
func TestLoweredConfidenceTakesEffect(t *testing.T) {
	clock := time.Now().UTC()
	s := NewStore(WithClock(func() time.Time { return clock }))
	s.UpsertFeed("threatfox", []Indicator{{Type: TypeDomain, Value: "evil.example", Source: "threatfox", Confidence: 100, Threat: "Mozi"}})
	s.UpsertFeed("misp", []Indicator{{Type: TypeDomain, Value: "evil.example", Source: "misp", Confidence: 40}})
	if got := s.All()[0]; got.Confidence != 100 || got.Source != "misp,threatfox" || got.Threat != "Mozi" {
		t.Fatalf("aggregate = %+v", got)
	}

	s.UpsertFeed("threatfox", []Indicator{{Type: TypeDomain, Value: "evil.example", Source: "threatfox", Confidence: 50}})
	if got := s.All()[0].Confidence; got != 50 {
		t.Errorf("confidence = %d after the feed lowered it to 50", got)
	}

	s.MarkFeedSuccess("threatfox", clock.Add(time.Hour))
	s.MarkFeedSuccess("misp", clock.Add(-time.Hour))
	clock = clock.Add(2 * time.Hour)
	s.PruneExpired(clock.Add(-30 * time.Minute)) // threatfox answered without it
	got := s.All()
	if len(got) != 1 || got[0].Confidence != 40 || got[0].Source != "misp" {
		t.Errorf("after threatfox withdrew it, aggregate = %+v; want misp's assertion only", got)
	}
}

// TestStoreCapRefusesNewIndicators (TI-4): the store no longer grows without
// bound. At the cap, new keys are refused and counted; existing ones are
// still refreshed, so a flood cannot evict what other feeds vouched for.
func TestStoreCapRefusesNewIndicators(t *testing.T) {
	s := NewStore(WithMaxIndicators(3))
	st := s.UpsertFeed("spamhaus", []Indicator{
		{Type: TypeIP, Value: "198.51.100.0/24"},
		{Type: TypeIP, Value: "203.0.113.0/24"},
	})
	if st.Accepted != 2 {
		t.Fatalf("accepted = %d", st.Accepted)
	}

	var flood []Indicator
	for i := 0; i < 1000; i++ {
		flood = append(flood, Indicator{Type: TypeDomain, Value: fmt.Sprintf("x%d.flood.example", i)})
	}
	flood = append(flood, Indicator{Type: TypeIP, Value: "198.51.100.0/24", Confidence: 80})
	st = s.UpsertFeed("hostile", flood)
	if s.Len() != 3 {
		t.Errorf("Len() = %d, want the cap of 3", s.Len())
	}
	if st.Accepted != 2 || st.Dropped != 999 {
		t.Errorf("accepted=%d dropped=%d, want 2 (one new key + one refresh) / 999", st.Accepted, st.Dropped)
	}
	if !has(s, "203.0.113.0/24") {
		t.Error("the flood evicted an indicator another feed vouched for")
	}
}

func TestUpsertFeedMergesDuplicatesInBatch(t *testing.T) {
	s := NewStore()
	st := s.UpsertFeed("feodo", []Indicator{
		{Type: TypeIP, Value: "203.0.113.10:443", Source: "feodo", Confidence: 70, Tags: []string{"c2"}},
		{Type: TypeIP, Value: "203.0.113.10:8080", Source: "feodo", Confidence: 90, Tags: []string{"botnet"}},
	})
	if st.Accepted != 2 || s.Len() != 1 {
		t.Fatalf("accepted=%d len=%d", st.Accepted, s.Len())
	}
	got := s.All()[0]
	if got.Value != "203.0.113.10" || got.Confidence != 90 || len(got.Tags) != 2 || got.LastAsserted.IsZero() {
		t.Errorf("merged = %+v", got)
	}
}

func TestRejectedRowLoggingIsBounded(t *testing.T) {
	s := NewStore()
	var bad []Indicator
	for i := 0; i < 5000; i++ {
		bad = append(bad, Indicator{Type: TypeDomain, Value: strings.Repeat("a", 300) + ".example"})
	}
	if st := s.UpsertFeed("hostile", bad); st.Rejected != 5000 || st.Accepted != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func has(s *Store, v string) bool {
	for _, i := range s.All() {
		if i.Value == v {
			return true
		}
	}
	return false
}
