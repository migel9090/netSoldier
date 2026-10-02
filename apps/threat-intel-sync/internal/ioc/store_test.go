package ioc

import (
	"testing"
	"time"
)

func TestStoreUpsertNew(t *testing.T) {
	s := NewStore()
	s.Upsert(Indicator{Type: TypeDomain, Value: "evil.com", Source: "test", Confidence: 80})

	if s.Len() != 1 {
		t.Fatalf("expected 1 indicator, got %d", s.Len())
	}
}

func TestStoreUpsertDeduplicate(t *testing.T) {
	s := NewStore()
	s.Upsert(Indicator{Type: TypeDomain, Value: "evil.com", Source: "src1", Confidence: 50})
	s.Upsert(Indicator{Type: TypeDomain, Value: "evil.com", Source: "src2", Confidence: 80})

	if s.Len() != 1 {
		t.Fatalf("expected 1 after dedup, got %d", s.Len())
	}

	all := s.All()
	if all[0].Confidence != 80 {
		t.Fatalf("merge should keep higher confidence, got %d", all[0].Confidence)
	}
	if all[0].Source != "src1,src2" {
		t.Fatalf("merge should combine sources, got %q", all[0].Source)
	}
}

func TestStoreUpsertCaseInsensitiveKey(t *testing.T) {
	s := NewStore()
	s.Upsert(Indicator{Type: TypeDomain, Value: "EVIL.COM", Source: "a", Confidence: 50})
	s.Upsert(Indicator{Type: TypeDomain, Value: "evil.com", Source: "b", Confidence: 60})

	if s.Len() != 1 {
		t.Fatalf("key should be case-insensitive, got %d", s.Len())
	}
}

func TestStoreUpsertAll(t *testing.T) {
	s := NewStore()
	s.UpsertAll([]Indicator{
		{Type: TypeDomain, Value: "a.com", Source: "test"},
		{Type: TypeIP, Value: "1.2.3.4", Source: "test"},
		{Type: TypeDomain, Value: "b.com", Source: "test"},
	})

	if s.Len() != 3 {
		t.Fatalf("expected 3, got %d", s.Len())
	}
}

func TestStoreByType(t *testing.T) {
	s := NewStore()
	s.UpsertAll([]Indicator{
		{Type: TypeDomain, Value: "a.com"},
		{Type: TypeDomain, Value: "b.com"},
		{Type: TypeIP, Value: "1.2.3.4"},
	})

	domains := s.ByType(TypeDomain)
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}

	ips := s.ByType(TypeIP)
	if len(ips) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(ips))
	}
}

func TestStoreClear(t *testing.T) {
	s := NewStore()
	s.Upsert(Indicator{Type: TypeDomain, Value: "evil.com"})
	s.Clear()

	if s.Len() != 0 {
		t.Fatalf("expected 0 after clear, got %d", s.Len())
	}
}

func TestIndicatorKey(t *testing.T) {
	ind := Indicator{Type: TypeDomain, Value: "Evil.Com"}
	if ind.Key() != "domain:evil.com" {
		t.Fatalf("expected domain:evil.com, got %q", ind.Key())
	}
}

func TestIndicatorMergeConfidence(t *testing.T) {
	a := Indicator{Type: TypeDomain, Value: "evil.com", Confidence: 50, Source: "a"}
	b := Indicator{Type: TypeDomain, Value: "evil.com", Confidence: 80, Source: "b"}
	a.Merge(b)

	if a.Confidence != 80 {
		t.Fatalf("expected confidence 80, got %d", a.Confidence)
	}
}

func TestIndicatorMergeFirstSeen(t *testing.T) {
	earlier := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	a := Indicator{FirstSeen: later, Source: "a"}
	b := Indicator{FirstSeen: earlier, Source: "b"}
	a.Merge(b)

	if !a.FirstSeen.Equal(earlier) {
		t.Fatalf("merge should keep earlier FirstSeen")
	}
}

func TestIndicatorMergeTags(t *testing.T) {
	a := Indicator{Tags: []string{"c2", "botnet"}, Source: "a"}
	b := Indicator{Tags: []string{"botnet", "malware"}, Source: "b"}
	a.Merge(b)

	if len(a.Tags) != 3 {
		t.Fatalf("expected 3 merged tags (deduped), got %d: %v", len(a.Tags), a.Tags)
	}
}

func TestIndicatorMergeThreat(t *testing.T) {
	a := Indicator{Source: "a"}
	b := Indicator{Threat: "emotet", Source: "b"}
	a.Merge(b)

	if a.Threat != "emotet" {
		t.Fatalf("merge should fill empty Threat, got %q", a.Threat)
	}
}

func TestIndicatorMergeSourceDedup(t *testing.T) {
	a := Indicator{Source: "threatfox"}
	b := Indicator{Source: "threatfox"}
	a.Merge(b)

	if a.Source != "threatfox" {
		t.Fatalf("should not duplicate source, got %q", a.Source)
	}
}

// TestUpsertAllRejectsUnsafeIndicators is the ingest-side half of the
// feed-poisoning guard. The detection-engine walks parent domains when
// matching, so a bare TLD matches everything under it; dropping it here also
// keeps it out of every downstream export (Suricata, Zeek, AdGuard, Vector).
func TestUpsertAllRejectsUnsafeIndicators(t *testing.T) {
	s := NewStore()
	accepted, rejected := s.UpsertAll([]Indicator{
		{Type: TypeDomain, Value: "c2.evil.example", Source: "feed", Confidence: 90},
		{Type: TypeDomain, Value: "com", Source: "broken", Confidence: 100},
		{Type: TypeDomain, Value: "co.uk", Source: "broken", Confidence: 100},
		{Type: TypeIP, Value: "0.0.0.0/0", Source: "broken", Confidence: 100},
		{Type: TypeIP, Value: "127.0.0.1", Source: "broken", Confidence: 100},
		{Type: TypeDomain, Value: "", Source: "broken", Confidence: 100},
		{Type: "mystery", Value: "x", Source: "broken", Confidence: 50},
	})

	if accepted != 1 {
		t.Errorf("accepted = %d, want 1", accepted)
	}
	if rejected != 6 {
		t.Errorf("rejected = %d, want 6", rejected)
	}
	if s.Len() != 1 {
		t.Errorf("store should hold only the safe indicator, Len() = %d", s.Len())
	}
}

func TestUpsertAllNormalizesValues(t *testing.T) {
	s := NewStore()
	s.UpsertAll([]Indicator{
		{Type: TypeDomain, Value: "  EVIL.Example.  ", Source: "feed", Confidence: 90},
		{Type: TypeIP, Value: "2001:DB8::1", Source: "feed", Confidence: 90},
		{Type: TypeIP, Value: "192.0.2.5:8080", Source: "feed", Confidence: 90},
	})

	values := map[string]bool{}
	for _, ind := range s.All() {
		values[ind.Value] = true
	}
	for _, want := range []string{"evil.example", "2001:db8::1", "192.0.2.5"} {
		if !values[want] {
			t.Errorf("expected normalized value %q in store, got %v", want, values)
		}
	}
}

// TestPruneBefore covers the other half of the "indicators never expire"
// problem: a domain a feed has withdrawn (false positive, or a lapsed
// registration taken over by a legitimate owner) used to keep matching
// forever because the store only ever grew.
func TestPruneBefore(t *testing.T) {
	s := NewStore()
	now := time.Now().UTC()

	s.UpsertAll([]Indicator{
		{Type: TypeDomain, Value: "fresh.example", Source: "feed", Confidence: 90, LastSeen: now},
		{Type: TypeDomain, Value: "stale.example", Source: "feed", Confidence: 90,
			LastSeen: now.Add(-60 * 24 * time.Hour)},
		{Type: TypeDomain, Value: "undated.example", Source: "feed", Confidence: 90},
	})

	removed := s.PruneBefore(now.Add(-30 * 24 * time.Hour))
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}

	remaining := map[string]bool{}
	for _, ind := range s.All() {
		remaining[ind.Value] = true
	}
	if !remaining["fresh.example"] {
		t.Error("a recently seen indicator must survive pruning")
	}
	if remaining["stale.example"] {
		t.Error("the stale indicator should have been pruned")
	}
	if !remaining["undated.example"] {
		t.Error("an undated indicator should be kept rather than guessed at")
	}
}

func TestValidateIndicatorTypes(t *testing.T) {
	ok := []Indicator{
		{Type: TypeDomain, Value: "evil.example"},
		{Type: TypeIP, Value: "192.0.2.1"},
		{Type: TypeIP, Value: "192.0.2.0/24"},
		{Type: TypeURL, Value: "http://evil.example/payload"},
		{Type: TypeMD5, Value: "D41D8CD98F00B204E9800998ECF8427E"},
		{Type: TypeSHA256, Value: "abc123"},
		{Type: TypeTLSFP, Value: "t13d1516h2_8daaf6152771_b186095e22b6"},
	}
	for _, i := range ok {
		if _, err := Validate(i); err != nil {
			t.Errorf("Validate(%s=%q) should pass: %v", i.Type, i.Value, err)
		}
	}

	bad := []Indicator{
		{Type: TypeDomain, Value: "com"},
		{Type: TypeIP, Value: "not-an-ip"},
		{Type: TypeIP, Value: "0.0.0.0"},
		{Type: "nope", Value: "x"},
		{Type: TypeDomain, Value: "evil.example", Confidence: 101},
		{Type: TypeDomain, Value: "evil.example", Confidence: -1},
	}
	for _, i := range bad {
		if _, err := Validate(i); err == nil {
			t.Errorf("Validate(%s=%q, conf=%d) should fail", i.Type, i.Value, i.Confidence)
		}
	}
}

func TestValidateLowercasesFingerprints(t *testing.T) {
	v, err := Validate(Indicator{Type: TypeMD5, Value: "D41D8CD98F00B204E9800998ECF8427E"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Value != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("fingerprint should be lowercased, got %q", v.Value)
	}
}
