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
