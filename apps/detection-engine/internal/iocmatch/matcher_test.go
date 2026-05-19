package iocmatch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatchDomainExact(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "test", Confidence: 80}})

	ioc, ok := m.MatchDomain("evil.com")
	if !ok {
		t.Fatal("expected match for evil.com")
	}
	if ioc.Value != "evil.com" {
		t.Fatalf("got value %q, want evil.com", ioc.Value)
	}
}

func TestMatchDomainSubdomain(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "test", Confidence: 80}})

	if _, ok := m.MatchDomain("malware.evil.com"); !ok {
		t.Fatal("expected subdomain match for malware.evil.com")
	}
	if _, ok := m.MatchDomain("deep.sub.evil.com"); !ok {
		t.Fatal("expected deep subdomain match")
	}
}

func TestMatchDomainNoMatch(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "test", Confidence: 80}})

	if _, ok := m.MatchDomain("notevil.com"); ok {
		t.Fatal("should not match notevil.com")
	}
	if _, ok := m.MatchDomain("google.com"); ok {
		t.Fatal("should not match google.com")
	}
}

func TestMatchDomainTrailingDot(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "test", Confidence: 80}})

	if _, ok := m.MatchDomain("evil.com."); !ok {
		t.Fatal("should match domain with trailing dot")
	}
}

func TestMatchDomainCaseInsensitive(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "EVIL.COM", Type: "domain", Source: "test", Confidence: 80}})

	if _, ok := m.MatchDomain("evil.com"); !ok {
		t.Fatal("match should be case-insensitive")
	}
}

func TestMatchIPExact(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "1.2.3.4", Type: "ip", Source: "test", Confidence: 90}})

	ioc, ok := m.MatchIP("1.2.3.4")
	if !ok {
		t.Fatal("expected match for 1.2.3.4")
	}
	if ioc.Value != "1.2.3.4" {
		t.Fatalf("got value %q", ioc.Value)
	}
}

func TestMatchIPNoMatch(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "1.2.3.4", Type: "ip", Source: "test", Confidence: 90}})

	if _, ok := m.MatchIP("5.6.7.8"); ok {
		t.Fatal("should not match 5.6.7.8")
	}
}

func TestMatchIPCIDR(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "10.0.0.0/24", Type: "ip", Source: "test", Confidence: 70}})

	if _, ok := m.MatchIP("10.0.0.42"); !ok {
		t.Fatal("expected CIDR match for 10.0.0.42")
	}
	if _, ok := m.MatchIP("10.0.1.1"); ok {
		t.Fatal("should not match IP outside CIDR")
	}
}

func TestMatchIPWithPort(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "1.2.3.4:8080", Type: "ip", Source: "test", Confidence: 90}})

	if _, ok := m.MatchIP("1.2.3.4"); !ok {
		t.Fatal("should match IP added with port")
	}
}

func TestMatchHash(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "abc123", Type: "ja3", Source: "test", Confidence: 80}})

	if _, ok := m.MatchHash("abc123"); !ok {
		t.Fatal("expected hash match")
	}
	if _, ok := m.MatchHash("ABC123"); !ok {
		t.Fatal("hash match should be case-insensitive")
	}
	if _, ok := m.MatchHash("xyz789"); ok {
		t.Fatal("should not match unknown hash")
	}
}

func TestHigherConfidenceReplaces(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "low", Confidence: 50}})
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "high", Confidence: 95}})

	ioc, ok := m.MatchDomain("evil.com")
	if !ok {
		t.Fatal("expected match")
	}
	if ioc.Source != "high" {
		t.Fatalf("expected high-confidence source, got %q", ioc.Source)
	}
}

func TestLowerConfidenceDoesNotReplace(t *testing.T) {
	m := New()
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "high", Confidence: 95}})
	m.Add([]IoC{{Value: "evil.com", Type: "domain", Source: "low", Confidence: 50}})

	ioc, _ := m.MatchDomain("evil.com")
	if ioc.Source != "high" {
		t.Fatalf("lower confidence should not replace, got source %q", ioc.Source)
	}
}

func TestSize(t *testing.T) {
	m := New()
	if m.Size() != 0 {
		t.Fatal("empty matcher should have size 0")
	}
	m.Add([]IoC{
		{Value: "evil.com", Type: "domain", Confidence: 80},
		{Value: "1.2.3.4", Type: "ip", Confidence: 80},
		{Value: "abc123", Type: "ja3", Confidence: 80},
	})
	if m.Size() != 3 {
		t.Fatalf("expected size 3, got %d", m.Size())
	}
}

func TestDeriveSeverity(t *testing.T) {
	tests := []struct {
		confidence int
		want       string
	}{
		{95, "critical"},
		{90, "critical"},
		{80, "high"},
		{70, "high"},
		{60, "medium"},
		{50, "medium"},
		{40, "low"},
		{0, "low"},
	}
	for _, tt := range tests {
		got := DeriveSeverity(IoC{Confidence: tt.confidence})
		if got != tt.want {
			t.Errorf("DeriveSeverity(confidence=%d) = %q, want %q", tt.confidence, got, tt.want)
		}
	}
}

func TestDeriveMitre(t *testing.T) {
	id, name := DeriveMitre(IoC{Type: "domain", Tags: []string{"c2", "botnet"}})
	if id != "T1071" {
		t.Errorf("expected T1071 for c2 tag, got %s", id)
	}
	if name == "" {
		t.Error("expected non-empty MITRE name")
	}

	id, _ = DeriveMitre(IoC{Type: "domain"})
	if id != "T1071.004" {
		t.Errorf("expected T1071.004 for plain domain, got %s", id)
	}
}

func TestLoadDomainsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	os.WriteFile(path, []byte("# comment\nevil.com\nmalware.net\n\n"), 0644)

	iocs, err := LoadDomainsFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(iocs) != 2 {
		t.Fatalf("expected 2 IoCs, got %d", len(iocs))
	}
	if iocs[0].Value != "evil.com" || iocs[0].Source != "local" {
		t.Errorf("unexpected first IoC: %+v", iocs[0])
	}
}

func TestDeriveMitreBranches(t *testing.T) {
	tests := []struct {
		tags   []string
		threat string
		wantID string
	}{
		{[]string{"malware_download"}, "", "T1105"},
		{[]string{}, "phishing campaign", "T1566"},
		{[]string{"exfil"}, "", "T1041"},
		{[]string{"dga"}, "", "T1568"},
		{[]string{"miner"}, "", "T1496"},
		{[]string{"scan"}, "", "T1595"},
	}
	for _, tt := range tests {
		id, _ := DeriveMitre(IoC{Type: "domain", Tags: tt.tags, Threat: tt.threat})
		if id != tt.wantID {
			t.Errorf("DeriveMitre(tags=%v, threat=%q) = %q, want %q", tt.tags, tt.threat, id, tt.wantID)
		}
	}

	id, _ := DeriveMitre(IoC{Type: "ip"})
	if id != "T1095" {
		t.Errorf("IP type default = %q, want T1095", id)
	}
	id, _ = DeriveMitre(IoC{Type: "url"})
	if id != "T1071.001" {
		t.Errorf("URL type default = %q, want T1071.001", id)
	}
	id, _ = DeriveMitre(IoC{Type: "ja3"})
	if id != "T1071.001" {
		t.Errorf("JA3 type default = %q, want T1071.001", id)
	}
	id, _ = DeriveMitre(IoC{Type: "sha256"})
	if id != "T1071" {
		t.Errorf("sha256 type default = %q, want T1071", id)
	}
}

func TestLoadDomainsFromFileMissing(t *testing.T) {
	_, err := LoadDomainsFromFile("/nonexistent/path")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
