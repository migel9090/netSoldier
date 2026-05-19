package policy

import (
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

func newTestPolicy() *Policy {
	p := DefaultPolicy()
	p.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")
	p.Allowlist.AddIP("192.168.1.1")
	return p
}

func TestAutoBlock(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 95,
		Severity:   events.SeverityCritical,
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "auto_block" {
		t.Fatalf("expected auto_block, got %q", d.Action)
	}
	if d.ActionType != events.ActionDNSSinkhole {
		t.Fatalf("expected dns_sinkhole, got %q", d.ActionType)
	}
	if d.TTLSeconds != 3600 {
		t.Fatalf("expected TTL 3600, got %d", d.TTLSeconds)
	}
}

func TestPending(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 60,
		Severity:   events.SeverityMedium,
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "pending" {
		t.Fatalf("expected pending, got %q", d.Action)
	}
}

func TestIgnoreBelowThresholds(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 30,
		Severity:   events.SeverityLow,
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "ignore" {
		t.Fatalf("expected ignore, got %q", d.Action)
	}
}

func TestAllowlistByMAC(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 99,
		Severity:   events.SeverityCritical,
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "ignore" {
		t.Fatalf("allowlisted MAC should always be ignored, got %q", d.Action)
	}
}

func TestAllowlistByIP(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 99,
		Severity:   events.SeverityCritical,
		ClientIP:   "192.168.1.1",
	})
	if d.Action != "ignore" {
		t.Fatalf("allowlisted IP should always be ignored, got %q", d.Action)
	}
}

func TestAllowlistCaseInsensitiveMAC(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 99,
		Severity:   events.SeverityCritical,
		ClientMAC:  "AA:BB:CC:DD:EE:FF",
	})
	if d.Action != "ignore" {
		t.Fatalf("MAC match should be case-insensitive, got %q", d.Action)
	}
}

func TestHighConfidenceLowSeverityNotAutoBlock(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 95,
		Severity:   events.SeverityLow,
		ClientIP:   "192.168.1.100",
	})
	if d.Action == "auto_block" {
		t.Fatal("low severity should not auto-block even with high confidence")
	}
}

func TestDefaultPolicyValues(t *testing.T) {
	p := DefaultPolicy()
	if p.AutoMinConfidence != 90 {
		t.Errorf("expected auto confidence 90, got %d", p.AutoMinConfidence)
	}
	if p.AutoMinSeverity != events.SeverityCritical {
		t.Errorf("expected auto severity critical, got %s", p.AutoMinSeverity)
	}
	if p.DefaultAction != events.ActionDNSSinkhole {
		t.Errorf("expected default action dns_sinkhole, got %s", p.DefaultAction)
	}
}

func TestAllowlistRemoveMAC(t *testing.T) {
	var al Allowlist
	al.AddMAC("aa:bb:cc:dd:ee:ff")
	al.RemoveMAC("aa:bb:cc:dd:ee:ff")
	if al.Contains("aa:bb:cc:dd:ee:ff", "") {
		t.Fatal("MAC should be removed")
	}
}

func TestAllowlistRemoveIP(t *testing.T) {
	var al Allowlist
	al.AddIP("192.168.1.1")
	al.RemoveIP("192.168.1.1")
	if al.Contains("", "192.168.1.1") {
		t.Fatal("IP should be removed")
	}
}

func TestAllowlistMACs(t *testing.T) {
	var al Allowlist
	al.AddMAC("aa:bb:cc:dd:ee:ff")
	al.AddMAC("11:22:33:44:55:66")
	macs := al.MACs()
	if len(macs) != 2 {
		t.Fatalf("expected 2 MACs, got %d", len(macs))
	}
}

func TestAllowlistIPs(t *testing.T) {
	var al Allowlist
	al.AddIP("10.0.0.1")
	ips := al.IPs()
	if len(ips) != 1 || ips[0] != "10.0.0.1" {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestAllowlistContainsEmpty(t *testing.T) {
	var al Allowlist
	if al.Contains("", "") {
		t.Fatal("empty allowlist should not match")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("POLICY_AUTO_CONFIDENCE", "85")
	t.Setenv("POLICY_AUTO_SEVERITY", "high")
	t.Setenv("POLICY_PENDING_CONFIDENCE", "40")
	t.Setenv("POLICY_PENDING_SEVERITY", "low")
	t.Setenv("POLICY_DEFAULT_TTL", "7200")
	t.Setenv("POLICY_DEFAULT_ACTION", "arp_isolate")
	t.Setenv("ALLOWLIST_MACS", "aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66")
	t.Setenv("ALLOWLIST_IPS", "10.0.0.1,10.0.0.2")

	p := LoadFromEnv()

	if p.AutoMinConfidence != 85 {
		t.Errorf("auto confidence = %d, want 85", p.AutoMinConfidence)
	}
	if p.AutoMinSeverity != "high" {
		t.Errorf("auto severity = %q, want high", p.AutoMinSeverity)
	}
	if p.PendMinConfidence != 40 {
		t.Errorf("pending confidence = %d, want 40", p.PendMinConfidence)
	}
	if p.DefaultTTL != 7200 {
		t.Errorf("default TTL = %d, want 7200", p.DefaultTTL)
	}
	if p.DefaultAction != "arp_isolate" {
		t.Errorf("default action = %q, want arp_isolate", p.DefaultAction)
	}
	if len(p.Allowlist.MACs()) != 2 {
		t.Errorf("expected 2 allowlisted MACs, got %d", len(p.Allowlist.MACs()))
	}
	if len(p.Allowlist.IPs()) != 2 {
		t.Errorf("expected 2 allowlisted IPs, got %d", len(p.Allowlist.IPs()))
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{events.SeverityCritical, 4},
		{events.SeverityHigh, 3},
		{events.SeverityMedium, 2},
		{events.SeverityLow, 1},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := severityRank(tt.severity)
		if got != tt.want {
			t.Errorf("severityRank(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}
