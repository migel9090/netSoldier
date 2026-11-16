package isolate

import (
	"net/netip"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

func mac(s string) wire.MAC {
	m, err := wire.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// newGuard is a guard for a sensor at 192.168.1.9 / aa:bb:cc:00:00:09 on a
// /24, with the gateway pinned to 192.168.1.1 / aa:bb:cc:00:00:01 and one
// protected device (the DNS server at .53). Forwarding is off.
func newGuard() *Guard {
	return &Guard{
		Interface:     "eth0",
		GatewayIP:     netip.MustParseAddr("192.168.1.1"),
		GatewayMAC:    mac("aa:bb:cc:00:00:01"),
		ProtectedMACs: map[wire.MAC]bool{mac("aa:bb:cc:00:00:53"): true},
		ProtectedIPs:  map[netip.Addr]bool{netip.MustParseAddr("192.168.1.53"): true},
		MaxTTL:        time.Hour,
		Local: func() (Local, error) {
			return Local{
				MACs:    []wire.MAC{mac("aa:bb:cc:00:00:09")},
				IPs:     []netip.Addr{netip.MustParseAddr("192.168.1.9")},
				Subnets: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			}, nil
		},
		Forwarding: func() (bool, error) { return false, nil },
	}
}

// TestGuardRules is the audit's refusal matrix plus the accept case. Each row
// names the rule it exercises.
func TestGuardRules(t *testing.T) {
	cases := []struct {
		name     string
		mac, ip  string
		ttl      int64
		wantCode string // "" = accepted
	}{
		{"valid host accepted", "aa:bb:cc:dd:ee:77", "192.168.1.77", 600, ""},
		{"broadcast MAC refused", "ff:ff:ff:ff:ff:ff", "192.168.1.77", 600, "group_mac"},
		{"multicast MAC 11:22:...:66 refused", "11:22:33:44:55:66", "192.168.1.77", 600, "group_mac"},
		{"zero MAC refused", "00:00:00:00:00:00", "192.168.1.77", 600, "zero_mac"},
		{"gateway by IP refused", "aa:bb:cc:dd:ee:77", "192.168.1.1", 600, "gateway"},
		{"gateway by MAC refused", "aa:bb:cc:00:00:01", "192.168.1.77", 600, "gateway"},
		{"agent's own MAC refused", "aa:bb:cc:00:00:09", "192.168.1.77", 600, "self"},
		{"agent's own IP refused", "aa:bb:cc:dd:ee:77", "192.168.1.9", 600, "self"},
		{"protected MAC refused", "aa:bb:cc:00:00:53", "192.168.1.77", 600, "protected"},
		{"protected IP refused", "aa:bb:cc:dd:ee:77", "192.168.1.53", 600, "protected"},
		{"off-subnet IP refused", "aa:bb:cc:dd:ee:77", "10.0.0.5", 600, "off_subnet"},
		{"network address refused", "aa:bb:cc:dd:ee:77", "192.168.1.0", 600, "off_subnet"},
		{"directed broadcast refused", "aa:bb:cc:dd:ee:77", "192.168.1.255", 600, "off_subnet"},
		{"limited broadcast refused", "aa:bb:cc:dd:ee:77", "255.255.255.255", 600, "unusable_ip"},
		{"multicast IP refused", "aa:bb:cc:dd:ee:77", "224.0.0.1", 600, "unusable_ip"},
		{"zero IP refused", "aa:bb:cc:dd:ee:77", "0.0.0.0", 600, "unusable_ip"},
		{"malformed MAC refused", "not-a-mac", "192.168.1.77", 600, "malformed"},
		{"malformed IP refused", "aa:bb:cc:dd:ee:77", "192.168.001.077", 600, "malformed"},
		{"zero TTL refused", "aa:bb:cc:dd:ee:77", "192.168.1.77", 0, "ttl"},
		{"over-max TTL refused", "aa:bb:cc:dd:ee:77", "192.168.1.77", 7200, "ttl"},
	}
	g := newGuard()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := g.Check(c.mac, c.ip, c.ttl)
			code := refusalCode(err)
			if code != c.wantCode {
				t.Fatalf("Check(%q,%q,%d) code = %q, want %q (err=%v)", c.mac, c.ip, c.ttl, code, c.wantCode, err)
			}
		})
	}
}

// TestRefusesWhileForwarding is the KS-9 case: with IP forwarding on, the
// redirect would route traffic instead of dropping it, so every isolation is
// refused.
func TestRefusesWhileForwarding(t *testing.T) {
	g := newGuard()
	g.Forwarding = func() (bool, error) { return true, nil }
	if _, _, err := g.Check("aa:bb:cc:dd:ee:77", "192.168.1.77", 600); refusalCode(err) != "forwarding" {
		t.Fatalf("want forwarding refusal, got %v", err)
	}
}

func TestGatewayMACIsConfigOnly(t *testing.T) {
	// The guard never reads the neighbour table (audit KS-8). Nothing it is
	// handed at Check time names the gateway MAC, so there is no code path by
	// which an observed frame could change it: the field is only ever set
	// from configuration. Prove the pinned MAC is refused and that a
	// different MAC claiming the gateway IP is still only refused as the
	// gateway by IP, not learned.
	g := newGuard()
	if _, _, err := g.Check("aa:bb:cc:00:00:01", "192.168.1.200", 600); refusalCode(err) != "gateway" {
		t.Fatalf("pinned gateway MAC not refused: %v", err)
	}
	// A forger using a different MAC on the gateway IP is refused by IP; the
	// guard's GatewayMAC is unchanged afterwards.
	before := g.GatewayMAC
	_, _, _ = g.Check("de:ad:be:ef:00:01", "192.168.1.1", 600)
	if g.GatewayMAC != before {
		t.Fatal("gateway MAC changed after a check; it must come only from configuration")
	}
}

func refusalCode(err error) string {
	if err == nil {
		return ""
	}
	if r, ok := err.(*Refusal); ok {
		return r.Code
	}
	return "unknown:" + err.Error()
}
