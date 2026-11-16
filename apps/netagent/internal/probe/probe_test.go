package probe

import (
	"net/netip"
	"testing"
)

func local() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("192.168.1.9/24")}
}

func TestPlan(t *testing.T) {
	cases := []struct {
		target  string
		wantOK  bool
		wantPfx string
	}{
		{"192.168.1.0/24", true, "192.168.1.0/24"},
		{"192.168.1.77", true, "192.168.1.77/32"},
		{"192.168.1.128/25", true, "192.168.1.128/25"},
		{"10.0.0.0/24", false, ""},    // not on our subnet
		{"192.168.1.0/8", false, ""},  // wider than /16
		{"0.0.0.0/0", false, ""},      // the whole internet
		{"garbage", false, ""},        // unparsable
		{"fd00::/64", false, ""},      // not IPv4
		{"192.168.0.0/16", false, ""}, // not contained in our /24
	}
	for _, c := range cases {
		pfx, src, err := Plan(c.target, local())
		if (err == nil) != c.wantOK {
			t.Errorf("Plan(%q) ok=%v, want %v (err=%v)", c.target, err == nil, c.wantOK, err)
			continue
		}
		if c.wantOK {
			if pfx.String() != c.wantPfx {
				t.Errorf("Plan(%q) pfx = %s, want %s", c.target, pfx, c.wantPfx)
			}
			if src != netip.MustParseAddr("192.168.1.9") {
				t.Errorf("Plan(%q) src = %s, want our address", c.target, src)
			}
		}
	}
}

func TestHostsExcludeNetworkBroadcastAndSelf(t *testing.T) {
	src := netip.MustParseAddr("192.168.1.9")
	hosts := Hosts(netip.MustParsePrefix("192.168.1.0/24"), src)
	// 256 addresses, minus network, minus broadcast, minus our own = 253.
	if len(hosts) != 253 {
		t.Fatalf("got %d hosts, want 253", len(hosts))
	}
	for _, a := range hosts {
		if a == src || a == netip.MustParseAddr("192.168.1.0") || a == netip.MustParseAddr("192.168.1.255") {
			t.Fatalf("host list includes an excluded address: %s", a)
		}
	}
}

func TestHostsSlash32(t *testing.T) {
	// A single-host sweep keeps the one address (it is not a /30-or-wider
	// network with a network/broadcast to drop).
	hosts := Hosts(netip.MustParsePrefix("192.168.1.77/32"), netip.MustParseAddr("192.168.1.9"))
	if len(hosts) != 1 || hosts[0] != netip.MustParseAddr("192.168.1.77") {
		t.Fatalf("/32 sweep = %v", hosts)
	}
}
