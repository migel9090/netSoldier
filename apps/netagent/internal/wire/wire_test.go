package wire

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseMAC(t *testing.T) {
	good := map[string]MAC{
		"aa:bb:cc:dd:ee:ff": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		"00:11:22:33:44:55": {0, 0x11, 0x22, 0x33, 0x44, 0x55},
		"AA:BB:CC:DD:EE:FF": {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	for s, want := range good {
		if got, err := ParseMAC(s); err != nil || got != want {
			t.Errorf("ParseMAC(%q) = %v, %v", s, got, err)
		}
	}
	for _, s := range []string{
		"aa-bb-cc-dd-ee-ff", // dashes are not our one accepted spelling
		"aabb.ccdd.eeff",    // dotted
		"aa:bb:cc:dd:ee",    // too short
		"aa:bb:cc:dd:ee:ff:00",
		"gg:bb:cc:dd:ee:ff", // non-hex
		"aa:bb:cc:dd:ee:f",
		"",
	} {
		if _, err := ParseMAC(s); err == nil {
			t.Errorf("ParseMAC(%q) accepted", s)
		}
	}
}

func TestParseIPv4RefusesOddSpellings(t *testing.T) {
	for _, s := range []string{"192.168.1.1", "10.0.0.255"} {
		if _, err := ParseIPv4(s); err != nil {
			t.Errorf("ParseIPv4(%q): %v", s, err)
		}
	}
	// Audit KS-11: leading-zero and hex forms must not parse as addresses.
	for _, s := range []string{"192.168.001.001", "0xc0a80101", "::ffff:192.168.1.1", "fe80::1", "", "192.168.1.1%eth0"} {
		if _, err := ParseIPv4(s); err == nil {
			t.Errorf("ParseIPv4(%q) accepted", s)
		}
	}
}

func TestUnicast(t *testing.T) {
	cases := map[string]bool{
		"aa:bb:cc:dd:ee:ff": true,
		"ff:ff:ff:ff:ff:ff": false, // broadcast
		"11:22:33:44:55:66": false, // group bit set (the audit's multicast test MAC)
		"01:00:5e:00:00:fb": false, // IPv4 multicast
		"00:00:00:00:00:00": false, // zero
		"02:00:00:00:00:01": true,  // locally administered but unicast
	}
	for s, want := range cases {
		m, err := ParseMAC(s)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", s, err)
		}
		if m.Unicast() != want {
			t.Errorf("%s.Unicast() = %v, want %v", s, m.Unicast(), want)
		}
	}
}

// recorder captures frames instead of sending them.
type recorder struct{ frames [][]byte }

func (r *recorder) record(_ MAC, f []byte) error {
	r.frames = append(r.frames, append([]byte(nil), f...))
	return nil
}

func senderWithRecorder() (*Sender, *recorder) {
	r := &recorder{}
	s := &Sender{mac: MAC{0x02, 0, 0, 0, 0, 0x01}}
	s.send = r.record
	return s, r
}

func host(mac string, ip string) Host {
	m, _ := ParseMAC(mac)
	a, _ := ParseIPv4(ip)
	return Host{MAC: m, IP: a}
}

func TestProbeIsBroadcastRequest(t *testing.T) {
	s, r := senderWithRecorder()
	if err := s.Probe(netip.MustParseAddr("192.168.1.2"), netip.MustParseAddr("192.168.1.9")); err != nil {
		t.Fatal(err)
	}
	if len(r.frames) != 1 {
		t.Fatalf("sent %d frames", len(r.frames))
	}
	f := r.frames[0]
	for i := 0; i < 6; i++ {
		if f[i] != 0xff {
			t.Fatalf("probe is not broadcast: % x", f[:6])
		}
	}
	if op := uint16(f[20])<<8 | uint16(f[21]); op != opRequest {
		t.Errorf("op = %d, want request", op)
	}
	if got := netip.AddrFrom4([4]byte(f[38:42])); got != netip.MustParseAddr("192.168.1.9") {
		t.Errorf("target IP = %s", got)
	}
}

func TestApplyAndLiftBuildUnicastPairs(t *testing.T) {
	s, r := senderWithRecorder()
	target := host("aa:bb:cc:dd:ee:01", "192.168.1.50")
	gw := host("aa:bb:cc:00:00:01", "192.168.1.1")

	if err := s.Apply(target, gw); err != nil {
		t.Fatal(err)
	}
	if len(r.frames) != 2 {
		t.Fatalf("Apply sent %d frames, want 2", len(r.frames))
	}
	// Every frame is sourced from our own interface, never a forged source.
	for i, f := range r.frames {
		if MAC(f[6:12]) != s.mac {
			t.Errorf("frame %d not sourced from the agent: % x", i, f[6:12])
		}
		if op := uint16(f[20])<<8 | uint16(f[21]); op != opReply {
			t.Errorf("frame %d op = %d, want reply", i, op)
		}
	}
	// Apply tells the target that the gateway IP is at our MAC.
	if sha := MAC(r.frames[0][22:28]); sha != s.mac {
		t.Errorf("apply-to-target sender MAC = %s, want the agent", sha)
	}

	r.frames = nil
	if err := s.Lift(target, gw); err != nil {
		t.Fatal(err)
	}
	// Lift tells the target the gateway's real MAC, so they reach each other.
	if sha := MAC(r.frames[0][22:28]); sha != gw.MAC {
		t.Errorf("lift-to-target sender MAC = %s, want the gateway", sha)
	}
	if MAC(r.frames[0][6:12]) != s.mac {
		t.Error("lift frame must still be sourced from the agent, not the gateway")
	}
}

// FuzzParseAddresses feeds arbitrary strings to the two address parsers that
// turn caller-supplied command fields into wire addresses. Neither may panic,
// and anything accepted must round-trip to its canonical form and be a
// unicast MAC / IPv4 address respectively.
func FuzzParseAddresses(f *testing.F) {
	f.Add("aa:bb:cc:dd:ee:ff", "192.168.1.1")
	f.Add("11:22:33:44:55:66", "192.168.001.001")
	f.Add("", "0xc0a80101")
	f.Fuzz(func(t *testing.T, macStr, ipStr string) {
		if m, err := ParseMAC(macStr); err == nil {
			if m.String() != strings.ToLower(macStr) {
				t.Fatalf("ParseMAC(%q) accepted a non-canonical form -> %s", macStr, m)
			}
		}
		if a, err := ParseIPv4(ipStr); err == nil {
			if !a.Is4() || a.String() != ipStr {
				t.Fatalf("ParseIPv4(%q) accepted a non-canonical or non-IPv4 value -> %s", ipStr, a)
			}
		}
	})
}

func TestBuildersRefuseBadAddresses(t *testing.T) {
	s, _ := senderWithRecorder()
	group := Host{MAC: MAC{0x01, 0, 0x5e, 0, 0, 1}, IP: netip.MustParseAddr("192.168.1.9")}
	ok := host("aa:bb:cc:dd:ee:01", "192.168.1.9")
	if err := s.Apply(group, ok); err == nil {
		t.Error("Apply accepted a group-MAC target")
	}
	if err := s.Lift(ok, group); err == nil {
		t.Error("Lift accepted a group-MAC gateway")
	}
}
