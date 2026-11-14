package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

var (
	router   = net.HardwareAddr{0x00, 0x11, 0x24, 0xaa, 0xbb, 0x01}
	attacker = net.HardwareAddr{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01}
)

// bootp builds a client message; extra options go before the end option.
func bootp(chaddr net.HardwareAddr, hlen, msgType byte, reqIP net.IP, host, vc string, extra ...byte) []byte {
	p := make([]byte, 240)
	p[0], p[1], p[2] = 1, 1, hlen
	copy(p[28:44], chaddr)
	binary.BigEndian.PutUint32(p[236:240], magicCookie)
	if msgType != 0 {
		p = append(p, optMessageType, 1, msgType)
	}
	if reqIP != nil {
		p = append(p, optRequestedIP, 4)
		p = append(p, reqIP.To4()...)
	}
	if host != "" {
		p = append(p, optHostName, byte(len(host)))
		p = append(p, host...)
	}
	if vc != "" {
		p = append(p, optVendorClass, byte(len(vc)))
		p = append(p, vc...)
	}
	p = append(p, optPRL, 4, 1, 3, 6, 15)
	p = append(p, extra...)
	return append(p, optEnd)
}

// frame wraps a payload in Ethernet/IPv4/UDP from ethSrc to dstPort.
func frame(ethSrc net.HardwareAddr, dstPort uint16, payload []byte) []byte {
	f := make([]byte, 14+20+8)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], ethSrc)
	binary.BigEndian.PutUint16(f[12:14], ethPIPv4)
	ip := f[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], net.IPv4zero.To4())
	copy(ip[16:20], net.IPv4bcast.To4())
	udp := f[34:42]
	binary.BigEndian.PutUint16(udp[0:2], 68)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(payload)))
	return append(f, payload...)
}

func request(chaddr net.HardwareAddr, ip net.IP, host, vc string) []byte {
	return bootp(chaddr, 6, msgRequest, ip, host, vc)
}

func TestParseFrameRequest(t *testing.T) {
	s, err := ParseFrame(frame(router, 67, request(router, net.IPv4(192, 168, 1, 1), "gateway", "udhcp 1.36")))
	if err != nil {
		t.Fatal(err)
	}
	want := discovery.Sighting{Source: discovery.SourceDHCP, MAC: "00:11:24:aa:bb:01", IP: "192.168.1.1",
		Name: "gateway", Fingerprint: "1,3,6,15", VendorClass: "udhcp 1.36"}
	if s != want {
		t.Errorf("got %+v\nwant %+v", s, want)
	}
}

// DI-2, from the auditor's TestAuditForgedChaddrRewritesVictim and run.sh:
// any host could send one datagram whose chaddr is the router's.
func TestForgedChaddrIsRefused(t *testing.T) {
	_, err := ParseFrame(frame(attacker, 67, request(router, net.IPv4(192, 168, 1, 66), "kids-tablet", "android-dhcp-14")))
	if !errors.Is(err, discovery.ErrLinkMismatch) {
		t.Fatalf("err = %v, want ErrLinkMismatch", err)
	}
	if discovery.RejectReason(err) != "link_mismatch" {
		t.Errorf("reason %q", discovery.RejectReason(err))
	}
}

// DI-10, from the auditor's TestAuditOddHlenAndRawHostname: hlen other than
// 6 produced keys that were not MACs, and the hostname was stored verbatim.
func TestHlenMustBeSix(t *testing.T) {
	long := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for _, hlen := range []byte{0, 1, 8, 16, 200} {
		if _, err := parsePacket(bootp(long, hlen, msgRequest, nil, "x", "")); err == nil {
			t.Errorf("hlen=%d accepted", hlen)
		}
	}
	p := bootp(router, 6, msgRequest, nil, "x", "")
	p[1] = 6 // IEEE 802 token ring
	if _, err := parsePacket(p); err == nil {
		t.Error("htype 6 accepted")
	}
}

func TestHostnameIsSanitized(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	s, err := ParseFrame(frame(mac, 67, request(mac, nil, "a\x00b\xff\x1b[31m\r\n<script>", "")))
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "ab[31m <script>" {
		t.Errorf("hostname = %q", s.Name)
	}
}

// DI-8: option 50 was taken from any message type. In a DECLINE it is the
// address the client refuses because someone else holds it.
func TestClaimedAddressDependsOnMessageType(t *testing.T) {
	gw := net.IPv4(192, 168, 1, 1)
	withCiaddr := func(p []byte, ip net.IP) []byte { copy(p[12:16], ip.To4()); return p }
	cases := []struct {
		name string
		pkt  []byte
		want string
	}{
		{"request option 50", bootp(router, 6, msgRequest, gw, "", ""), "192.168.1.1"},
		{"request renewing", withCiaddr(bootp(router, 6, msgRequest, nil, "", ""), gw), "192.168.1.1"},
		{"inform", withCiaddr(bootp(router, 6, msgInform, nil, "", ""), gw), "192.168.1.1"},
		{"discover wish", bootp(router, 6, msgDiscover, gw, "", ""), ""},
		{"decline", bootp(router, 6, 4, gw, "", ""), ""},
		{"release", withCiaddr(bootp(router, 6, 7, nil, "", ""), gw), ""},
		{"bootp without option 53", bootp(router, 6, 0, gw, "", ""), ""},
		{"request for broadcast", bootp(router, 6, msgRequest, net.IPv4bcast, "", ""), ""},
	}
	for _, c := range cases {
		s, err := ParseFrame(frame(router, 67, c.pkt))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if s.IP != c.want {
			t.Errorf("%s: ip %q, want %q", c.name, s.IP, c.want)
		}
	}
	// INFORM carries no profile.
	s, _ := ParseFrame(frame(router, 67, bootp(router, 6, msgInform, nil, "", "MSFT 5.0")))
	if s.Fingerprint != "" || s.VendorClass != "" {
		t.Errorf("INFORM profile kept: %+v", s)
	}
}

func TestFramesThatAreNotClientMessages(t *testing.T) {
	relayed := request(router, nil, "", "")
	copy(relayed[24:28], net.IPv4(10, 0, 0, 1).To4())
	reply := request(router, nil, "", "")
	reply[0] = 2
	group := net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1}
	cases := map[string][]byte{
		"relayed":         frame(router, 67, relayed),
		"server reply":    frame(router, 67, reply),
		"other port":      frame(router, 68, request(router, nil, "", "")),
		"group chaddr":    frame(group, 67, request(group, nil, "", "")),
		"short":           frame(router, 67, make([]byte, 100)),
		"truncated frame": frame(router, 67, nil)[:30],
	}
	for name, f := range cases {
		if _, err := ParseFrame(f); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	bad := request(router, nil, "", "")
	binary.BigEndian.PutUint32(bad[236:240], 0)
	if _, err := parsePacket(bad); !errors.Is(err, discovery.ErrMalformed) {
		t.Errorf("bad cookie: %v", err)
	}
	frag := frame(router, 67, request(router, nil, "", ""))
	frag[14+6] = 0x20 // more fragments
	if _, err := ParseFrame(frag); err == nil {
		t.Error("fragment accepted")
	}
}

func TestParseFrameTrimsEthernetPadding(t *testing.T) {
	f := append(frame(router, 67, request(router, nil, "pad", "")), make([]byte, 40)...)
	if s, err := ParseFrame(f); err != nil || s.Name != "pad" {
		t.Errorf("padded frame: %+v %v", s, err)
	}
}

// runBPF interprets the classic-BPF subset serverPortFilter uses, with the
// kernel's rule that an out-of-bounds load drops the packet.
func runBPF(t *testing.T, prog []unix.SockFilter, pkt []byte) uint32 {
	t.Helper()
	var a, x uint32
	load := func(off uint32, size int) (uint32, bool) {
		if int(off)+size > len(pkt) {
			return 0, false
		}
		if size == 1 {
			return uint32(pkt[off]), true
		}
		return uint32(binary.BigEndian.Uint16(pkt[off:])), true
	}
	for pc := 0; pc < len(prog); pc++ {
		ins := prog[pc]
		var ok = true
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_H | unix.BPF_ABS:
			a, ok = load(ins.K, 2)
		case unix.BPF_LD | unix.BPF_B | unix.BPF_ABS:
			a, ok = load(ins.K, 1)
		case unix.BPF_LD | unix.BPF_H | unix.BPF_IND:
			a, ok = load(x+ins.K, 2)
		case unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH:
			var b uint32
			b, ok = load(ins.K, 1)
			x = 4 * (b & 0xf)
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == ins.K {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if a&ins.K != 0 {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		default:
			t.Fatalf("instruction %d: opcode %#x not interpreted", pc, ins.Code)
		}
		if !ok {
			return 0
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func TestServerPortFilter(t *testing.T) {
	dhcpFrame := frame(router, 67, request(router, nil, "", ""))
	withOptions := func() []byte { // IHL 6: one word of IP options
		f := frame(router, 67, request(router, nil, "", ""))
		g := append([]byte{}, f[:34]...)
		g = append(g, 1, 1, 1, 0)
		g = append(g, f[34:]...)
		g[14] = 0x46
		return g
	}()
	tcp := frame(router, 67, nil)
	tcp[14+9] = 6
	frag := frame(router, 67, nil)
	frag[14+7] = 0x10
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:14], 0x0806)

	for name, c := range map[string]struct {
		pkt    []byte
		accept bool
	}{
		"dhcp to 67":      {dhcpFrame, true},
		"ip options":      {withOptions, true},
		"udp to 68":       {frame(router, 68, nil), false},
		"tcp to 67":       {tcp, false},
		"later fragment":  {frag, false},
		"arp":             {arp, false},
		"truncated frame": {dhcpFrame[:20], false},
	} {
		if got := runBPF(t, serverPortFilter, c.pkt) != 0; got != c.accept {
			t.Errorf("%s: accepted=%v, want %v", name, got, c.accept)
		}
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(frame(router, 67, request(router, net.IPv4(192, 168, 1, 50), "host", "MSFT")))
	f.Add(frame(router, 67, bootp(router, 16, msgDiscover, nil, "x", "")))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseFrame(b)
		if err != nil {
			return
		}
		if _, ok := discovery.ParseMAC(s.MAC); !ok || s.MAC != net.HardwareAddr(b[6:12]).String() {
			t.Fatalf("accepted claim for %q from %s", s.MAC, net.HardwareAddr(b[6:12]))
		}
		if len(s.Name) > discovery.MaxNameLen || len(s.VendorClass) > discovery.MaxVendorClassLen {
			t.Fatalf("unbounded strings: %+v", s)
		}
	})
}

func FuzzParsePacket(f *testing.F) {
	f.Add(request(router, net.IPv4(192, 168, 1, 50), "host", "MSFT"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parsePacket(b)
		_ = parseOptions(b)
	})
}
