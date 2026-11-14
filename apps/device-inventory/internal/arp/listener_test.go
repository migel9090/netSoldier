package arp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

var (
	router   = net.HardwareAddr{0x00, 0x11, 0x24, 0xaa, 0xbb, 0x01}
	attacker = net.HardwareAddr{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01}
)

func arpFrame(ethSrc, sha net.HardwareAddr, spa net.IP, op uint16) []byte {
	f := make([]byte, ethHdrLen+arpLen)
	copy(f[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(f[6:12], ethSrc)
	binary.BigEndian.PutUint16(f[12:14], ethPARP)
	a := f[ethHdrLen:]
	binary.BigEndian.PutUint16(a[0:2], 1)
	binary.BigEndian.PutUint16(a[2:4], 0x0800)
	a[4], a[5] = 6, 4
	binary.BigEndian.PutUint16(a[6:8], op)
	copy(a[8:14], sha)
	copy(a[14:18], spa.To4())
	copy(a[24:28], net.IPv4(192, 168, 77, 254).To4())
	return f
}

func TestParseFrame(t *testing.T) {
	s, err := ParseFrame(arpFrame(router, router, net.IPv4(192, 168, 77, 1), 1))
	if err != nil {
		t.Fatal(err)
	}
	if s != (discovery.Sighting{Source: discovery.SourceARP, MAC: "00:11:24:aa:bb:01", IP: "192.168.77.1"}) {
		t.Errorf("got %+v", s)
	}
	if s, err := ParseFrame(append(arpFrame(router, router, net.IPv4(192, 168, 77, 1), 2), make([]byte, 18)...)); err != nil || s.IP == "" {
		t.Errorf("padded reply: %+v %v", s, err)
	}
}

// DI-2, from the auditor's run.sh: one ARP frame from the attacker's
// interface whose sender address was the router's rewrote the router's row.
func TestSpoofedSenderIsRefused(t *testing.T) {
	_, err := ParseFrame(arpFrame(attacker, router, net.IPv4(192, 168, 77, 66), 1))
	if !errors.Is(err, discovery.ErrLinkMismatch) {
		t.Fatalf("err = %v, want ErrLinkMismatch", err)
	}
}

func TestProbesAndOddFrames(t *testing.T) {
	// An ARP probe proves the MAC, not an address.
	s, err := ParseFrame(arpFrame(router, router, net.IPv4zero, 1))
	if err != nil || s.MAC == "" || s.IP != "" {
		t.Errorf("probe: %+v %v", s, err)
	}
	for _, ip := range []net.IP{net.IPv4bcast, net.IPv4(127, 0, 0, 1), net.IPv4(224, 0, 0, 1)} {
		if s, _ := ParseFrame(arpFrame(router, router, ip, 1)); s.IP != "" {
			t.Errorf("unusable sender address %s kept", ip)
		}
	}

	group := net.HardwareAddr{0x01, 0, 0x5e, 0, 0, 1}
	rarp := arpFrame(router, router, net.IPv4(1, 2, 3, 4), 3)
	ipv6 := arpFrame(router, router, net.IPv4(1, 2, 3, 4), 1)
	ipv6[ethHdrLen+3] = 0xdd
	notARP := arpFrame(router, router, net.IPv4(1, 2, 3, 4), 1)
	notARP[13] = 0
	for name, c := range map[string]struct {
		f    []byte
		want error
	}{
		"short":          {arpFrame(router, router, nil, 1)[:30], discovery.ErrMalformed},
		"group sender":   {arpFrame(group, group, net.IPv4(1, 2, 3, 4), 1), discovery.ErrMalformed},
		"rarp opcode":    {rarp, discovery.ErrIgnored},
		"other protocol": {ipv6, discovery.ErrIgnored},
		"not arp":        {notARP, discovery.ErrIgnored},
	} {
		if _, err := ParseFrame(c.f); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func FuzzParseFrame(f *testing.F) {
	f.Add(arpFrame(router, router, net.IPv4(192, 168, 77, 1), 1))
	f.Add(arpFrame(attacker, router, net.IPv4(192, 168, 77, 66), 2))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseFrame(b)
		if err != nil {
			return
		}
		if s.MAC != net.HardwareAddr(b[6:12]).String() || s.MAC != net.HardwareAddr(b[ethHdrLen+8:ethHdrLen+14]).String() {
			t.Fatalf("claim %s accepted from %s", s.MAC, net.HardwareAddr(b[6:12]))
		}
	})
}

type fakeSender struct {
	frames [][]byte
	err    error
}

func (f *fakeSender) Send(frame []byte) error {
	f.frames = append(f.frames, frame)
	return f.err
}

func TestScannerBuildsRequests(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("192.168.77.0/30")
	s := &Scanner{
		subnet:  subnet,
		iface:   &net.Interface{Index: 3, Name: "veth0", HardwareAddr: net.HardwareAddr{2, 0, 0, 0, 0, 2}},
		localIP: net.IPv4(192, 168, 77, 2),
	}
	fs := &fakeSender{}
	if err := s.sweep(context.Background(), fs); err != nil {
		t.Fatal(err)
	}
	if len(fs.frames) != 2 { // .1 and .2; network and broadcast excluded
		t.Fatalf("sent %d requests, want 2", len(fs.frames))
	}
	got, err := ParseFrame(fs.frames[0])
	if err != nil || got.MAC != "02:00:00:00:00:02" || got.IP != "192.168.77.2" {
		t.Errorf("request does not parse as our own claim: %+v %v", got, err)
	}
	if target := net.IP(fs.frames[1][38:42]); !target.Equal(net.IPv4(192, 168, 77, 2)) {
		t.Errorf("second target %s", target)
	}

	if err := s.sweep(context.Background(), &fakeSender{err: errors.New("ENETDOWN")}); err == nil {
		t.Error("a sweep where every send failed must be an error (so the supervisor restarts)")
	}
}

func TestNewScannerValidates(t *testing.T) {
	for _, cidr := range []string{"10.0.0.0/8", "garbage", "fd00::/64"} {
		if _, err := NewScanner(cidr, time.Minute); err == nil {
			t.Errorf("%s accepted", cidr)
		}
	}
	if _, err := NewScanner("192.0.2.0/24", 0); err == nil {
		t.Error("zero interval accepted")
	}
	if _, err := NewScanner("192.0.2.0/24", time.Minute); err == nil {
		t.Error("a subnet no interface is on should fail")
	}
	_, subnet, _ := net.ParseCIDR("10.1.0.0/16")
	if n := len(subnetIPs(subnet)); n != 65534 {
		t.Errorf("/16 enumerates %d hosts", n)
	}
}
