package mdns

import (
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

var src = net.IPv4(192, 168, 1, 20)

// hdr builds a response header (flags 0x8400) with the given counts.
func hdr(qd, an uint16) []byte {
	return []byte{0, 0, 0x84, 0, byte(qd >> 8), byte(qd), byte(an >> 8), byte(an), 0, 0, 0, 0}
}

func label(parts ...string) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return append(b, 0)
}

// aRecord is an A record header + rdata after a name.
func aRecord(ip net.IP) []byte {
	return append([]byte{0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4}, ip.To4()...)
}

func within(t *testing.T, d time.Duration, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("still running after %s: unbounded loop", d)
	}
}

// DI-1, from the auditor's TestAuditSelfPointerHangs: a compression pointer
// to itself spun a core forever on a 30-byte datagram.
func TestSelfPointerTerminates(t *testing.T) {
	pkt := append(hdr(0, 1), 0xC0, 0x0C)
	pkt = append(pkt, make([]byte, 16)...)
	within(t, time.Second, func() {
		if h := extractHostname(pkt, src); h != "" {
			t.Errorf("got %q", h)
		}
	})
}

// DI-1, from the auditor's TestAuditPointerLoopEatsMemory: a label followed
// by a pointer back to it appended to the name on every lap until the OOM
// killer fired (32 bytes, 128 MB in half a second).
func TestPointerLoopIsBounded(t *testing.T) {
	pkt := append(hdr(0, 1), 0x01, 'a', 0xC0, 0x0C)
	pkt = append(pkt, make([]byte, 16)...)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	within(t, time.Second, func() {
		for i := 0; i < 1000; i++ {
			extractHostname(pkt, src)
		}
	})
	runtime.ReadMemStats(&after)
	if grown := after.TotalAlloc - before.TotalAlloc; grown > 8<<20 {
		t.Errorf("1000 parses allocated %d MiB", grown>>20)
	}
}

func TestParseDNSNameLimits(t *testing.T) {
	// Forward pointer.
	if _, _, err := parseDNSName([]byte{0xC0, 0x05, 0, 0, 0, 0}, 0); err == nil {
		t.Error("forward pointer accepted")
	}
	// Reserved label type 0x40.
	if _, _, err := parseDNSName([]byte{0x41, 'a', 0}, 0); err == nil {
		t.Error("extended label type accepted")
	}
	// Truncated label.
	if _, _, err := parseDNSName([]byte{5, 'a', 'b'}, 0); err == nil {
		t.Error("truncated label accepted")
	}
	// Longer than 255 bytes.
	var long []byte
	for i := 0; i < 5; i++ {
		long = append(long, 63)
		long = append(long, strings.Repeat("x", 63)...)
	}
	if _, _, err := parseDNSName(append(long, 0), 0); err == nil {
		t.Error("name over 255 bytes accepted")
	}
	// A backwards pointer chain is followed and the offset after the
	// first pointer is returned.
	pkt := append(label("host", "local"), 0xC0, 0x00)
	name, next, err := parseDNSName(pkt, len(pkt)-2)
	if err != nil || name != "host.local" || next != len(pkt) {
		t.Errorf("compressed name: %q %d %v", name, next, err)
	}
}

func TestExtractHostname(t *testing.T) {
	pkt := append(hdr(0, 1), label("Dads-iPhone", "local")...)
	pkt = append(pkt, aRecord(src)...)
	if h := extractHostname(pkt, src); h != "Dads-iPhone" {
		t.Errorf("got %q", h)
	}

	// A record for another address: a sleep proxy or someone naming a
	// neighbour. Not the sender's own name.
	other := append(hdr(0, 1), label("router", "local")...)
	other = append(other, aRecord(net.IPv4(192, 168, 1, 1))...)
	if h := extractHostname(other, src); h != "" {
		t.Errorf("record for another address accepted: %q", h)
	}

	// A query (QR=0) is never a source of names.
	query := append([]byte{}, pkt...)
	query[2] = 0
	if h := extractHostname(query, src); h != "" {
		t.Errorf("query accepted: %q", h)
	}

	// Non-.local names are ignored; a question is skipped first.
	withQ := append(hdr(1, 1), label("x", "local")...)
	withQ = append(withQ, 0, 1, 0, 1)
	withQ = append(withQ, label("example", "com")...)
	withQ = append(withQ, aRecord(src)...)
	if h := extractHostname(withQ, src); h != "" {
		t.Errorf("non-.local name accepted: %q", h)
	}
}

func TestParseDatagramSanitizes(t *testing.T) {
	pkt := append(hdr(0, 1), label("evil\x1b[2J\u202ename", "LOCAL")...)
	pkt = append(pkt, aRecord(src)...)
	s, err := ParseDatagram(pkt, src)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "evil[2Jname" || s.IP != "192.168.1.20" || s.Source != discovery.SourceMDNS || s.MAC != "" {
		t.Errorf("sighting: %+v", s)
	}
	if _, err := ParseDatagram(pkt, net.IPv4(127, 0, 0, 1)); err == nil {
		t.Error("loopback source accepted")
	}
}

func FuzzExtractHostname(f *testing.F) {
	good := append(hdr(0, 1), label("host", "local")...)
	f.Add(append(good, aRecord(src)...))
	f.Add(append(append(hdr(0, 1), 0xC0, 0x0C), make([]byte, 16)...))
	f.Add(append(append(hdr(0, 1), 0x01, 'a', 0xC0, 0x0C), make([]byte, 16)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		h := extractHostname(b, src)
		if len(h) > discovery.MaxNameLen || !utf8.ValidString(h) {
			t.Fatalf("unbounded or invalid name %q", h)
		}
		if discovery.SanitizeText(h, discovery.MaxNameLen) != h {
			t.Fatalf("unsanitised name %q", h)
		}
	})
}

// mdnsFrame wraps an mDNS payload in Ethernet/IPv4/UDP to UDP 5353 from s.
func mdnsFrame(s net.IP, payload []byte) []byte {
	ihl, ulen := 20, 8+len(payload)
	f := make([]byte, 14+ihl+8+len(payload))
	f[12], f[13] = 0x08, 0x00
	ip := f[14:]
	ip[0] = 0x45
	total := ihl + ulen
	ip[2], ip[3] = byte(total>>8), byte(total)
	ip[9] = 17
	copy(ip[12:16], s.To4())
	udp := ip[ihl:]
	udp[2], udp[3] = 0x14, 0xe9 // 5353
	udp[4], udp[5] = byte(ulen>>8), byte(ulen)
	copy(udp[8:], payload)
	return f
}

// FuzzParseFrame feeds arbitrary bytes through the whole-frame path (header
// stripping plus the mDNS parser) that now faces attacker-controlled frames.
func FuzzParseFrame(f *testing.F) {
	f.Add(mdnsFrame(src, append(append(hdr(0, 1), label("host", "local")...), aRecord(src)...)))
	f.Add([]byte{0x08, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseFrame(b)
		if err == nil && (s.IP == "" || len(s.Name) > discovery.MaxNameLen) {
			t.Fatalf("bad sighting from frame: %+v", s)
		}
	})
}

func FuzzParseDNSName(f *testing.F) {
	f.Add(label("host", "local"), 0)
	f.Add([]byte{0x01, 'a', 0xC0, 0x00}, 0)
	f.Fuzz(func(t *testing.T, b []byte, off int) {
		if off < 0 || off > len(b) {
			return
		}
		name, next, err := parseDNSName(b, off)
		if err == nil && (len(name) > maxNameLen || next <= off || next > len(b)) {
			t.Fatalf("name %d bytes, next %d (off %d, len %d)", len(name), next, off, len(b))
		}
	})
}
