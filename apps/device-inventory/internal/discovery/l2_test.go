package discovery

import (
	"net"
	"testing"
)

// udpFrame builds an Ethernet/IPv4/UDP frame from src to dstPort with the
// given payload and optional extra IP-option words.
func udpFrame(src net.IP, dstPort uint16, ihlWords int, fragWord uint16, payload []byte) []byte {
	ihl := 20 + 4*ihlWords
	f := make([]byte, ethHeaderLen+ihl+udpHeaderLen+len(payload))
	f[12], f[13] = 0x08, 0x00
	ip := f[ethHeaderLen:]
	ip[0] = byte(0x40 | (ihl / 4))
	total := ihl + udpHeaderLen + len(payload)
	ip[2], ip[3] = byte(total>>8), byte(total)
	ip[6], ip[7] = byte(fragWord>>8), byte(fragWord)
	ip[9] = protoUDP
	copy(ip[12:16], src.To4())
	udp := ip[ihl:]
	udp[2], udp[3] = byte(dstPort>>8), byte(dstPort)
	ulen := udpHeaderLen + len(payload)
	udp[4], udp[5] = byte(ulen>>8), byte(ulen)
	copy(udp[udpHeaderLen:], payload)
	return f
}

func TestUDPPayload(t *testing.T) {
	want := []byte("hello")
	frame := udpFrame(net.IPv4(192, 168, 1, 7), 5353, 0, 0, want)
	payload, src, ok := UDPPayload(frame, 5353)
	if !ok || string(payload) != "hello" || src.String() != "192.168.1.7" {
		t.Fatalf("UDPPayload = %q %v %v", payload, src, ok)
	}
	// Trailing Ethernet padding is trimmed via the IP total-length field.
	padded := append(udpFrame(net.IPv4(192, 168, 1, 7), 5353, 0, 0, want), make([]byte, 20)...)
	if p, _, ok := UDPPayload(padded, 5353); !ok || string(p) != "hello" {
		t.Errorf("padded frame: %q %v", p, ok)
	}
	// IP options (IHL > 5) are handled.
	if p, _, ok := UDPPayload(udpFrame(net.IPv4(192, 168, 1, 7), 5353, 1, 0, want), 5353); !ok || string(p) != "hello" {
		t.Errorf("ip-options frame: %q %v", p, ok)
	}

	reject := map[string][]byte{
		"truncated":     frame[:30],
		"wrong port":    udpFrame(net.IPv4(192, 168, 1, 7), 1900, 0, 0, want),
		"fragment":      udpFrame(net.IPv4(192, 168, 1, 7), 5353, 0, 0x2000, want),
		"later frag":    udpFrame(net.IPv4(192, 168, 1, 7), 5353, 0, 0x0001, want),
		"multicast src": udpFrame(net.IPv4(224, 0, 0, 251), 5353, 0, 0, want),
	}
	notUDP := udpFrame(net.IPv4(192, 168, 1, 7), 5353, 0, 0, want)
	notUDP[ethHeaderLen+9] = 6 // TCP
	reject["not udp"] = notUDP
	notIPv4 := udpFrame(net.IPv4(192, 168, 1, 7), 5353, 0, 0, want)
	notIPv4[12], notIPv4[13] = 0x86, 0xdd
	reject["not ipv4"] = notIPv4
	for name, f := range reject {
		if _, _, ok := UDPPayload(f, 5353); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func FuzzUDPPayload(f *testing.F) {
	f.Add(udpFrame(net.IPv4(192, 168, 1, 7), 5353, 0, 0, []byte("x")))
	f.Add(udpFrame(net.IPv4(192, 168, 1, 7), 5353, 1, 0, make([]byte, 40)))
	f.Add([]byte{0x08, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		payload, src, ok := UDPPayload(b, 5353)
		if !ok {
			return
		}
		// Whatever is accepted must be a real sub-view and a usable source.
		if len(payload) > len(b) {
			t.Fatalf("payload longer than frame: %d > %d", len(payload), len(b))
		}
		if src == nil || src.To4() == nil {
			t.Fatalf("accepted a non-IPv4 source %v", src)
		}
	})
}
