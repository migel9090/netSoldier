package ssdp

import (
	"errors"
	"net"
	"testing"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

var src = net.IPv4(192, 168, 77, 9)

func notify(server, location string) []byte {
	return []byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNTS: ssdp:alive\r\nSERVER: " + server +
		"\r\nLOCATION: " + location + "\r\n\r\n")
}

// DI-10, from the auditor's TestAuditProductName: the OS token before UPnP/
// became the "hostname", so every Linux box was named "Linux".
func TestExtractProductName(t *testing.T) {
	for server, want := range map[string]string{
		"Linux/5.15 UPnP/1.0 MiniDLNA/1.3":                     "MiniDLNA",
		"Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0": "UPnP-Device-Host",
		"POSIX, UPnP/1.0, Intel MicroStack/1.0.2777":           "Intel MicroStack",
		"Linux/3.14.0 UPnP/1.0 Sonos/63.2-88230 (ZPS9)":        "Sonos",
		"Linux/3.14.0 UPnP/1.0":                                "",
		"Apache/2.4":                                           "",
		"":                                                     "",
		"OS/1 UPnP/1.0 Evil\x1b[2J\u202eName/1":                "Evil[2JName",
	} {
		if got := extractProductName(server); got != want {
			t.Errorf("%q -> %q, want %q", server, got, want)
		}
	}
}

// Found by FuzzSSDP: lower-casing invalid UTF-8 (or a rune such as U+0130)
// changes the byte length, and the index of "upnp/" in the lowered string
// overran the original.
func TestProductNameOffsetsSurviveCaseFolding(t *testing.T) {
	for _, server := range []string{
		"000000000\xd1\xd1\xd1000UPnP/",
		"\u0130\u0130\u0130\u0130 UPnP/1.0 Thing/1",
		"\xff\xfe UPNP/1.0 \xd1Thing/1",
	} {
		_ = extractProductName(server) // must not panic
	}
	if got := extractProductName("\u0130\u0130 UPnP/1.0 Thing/1"); got != "Thing" {
		t.Errorf("got %q", got)
	}
}

func TestParseDatagram(t *testing.T) {
	s, err := ParseDatagram(notify("Linux/5.15 UPnP/1.0 MiniDLNA/1.3", "http://192.168.77.9:8200/rootDesc.xml"), src)
	if err != nil {
		t.Fatal(err)
	}
	if s != (discovery.Sighting{Source: discovery.SourceSSDP, IP: "192.168.77.9", Name: "MiniDLNA"}) {
		t.Errorf("got %+v", s)
	}
	if _, err := ParseDatagram(notify("Linux UPnP/1.0 NAS/1", "http://nas.local:80/d.xml"), src); err != nil {
		t.Errorf("LOCATION with a host name: %v", err)
	}
}

// DI-10, from the auditor's run.sh: one unicast NOTIFY whose LOCATION named
// another host's address put a name on that host.
func TestLocationNamingAnotherHostIsDropped(t *testing.T) {
	_, err := ParseDatagram(notify("Totally-Legit-NAS/1.0 UPnP/1.0 NAS/1", "http://192.168.77.1:80/desc.xml"), src)
	if !errors.Is(err, discovery.ErrIgnored) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseDatagramIgnores(t *testing.T) {
	for name, msg := range map[string][]byte{
		"m-search": []byte("M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\nSERVER: x UPnP/1.0 y/1\r\n\r\n"),
		"byebye":   []byte("NOTIFY * HTTP/1.1\r\nNTS: ssdp:byebye\r\nSERVER: x UPnP/1.0 y/1\r\n\r\n"),
		"no name":  notify("Linux/5.15", "http://192.168.77.9/"),
		"bad url":  notify("x UPnP/1.0 y/1", "http://[::1"),
		"empty":    nil,
	} {
		if _, err := ParseDatagram(msg, src); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := ParseDatagram(notify("x UPnP/1.0 y/1", ""), net.IPv4(0, 0, 0, 0)); err == nil {
		t.Error("unspecified source accepted")
	}
	h := parseHeaders([]byte("NOTIFY * HTTP/1.1\r\nServer: first\r\nSERVER: second\r\n"))
	if h["server"] != "first" {
		t.Errorf("first header occurrence should win: %q", h["server"])
	}
}

func FuzzSSDP(f *testing.F) {
	f.Add(notify("Linux/5.15 UPnP/1.0 MiniDLNA/1.3", "http://192.168.77.9:8200/rootDesc.xml"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseDatagram(b, src)
		if err == nil && (s.IP != "192.168.77.9" || len(s.Name) > discovery.MaxNameLen || s.Name == "") {
			t.Fatalf("bad sighting %+v", s)
		}
	})
}

// ssdpFrame wraps an SSDP payload in Ethernet/IPv4/UDP to UDP 1900 from s.
func ssdpFrame(s net.IP, payload []byte) []byte {
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
	udp[2], udp[3] = 0x07, 0x6c // 1900
	udp[4], udp[5] = byte(ulen>>8), byte(ulen)
	copy(udp[8:], payload)
	return f
}

// FuzzParseFrame feeds arbitrary bytes through the whole-frame path (header
// stripping plus the SSDP parser) that now faces attacker-controlled frames.
func FuzzParseFrame(f *testing.F) {
	f.Add(ssdpFrame(src, notify("Linux/5.15 UPnP/1.0 MiniDLNA/1.3", "http://192.168.77.9:8200/rootDesc.xml")))
	f.Add([]byte{0x08, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseFrame(b)
		if err == nil && (s.IP == "" || len(s.Name) > discovery.MaxNameLen) {
			t.Fatalf("bad sighting from frame: %+v", s)
		}
	})
}
