package discovery

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

func TestSanitizeText(t *testing.T) {
	for in, want := range map[string]string{
		"Dads-iPhone":                       "Dads-iPhone",
		"  spaced \t\r\n out  ":             "spaced out",
		"a\x00b\x7fc\x1b[31m":               "abc[31m",
		"bad\xff\xfeutf8":                   "badutf8",
		"bidi\u202eflip\u2066x\u200by":      "bidiflipxy",
		"Łukasz's iPhone":                   "Łukasz's iPhone",
		"\u00a0nbsp\u3000ideographic\u00a0": "nbsp ideographic",
		"":                                  "",
		"\x00\x01":                          "",
	} {
		if got := SanitizeText(in, MaxNameLen); got != want {
			t.Errorf("SanitizeText(%q) = %q, want %q", in, got, want)
		}
	}
	// Cut on a rune boundary, never mid-character.
	if got := SanitizeText(strings.Repeat("ł", 40), 9); got != "łłłł" {
		t.Errorf("cut = %q", got)
	}
	if got := SanitizeText("ab cd", 3); got != "ab" {
		t.Errorf("a trailing space is not kept: %q", got)
	}
}

func TestCanonicalAndParseMAC(t *testing.T) {
	if m, ok := CanonicalMAC([]byte{0x00, 0x11, 0x24, 0xAA, 0xBB, 0x01}); !ok || m != "00:11:24:aa:bb:01" {
		t.Errorf("canonical: %q %v", m, ok)
	}
	for _, hw := range [][]byte{
		{0x01, 0, 0x5e, 0, 0, 1},             // multicast
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // broadcast
		{0, 0, 0, 0, 0, 0},
		{0, 1, 2, 3, 4},
		{0, 1, 2, 3, 4, 5, 6, 7},
	} {
		if _, ok := CanonicalMAC(hw); ok {
			t.Errorf("CanonicalMAC(% x) accepted", hw)
		}
	}
	for in, want := range map[string]string{
		"AA:BB:CC:DD:EE:F0": "aa:bb:cc:dd:ee:f0",
		"aa-bb-cc-dd-ee-f0": "aa:bb:cc:dd:ee:f0",
	} {
		if got, ok := ParseMAC(in); !ok || got != want {
			t.Errorf("ParseMAC(%q) = %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "garbage", "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff:00:11", "01:00:5e:00:00:01", "zz:11:22:33:44:55"} {
		if _, ok := ParseMAC(in); ok {
			t.Errorf("ParseMAC(%q) accepted", in)
		}
	}
}

func TestIsRandomizedMAC(t *testing.T) {
	for _, m := range []string{"aa:bb:cc:dd:ee:ff", "02:00:00:00:00:01", "3a:1f:2b:00:00:01"} {
		if !IsRandomizedMAC(m) {
			t.Errorf("IsRandomizedMAC(%q) = false", m)
		}
	}
	for _, m := range []string{"00:11:22:33:44:55", "b8:27:eb:00:00:01", "", "garbage"} {
		if IsRandomizedMAC(m) {
			t.Errorf("IsRandomizedMAC(%q) = true", m)
		}
	}
}

func TestUsableIPv4(t *testing.T) {
	for _, ok := range []string{"192.168.1.1", "10.0.0.1", "169.254.3.4", "::ffff:192.168.1.2"} {
		if _, good := ParseUsableIPv4(ok); !good {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"0.0.0.0", "0.1.2.3", "127.0.0.1", "224.0.0.251", "255.255.255.255", "fe80::1", "x"} {
		if _, good := ParseUsableIPv4(bad); good {
			t.Errorf("%s accepted", bad)
		}
	}
	if _, ok := UsableIPv4(net.IP{1, 2, 3}); ok {
		t.Error("3-byte address accepted")
	}
}

func TestSourceRanks(t *testing.T) {
	order := []Source{"", SourceSSDP, SourceMDNS, SourceLLDP, SourceDHCP, SourceLease}
	for i := 1; i < len(order); i++ {
		if order[i].Rank() <= order[i-1].Rank() {
			t.Errorf("%q should outrank %q", order[i], order[i-1])
		}
	}
	if SourceARP.Rank() != SourceDHCP.Rank() || !SourceLease.Authoritative() || SourceDHCP.Authoritative() {
		t.Error("ARP and DHCP are equal and only the lease table is authoritative")
	}
}

func TestRejectReason(t *testing.T) {
	for err, want := range map[error]string{
		fmt.Errorf("x: %w", ErrLinkMismatch): "link_mismatch",
		ErrIgnored:                           "ignored",
		ErrMalformed:                         "malformed",
		errors.New("other"):                  "malformed",
	} {
		if got := RejectReason(err); got != want {
			t.Errorf("RejectReason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestLogLimiter(t *testing.T) {
	l := LogLimiter{Interval: 10 * time.Second}
	t0 := time.Unix(1000, 0)
	if ok, _ := l.Allow(t0); !ok {
		t.Fatal("first event must log")
	}
	for i := 1; i <= 5; i++ {
		if ok, _ := l.Allow(t0.Add(time.Duration(i) * time.Second)); ok {
			t.Fatal("events inside the interval must not log")
		}
	}
	if ok, n := l.Allow(t0.Add(11 * time.Second)); !ok || n != 5 {
		t.Errorf("after the interval: ok=%v suppressed=%d, want true 5", ok, n)
	}
}

func FuzzSanitizeText(f *testing.F) {
	f.Add("a\x00b\xff\x1b[31m\r\n<script>\u202e", 64)
	f.Add("Łukasz", 3)
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 1024 {
			return
		}
		out := SanitizeText(s, max)
		if len(out) > max || !utf8.ValidString(out) || strings.TrimSpace(out) != out || strings.Contains(out, "  ") {
			t.Fatalf("SanitizeText(%q, %d) = %q", s, max, out)
		}
		for _, r := range out {
			if r != ' ' && !unicode.IsPrint(r) {
				t.Fatalf("unprintable %U in %q", r, out)
			}
		}
		if SanitizeText(out, max) != out {
			t.Fatalf("not idempotent: %q", out)
		}
	})
}
