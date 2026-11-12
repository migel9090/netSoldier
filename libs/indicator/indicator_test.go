package indicator

import (
	"errors"
	"strings"
	"testing"
)

// TestDomainAccepts covers the shapes real feeds deliver and the canonical
// spelling each must come out in, so threat-intel-sync and the matcher key
// the same indicator identically.
func TestDomainAccepts(t *testing.T) {
	for in, want := range map[string]string{
		"evil.com":                           "evil.com",
		"EVIL.COM":                           "evil.com",
		"evil.com.":                          "evil.com",
		"evil.com\r\n":                       "evil.com", // a CRLF line
		"*.evil.com":                         "evil.com",
		"  c2.evil.com  ":                    "c2.evil.com",
		"a.b.c.d.example":                    "a.b.c.d.example",
		"victim.duckdns.org":                 "victim.duckdns.org",
		"malware.herokuapp.com":              "malware.herokuapp.com",
		"bucket.s3.amazonaws.com":            "bucket.s3.amazonaws.com",
		"bücher.example":                     "xn--bcher-kva.example",
		"BÜCHER.example":                     "xn--bcher-kva.example",
		"xn--bcher-kva.example":              "xn--bcher-kva.example",
		"bücher-c2.example":                  "xn--bcher-c2-65a.example",
		"r3---sn-abc.googlevideo.com":        "r3---sn-abc.googlevideo.com",
		"www.ck":                             "www.ck", // PSL exception rule
		"1.2.3.example":                      "1.2.3.example",
		strings.Repeat("a", 63) + ".example": strings.Repeat("a", 63) + ".example",
	} {
		got, err := Domain(in)
		if err != nil {
			t.Errorf("Domain(%q) refused a legitimate indicator: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("Domain(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDomainRefusesAuditCandidates lists every hostile or over-broad domain
// the two 2026-11 auditors got through the old deny-list validators, plus
// the classic malformed shapes. Each one would have become an AdGuard rule
// ("*.*.*" was exported as "||*.*^") or a parent-domain match on every name
// under it.
func TestDomainRefusesAuditCandidates(t *testing.T) {
	for _, in := range []string{
		// wildcards and filter-rule syntax (TI-2)
		"*.*.*", "*.*.com", "*.*.co.uk", "com.*", "*", "*.",
		"evil.example^$dnsrewrite=203.0.113.9", "a.b|c^$important",
		"evil.example$important", "||evil.example^", "evil.example/",
		// control characters and whitespace
		"x.y\x00z", "evil\n.com", "evil\t.com", "evil .com", "evil\r.com",
		"evil\u200b.com", "evil\u202e.com",
		// public suffixes, ICANN and private sections (TI-2, DE-15)
		"com", "pl", "co.uk", "com.pl", "co.kr", "com.ar", "com.tw", "edu.pl",
		"waw.pl", "com.ua", "blogspot.com", "s3.amazonaws.com",
		"blob.core.windows.net", "trycloudflare.com", "github.io", "duckdns.org",
		"vercel.app", "herokuapp.com", "cloudfront.net", "foo.ck",
		// shared-hosting parents the PSL does not cover
		"amazonaws.com", "core.windows.net", "googleusercontent.com", "glitch.me",
		// household-local namespaces
		"in-addr.arpa", "1.1.168.192.in-addr.arpa", "router.home.arpa",
		"printer.local", "localhost", "nas.lan", "fritz.home", "db.internal",
		// addresses are not names
		"1.2.3.4", "203.0.113.9",
		// malformed shapes
		"", "   ", ".", "evil..com", "-evil.com", "evil-.com", "evil.com/path",
		"http://evil.com", "evil.com:8080", "user@evil.com", "_dmarc.evil.com",
		"xn--zz.example", "xn--mnchen-c2-9db.example", // invalid punycode
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 200) + "example",
		strings.Repeat("x", 2000),
	} {
		if got, err := Domain(in); err == nil {
			t.Errorf("Domain(%q) accepted %q", in, got)
		}
	}
}

func TestQueryName(t *testing.T) {
	for in, want := range map[string]string{
		"evil.com":                    "evil.com",
		"EVIL.COM.":                   "evil.com",
		"bücher.example":              "xn--bcher-kva.example",
		"BÜCHER.EXAMPLE.":             "xn--bcher-kva.example",
		"XN--BCHER-KVA.EXAMPLE":       "xn--bcher-kva.example",
		"_ldap._tcp.dc.evil.com":      "_ldap._tcp.dc.evil.com",
		"_ldap._tcp.bücher.example":   "_ldap._tcp.xn--bcher-kva.example",
		"r3---sn-abc.googlevideo.com": "r3---sn-abc.googlevideo.com",
	} {
		got, ok := QueryName(in)
		if !ok || got != want {
			t.Errorf("QueryName(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", " ", ".", "evil\x00.com", "evil .com", strings.Repeat("a", 2000)} {
		if got, ok := QueryName(in); ok {
			t.Errorf("QueryName(%q) = %q, want refusal", in, got)
		}
	}
	// A U-label query and an A-label indicator meet on one key, and the
	// other way round (DE-20).
	ind, err := Domain("xn--bcher-c2-65a.example")
	if err != nil {
		t.Fatal(err)
	}
	if q, _ := QueryName("bücher-c2.example"); q != ind {
		t.Errorf("U-label query %q does not meet A-label indicator %q", q, ind)
	}
	ind, _ = Domain("münchen-c2.example")
	if q, _ := QueryName(strings.ToUpper("münchen-c2.example")); q != ind {
		t.Errorf("upper-case U-label query %q does not meet indicator %q", q, ind)
	}
}

func TestIPAccepts(t *testing.T) {
	for in, want := range map[string]string{
		"8.8.8.8":                  "8.8.8.8",
		" 203.0.113.7 ":            "203.0.113.7",
		"203.0.113.7:443":          "203.0.113.7",
		"[2001:db8::1]:443":        "2001:db8::1",
		"2001:DB8::0001":           "2001:db8::1",
		"::ffff:198.51.100.9":      "198.51.100.9",
		"2a00:1450:4001:81b::200e": "2a00:1450:4001:81b::200e",
		"198.51.100.0/24":          "198.51.100.0/24",
		"198.51.100.77/24":         "198.51.100.0/24", // masked
		"1.10.16.0/20":             "1.10.16.0/20",
		"44.0.0.0/12":              "44.0.0.0/12",
		"::ffff:198.51.100.0/120":  "198.51.100.0/24",
		"2001:db8::/32":            "2001:db8::/32",
		"2a06:e480::/48":           "2a06:e480::/48",
	} {
		got, err := IP(in)
		if err != nil {
			t.Errorf("IP(%q) refused a legitimate indicator: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("IP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIPRefusesAuditCandidates: every catch-all, local and malformed address
// the auditors fed through. 0.0.0.0/1 + 128.0.0.0/1 used to match every
// IPv4 address; the gateway, multicast and broadcast were accepted.
func TestIPRefusesAuditCandidates(t *testing.T) {
	for _, in := range []string{
		// over-broad prefixes
		"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "8.0.0.0/7", "44.0.0.0/11",
		"::/0", "::/1", "2000::/3", "2a00::/12", "2001:db8::/31",
		// non-global prefixes
		"10.0.0.0/8", "192.168.0.0/16", "192.168.1.0/24", "127.0.0.0/8", "0.0.0.0/8",
		"100.64.0.0/10", "172.16.0.0/12", "169.254.0.0/16", "224.0.0.0/4",
		"192.160.0.0/12", // overlaps 192.168.0.0/16
		"fc00::/7", "fd00::/48", "fe80::/64", "ff02::/16", "::ffff:10.0.0.0/104",
		"::ffff:0.0.0.0/95",
		// non-global addresses
		"0.0.0.0", "127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.5.4",
		"100.64.0.1", "169.254.1.1", "224.0.0.251", "239.255.255.250",
		"255.255.255.255", "240.0.0.1", "192.0.0.8", "198.18.0.1",
		"::", "::1", "fe80::1", "fe80::1%eth0", "fd12:3456::1", "ff02::fb",
		"::ffff:192.168.1.1", "64:ff9b::808:808",
		// malformed
		"", "not-an-ip", "203.000.113.007", "1.2.3", "1.2.3.4.5", "1.2.3.4/33",
		"not-a-cidr/x", `"203.0.113.10":"443"`, "203.0.113.7 443", "203.0.113.7\n:443",
	} {
		if got, err := IP(in); err == nil {
			t.Errorf("IP(%q) accepted %q", in, got)
		}
	}
}

func TestQueryAddr(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.7":              "203.0.113.7",
		" 203.0.113.7 ":            "203.0.113.7",
		"::ffff:203.0.113.7":       "203.0.113.7",
		"0:0:0:0:0:ffff:cb00:7107": "203.0.113.7",
		"2001:DB8:0:0:0:0:0:1":     "2001:db8::1",
		"192.168.1.1":              "192.168.1.1", // a query is not judged
		"fe80::1%eth0":             "fe80::1",
	} {
		got, ok := QueryAddr(in)
		if !ok || got.String() != want {
			t.Errorf("QueryAddr(%q) = %v, %v; want %s", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "203.000.113.007", "203.0.113.7:443", "evil.com"} {
		if got, ok := QueryAddr(in); ok {
			t.Errorf("QueryAddr(%q) = %v, want refusal", in, got)
		}
	}
}

func TestHash(t *testing.T) {
	ok := []struct{ typ, in, want string }{
		{TypeMD5, "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"},
		{TypeJA3, "db8a6f4f9f8195ea17db377175d2cb08", "db8a6f4f9f8195ea17db377175d2cb08"},
		{TypeSHA256, strings.Repeat("Ab", 32), strings.Repeat("ab", 32)},
		{TypeCertSHA1, "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
		{TypeCertSHA1, "A9:4A:8F:E5:CC:B1:9B:A6:1C:4C:08:73:D3:91:E9:87:98:2F:BB:D3", "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"},
		{TypeCertSHA256, strings.Repeat("ab", 32), strings.Repeat("ab", 32)},
		{TypeTLSFP, "t13d1516h2_8daaf6152771_b186095e22b6", "t13d1516h2_8daaf6152771_b186095e22b6"},
		{TypeTLSFP, "T13D3012H2_1D37BD780C83_882D495AC381", "t13d3012h2_1d37bd780c83_882d495ac381"},
		{TypeTLSFP, "q13i0310h3_55b375c5d22e_cd85d2d88918", "q13i0310h3_55b375c5d22e_cd85d2d88918"},
	}
	for _, c := range ok {
		got, err := Hash(c.typ, c.in)
		if err != nil || got != c.want {
			t.Errorf("Hash(%s, %q) = %q, %v; want %q", c.typ, c.in, got, err, c.want)
		}
	}
	bad := []struct{ typ, in string }{
		{TypeMD5, "not-a-hash;rm"}, {TypeMD5, "abc123"}, {TypeMD5, strings.Repeat("g", 32)},
		{TypeMD5, strings.Repeat("a", 33)}, {TypeMD5, ""}, {TypeMD5, "d41d8cd98f00b204 e9800998ecf8427e"},
		{TypeSHA256, "zz"}, {TypeSHA256, strings.Repeat("a", 63)}, {TypeSHA256, "d41d8cd98f00b204e9800998ecf8427e"},
		{TypeJA3, "abc123"}, {TypeCertSHA1, strings.Repeat("a", 64)},
		{TypeCertSHA256, strings.Repeat("a", 40)},
		{TypeTLSFP, "abc"}, {TypeTLSFP, "x13d1516h2_8daaf6152771_b186095e22b6"},
		{TypeTLSFP, "t13d1516h2_8daaf615277_b186095e22b6"}, {TypeTLSFP, "t13d1516h2_8daaf6152771_b186095e22bz"},
		{TypeTLSFP, "t13x1516h2_8daaf6152771_b186095e22b6"}, {TypeTLSFP, "t13d1516h2_8daaf6152771_b186095e22b6_x"},
		{"sha1", strings.Repeat("a", 40)},
	}
	for _, c := range bad {
		if got, err := Hash(c.typ, c.in); err == nil {
			t.Errorf("Hash(%s, %q) accepted %q", c.typ, c.in, got)
		}
	}
}

func TestURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://evil.example/payload":          "http://evil.example/payload",
		"HTTP://EVIL.Example/Payload.EXE":      "http://evil.example/Payload.EXE",
		"http://evil.example":                  "http://evil.example/",
		"http://evil.example:8080/a?b=c":       "http://evil.example:8080/a?b=c",
		"https://bücher.example/x#frag":        "https://xn--bcher-kva.example/x",
		"http://45.61.49.78/razor/r4z0r.mips":  "http://45.61.49.78/razor/r4z0r.mips",
		"http://[2001:db8::1]:8080/x":          "http://[2001:db8::1]:8080/x",
		"http://bucket.s3.amazonaws.com/a.exe": "http://bucket.s3.amazonaws.com/a.exe",
		"http://evil.example/a%20b":            "http://evil.example/a%20b",
	} {
		got, err := URL(in)
		if err != nil || got != want {
			t.Errorf("URL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"http://x/\tIntel::URL\n0.0.0.0/0\tIntel::SUBNET\tx\t-\t-",
		"http://evil.example/a b", "http://evil.example/\x00", "ftp://evil.example/x",
		"javascript:alert(1)", "http:evil.example", "//evil.example/x", "evil.example/x",
		"http://user:pw@evil.example/", "http://bank.example@evil.example/",
		"http://192.168.1.1/admin", "http://127.0.0.1/", "http://[::1]/", "http://localhost/",
		"http://router.lan/", "http://intranet/x", "http://*.evil.example/",
		"http://evil.example:0/", "http://evil.example:99999/", "http://evil.example:08080/",
		"http://203.000.113.007/", "", "http://evil.example/" + strings.Repeat("a", MaxURLLen),
	} {
		if got, err := URL(in); err == nil {
			t.Errorf("URL(%q) accepted %q", in, got)
		}
	}
}

func TestText(t *testing.T) {
	for _, c := range []struct {
		in   string
		max  int
		want string
	}{
		{"Mozi", 64, "Mozi"},
		{"Mozi\t-\n0.0.0.0/0\tIntel::SUBNET\tthreatfox\tinjected", 512, "Mozi - 0.0.0.0/0 Intel::SUBNET threatfox injected"},
		{"seen in campaign X\nsecond line\twith a tab", 512, "seen in campaign X second line with a tab"},
		{"  a\r\n\r\n  b  ", 64, "a b"},
		{"bad\x00\x07\x1b[31mred\u202e\u200b\u2028x", 64, "bad[31mred x"},
		{"\xff\xfeok", 64, "\uFFFDok"},
		{"zażółć", 7, "zażó"}, // "ł" would end at byte 8: cut on a rune boundary
		{strings.Repeat("a", 600), MaxTextLen, strings.Repeat("a", MaxTextLen)},
		{"", 10, ""},
		{"a b", 2, "a"}, // no dangling separator at the cut
	} {
		if got := Text(c.in, c.max); got != c.want {
			t.Errorf("Text(%q, %d) = %q, want %q", c.in, c.max, got, c.want)
		}
	}
}

func TestTags(t *testing.T) {
	in := []string{"c2", "c2", " botnet ", "", "\t", "x\ny"}
	for i := 0; i < 50; i++ {
		in = append(in, "t"+strings.Repeat("x", i))
	}
	got := Tags(in)
	if len(got) != MaxTags {
		t.Fatalf("len(Tags) = %d, want %d", len(got), MaxTags)
	}
	if got[0] != "c2" || got[1] != "botnet" || got[2] != "x y" {
		t.Errorf("Tags = %q", got[:3])
	}
	if Tags(nil) != nil {
		t.Error("Tags(nil) should be nil")
	}
}

func TestValueDispatch(t *testing.T) {
	for _, c := range []struct{ typ, in, want string }{
		{TypeDomain, "EVIL.example", "evil.example"},
		{TypeIP, "203.0.113.7:443", "203.0.113.7"},
		{TypeURL, "http://evil.example", "http://evil.example/"},
		{TypeMD5, strings.Repeat("A", 32), strings.Repeat("a", 32)},
	} {
		got, err := Value(c.typ, c.in)
		if err != nil || got != c.want {
			t.Errorf("Value(%s, %q) = %q, %v; want %q", c.typ, c.in, got, err, c.want)
		}
	}
	if _, err := Value("mystery", "x"); !errors.Is(err, ErrUnknownType) {
		t.Errorf("Value(mystery) error = %v, want ErrUnknownType", err)
	}
	if _, err := Value(TypeDomain, "com"); err == nil || errors.Is(err, ErrUnknownType) {
		t.Errorf("Value(domain, com) error = %v, want a validation error", err)
	}
	for _, typ := range []string{TypeDomain, TypeIP, TypeURL, TypeMD5, TypeSHA256, TypeJA3,
		TypeTLSFP, TypeCertSHA1, TypeCertSHA256} {
		if !KnownType(typ) {
			t.Errorf("KnownType(%q) = false", typ)
		}
	}
	if KnownType("mystery") {
		t.Error("KnownType(mystery) = true")
	}
}
