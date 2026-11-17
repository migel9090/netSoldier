package indicator

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/publicsuffix"
)

// TestNeverBlockProtects: the hosts a feed has listed by mistake, or would
// list by extracting the host of a malicious URL, are refused, and so is
// everything under a "tree" entry.
func TestNeverBlockProtects(t *testing.T) {
	for _, c := range []struct{ typ, value, reason string }{
		{TypeDomain, "google.com", ReasonPopular},
		{TypeDomain, "docs.google.com", ReasonPopular},  // a malicious Docs URL in URLhaus
		{TypeDomain, "drive.google.com", ReasonPopular}, // likewise Drive
		{TypeDomain, "connectivitycheck.gstatic.com", ReasonPopular},
		{TypeDomain, "r3---sn-abc.googlevideo.com", ReasonPopular},
		{TypeDomain, "lh3.googleusercontent.com", ReasonPopular},
		{TypeDomain, "www.msftconnecttest.com", ReasonPopular},
		{TypeDomain, "api.telegram.org", ReasonPopular}, // Telegram bots used as C2
		{TypeDomain, "cdn.discordapp.com", ReasonPopular},
		{TypeDomain, "onedrive.live.com", ReasonPopular},
		{TypeDomain, "GOOGLE.COM.", ReasonPopular},
		{TypeDomain, "tumblr.com", ReasonPopular},
		{TypeDomain, "sharepoint.com", ReasonPopular},
		{TypeDomain, "raw.githubusercontent.com", ReasonSharedHosting},
		{TypeDomain, "storage.googleapis.com", ReasonSharedHosting},
		{TypeDomain, "firebasestorage.googleapis.com", ReasonSharedHosting},
		{TypeDomain, "pastebin.com", ReasonSharedHosting},
		{TypeDomain, "000webhostapp.com", ReasonSharedHosting},
		{TypeDomain, "weebly.com", ReasonSharedHosting},
		{TypeDomain, "e1234.dscb.akamaiedge.net", ReasonCDN},
		{TypeDomain, "cdn.jsdelivr.net", ReasonCDN},
		{TypeDomain, "fastly.net", ReasonCDN},
		{TypeDomain, "no-ip.com", ReasonDynamicDNS},
		{TypeDomain, "mooo.com", ReasonDynamicDNS},
		{TypeDomain, "dns.google", ReasonPublicResolver},
		{TypeDomain, "security.cloudflare-dns.com", ReasonPublicResolver},
		{TypeIP, "8.8.8.8", ReasonPublicResolver},
		{TypeIP, "1.1.1.1", ReasonPublicResolver},
		{TypeIP, "9.9.9.9", ReasonPublicResolver},
		{TypeIP, "2620:fe::fe", ReasonPublicResolver},
		{TypeIP, "2001:4860:4860::8888", ReasonPublicResolver},
		{TypeIP, "8.8.8.0/24", ReasonPublicResolver},     // contains 8.8.8.8
		{TypeIP, "8.0.0.0/12", ReasonPublicResolver},     // likewise
		{TypeIP, "2606:4700::/32", ReasonPublicResolver}, // contains Cloudflare's resolvers
	} {
		p, ok := NeverBlock(c.typ, c.value)
		if !ok || p.Reason != c.reason {
			t.Errorf("NeverBlock(%s, %q) = %+v, %v; want reason %s", c.typ, c.value, p, ok, c.reason)
			continue
		}
		err := CheckBlockable(c.typ, c.value)
		var nb *NeverBlockError
		if !errors.Is(err, ErrNeverBlock) || !errors.As(err, &nb) || nb.Reason != c.reason {
			t.Errorf("CheckBlockable(%s, %q) = %v", c.typ, c.value, err)
		}
	}
}

// TestNeverBlockLeavesTenantsBlockable: a "name" entry protects only the
// apex, and nothing protects a customer of a shared host, a look-alike, or
// an address next to a resolver. The list is immunity from blocking, so
// these must stay blockable.
func TestNeverBlockLeavesTenantsBlockable(t *testing.T) {
	for _, c := range []struct{ typ, value string }{
		{TypeDomain, "evil.000webhostapp.com"},
		{TypeDomain, "phish.weebly.com"},
		{TypeDomain, "evil-bucket.storage.googleapis.com"},
		{TypeDomain, "victim-corp.sharepoint.com"},
		{TypeDomain, "evil.tumblr.com"},
		{TypeDomain, "evil.mooo.com"},
		{TypeDomain, "c2.no-ip.com.evil.example"},
		{TypeDomain, "evil.github.io"},
		{TypeDomain, "evil.herokuapp.com"},
		{TypeDomain, "d111111abcdef8.cloudfront.net"},
		{TypeDomain, "phish.b-cdn.net"},
		{TypeDomain, "google.com.evil.example"},
		{TypeDomain, "evilgoogle.com"},
		{TypeDomain, "xgoogle.com"},
		{TypeDomain, "c2.evil.example"},
		{TypeIP, "8.8.8.9"},
		{TypeIP, "203.0.113.7"},
		{TypeIP, "198.51.100.0/24"},
		{TypeIP, "1.1.2.0/24"},
		{TypeURL, "https://docs.google.com/uc?id=malware"}, // a URL is specific
		{TypeMD5, strings.Repeat("a", 32)},
		{TypeDomain, ""},
		{TypeIP, "not-an-ip"},
	} {
		if p, ok := NeverBlock(c.typ, c.value); ok {
			t.Errorf("NeverBlock(%s, %q) = %+v: must stay blockable", c.typ, c.value, p)
		}
		if err := CheckBlockable(c.typ, c.value); err != nil {
			t.Errorf("CheckBlockable(%s, %q) = %v", c.typ, c.value, err)
		}
	}
}

func TestNeverBlockAddrForms(t *testing.T) {
	if _, ok := NeverBlockAddr(netip.MustParseAddr("::ffff:8.8.8.8")); !ok {
		t.Error("an IPv4-mapped spelling of 8.8.8.8 is not protected")
	}
	if _, ok := NeverBlockPrefix(netip.MustParsePrefix("::ffff:8.8.8.0/120")); !ok {
		t.Error("an IPv4-mapped prefix holding 8.8.8.8 is not protected")
	}
	if _, ok := NeverBlockAddr(netip.Addr{}); ok {
		t.Error("the zero address is protected")
	}
	if _, ok := NeverBlockPrefix(netip.Prefix{}); ok {
		t.Error("the zero prefix is protected")
	}
}

// TestNeverBlockListInvariants checks every entry of the embedded file
// against the Public Suffix List and the indicator rules, so a refresh, or a
// golang.org/x/net update that changes the PSL, cannot quietly turn an entry
// into immunity for every tenant of a shared host.
func TestNeverBlockListInvariants(t *testing.T) {
	if !strings.Contains(neverBlockFile, "Majestic Million of "+NeverBlockSnapshot) {
		t.Errorf("neverblock.txt does not name the snapshot %s it was curated from", NeverBlockSnapshot)
	}
	if !strings.Contains(neverBlockFile, "CC BY 3.0") || !strings.Contains(neverBlockFile, "Majestic-12 Ltd") {
		t.Error("neverblock.txt lost its attribution (CC BY 3.0 requires it)")
	}
	info := NeverBlockList()
	if info.Entries < 100 || info.Entries > 1000 {
		t.Errorf("list has %d entries: modest means between 100 and 1000", info.Entries)
	}
	for _, r := range NeverBlockReasons() {
		if info.ByReason[r] == 0 {
			t.Errorf("no entry with reason %s", r)
		}
	}

	all := map[string]Protection{}
	for d, p := range neverBlock.names {
		all[d] = p
	}
	for d, p := range neverBlock.trees {
		all[d] = p
	}
	for d, p := range all {
		suffix, _ := publicsuffix.PublicSuffix(d)
		_, isTree := neverBlock.trees[d]
		switch {
		case suffix == d && !isTree:
			// Domain refuses a public suffix already: a "name" entry for one
			// is dead weight, and hides that the PSL covers it.
			t.Errorf("%q is a public suffix: a name entry for it is redundant", d)
		case suffix == d && p.Reason != ReasonCDN:
			// A tree over a public suffix protects every tenant under it.
			// Only enterprise CDN edge namespaces may be protected whole.
			t.Errorf("%q is a public suffix: only a %s entry may protect its whole tree", d, ReasonCDN)
		}
		// No entry may be redundant under another tree entry.
		for s := d; ; {
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
			if _, under := neverBlock.trees[s]; under {
				t.Errorf("%q is already covered by the tree entry %q", d, s)
			}
		}
		// A name entry protects one name, so that name must be one Domain
		// accepts. A tree entry may itself be refused (a CDN suffix,
		// googleusercontent.com): what it protects is the names under it.
		if _, err := Domain(d); err != nil && !isTree {
			t.Errorf("name entry %q is refused by Domain (%v): it can never be an indicator", d, err)
		}
	}
	for _, e := range neverBlock.addrs {
		if e.Reason != ReasonPublicResolver {
			t.Errorf("address entry %s has reason %s", e.prefix, e.Reason)
		}
		v := e.prefix.Addr().String()
		if e.prefix.Bits() != e.prefix.Addr().BitLen() {
			v = e.prefix.String()
		}
		if _, err := IP(v); err != nil {
			t.Errorf("address entry %s is not a global unicast indicator shape: %v", v, err)
		}
	}
}

// TestParseNeverBlockRefusesMalformedLines: the parser that guards the
// embedded file refuses what a careless edit would introduce.
func TestParseNeverBlockRefusesMalformedLines(t *testing.T) {
	for _, src := range []string{
		"popular tree",
		"popular tree google.com extra",
		"famous tree google.com",
		"popular subtree google.com",
		"popular tree Google.com",
		"popular tree google.com.",
		"popular tree com",
		"popular tree *.google.com",
		"popular tree google.com\npopular name google.com",
		"public_resolver addr 8.8.8",
		"public_resolver addr 8.8.8.1/24",
		"public_resolver addr ::ffff:8.8.8.8",
		"public_resolver addr 2001:4860:4860:0::8888",
	} {
		if _, err := parseNeverBlock(src); err == nil {
			t.Errorf("parseNeverBlock(%q) accepted it", src)
		}
	}
	s, err := parseNeverBlock("# comment\n\n  popular tree google.com  \npublic_resolver addr 8.8.8.0/24\n")
	if err != nil || s.entries != 2 {
		t.Fatalf("a well-formed list: %v, %+v", err, s)
	}
}

// TestNeverBlockDoesNotChangeValidation: the list is a separate check. Value
// still accepts the shape of a protected domain, so the detection-engine's
// matcher and threat-intel-sync keep keying it identically (API
// compatibility for existing callers).
func TestNeverBlockDoesNotChangeValidation(t *testing.T) {
	for _, c := range []struct{ typ, in string }{
		{TypeDomain, "docs.google.com"}, {TypeDomain, "raw.githubusercontent.com"}, {TypeIP, "8.8.8.8"},
	} {
		if _, err := Value(c.typ, c.in); err != nil {
			t.Errorf("Value(%s, %q) = %v: validation must not depend on the never-block list", c.typ, c.in, err)
		}
	}
}
