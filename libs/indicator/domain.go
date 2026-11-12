package indicator

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// MaxDomainLen is the DNS limit for a name in presentation form, without
// the trailing dot.
const MaxDomainLen = 253

// maxRawDomainLen bounds the work done on a candidate before IDNA mapping.
// A U-label name can legitimately be longer than its A-label form, but not
// by this much.
const maxRawDomainLen = 1024

// idnaProfile converts a domain indicator to its ASCII (A-label) form.
// MapForLookup applies UTS #46 mapping (case folding, width folding, the
// ideographic full stop) and the STD3 rules, which restrict every label to
// letters, digits and hyphens. Hyphen placement is checked below instead of
// by CheckHyphens: that option also refuses "--" in positions 3–4, which
// real names such as CDN hosts use.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.CheckJoiners(true),
	idna.CheckHyphens(false),
	idna.VerifyDNSLength(true),
	idna.StrictDomainName(true),
)

// localTLDs are names that resolve inside the household, never on the
// internet. A feed has no business listing them, and blocking one breaks
// the LAN itself (the router's own name, reverse lookups, mDNS).
var localTLDs = map[string]struct{}{
	"arpa":        {}, // in-addr.arpa, ip6.arpa, home.arpa (RFC 8375)
	"local":       {}, // mDNS (RFC 6762)
	"localhost":   {}, // RFC 6761
	"internal":    {}, // reserved by ICANN for private use (2024)
	"lan":         {},
	"home":        {},
	"localdomain": {},
}

// sharedHostParents are registered domains whose subdomains belong to many
// unrelated tenants but that the Public Suffix List does not list as
// suffixes themselves (it lists their children, e.g. s3.amazonaws.com, or
// nothing). The first three were on the hand-written list this package
// replaces, the rest were found by the 2026-11 audit; refusing them keeps
// that protection. This is not the popular-host allow-list — a name like
// github.com is a single tenant and stays acceptable here.
var sharedHostParents = map[string]struct{}{
	"amazonaws.com":         {},
	"glitch.me":             {},
	"serveo.net":            {},
	"windows.net":           {},
	"core.windows.net":      {},
	"googleusercontent.com": {},
}

// Domain validates a domain indicator and returns it in canonical form:
// lower case, A-label (punycode) spelling, no trailing dot.
//
// Accepted: two or more labels of letters, digits and hyphens (1–63 bytes,
// no leading or trailing hyphen, 253 bytes in total), after IDNA mapping of
// any Unicode spelling; a leading "*." is dropped, because a domain
// indicator already covers its subdomains. Refused: anything else, an
// all-numeric top-level label (that is an address, not a name), the
// household-local namespaces above, any name that is itself a public
// suffix — in the ICANN or the private section of the Public Suffix List —
// and the shared-hosting parents above, because the matcher walks parent
// domains and "co.uk" or "s3.amazonaws.com" as an indicator would match
// every name registered under it.
func Domain(raw string) (string, error) {
	if len(raw) > maxRawDomainLen {
		return "", fmt.Errorf("domain too long (%d bytes)", len(raw))
	}
	d := strings.TrimSpace(raw)
	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	if hasControlOrSpace(d) {
		return "", fmt.Errorf("domain contains whitespace or control characters: %q", raw)
	}
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	ascii, err := hostName(d)
	if err != nil {
		return "", err
	}
	if suffix, _ := publicsuffix.PublicSuffix(ascii); suffix == ascii {
		return "", fmt.Errorf("refusing public suffix %q as an indicator: it would match every "+
			"domain registered under it", ascii)
	}
	if _, shared := sharedHostParents[ascii]; shared {
		return "", fmt.Errorf("refusing shared-hosting parent %q as an indicator: it would match "+
			"every tenant under it", ascii)
	}
	return ascii, nil
}

// hostName converts an internet host name to lower-case A-label form and
// checks its shape: LDH labels, at least two of them, a non-numeric
// top-level label outside the household-local namespaces. It does not
// consult the Public Suffix List; a URL on a shared host is still specific.
func hostName(d string) (string, error) {
	if d == "" {
		return "", fmt.Errorf("empty domain")
	}
	ascii, err := idnaProfile.ToASCII(d)
	if err != nil {
		return "", fmt.Errorf("%q is not a valid host name: %v", d, err)
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > MaxDomainLen {
		return "", fmt.Errorf("domain too long (%d bytes)", len(ascii))
	}

	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("domain %q has a single label: it would match every name under it", ascii)
	}
	for _, l := range labels {
		if err := checkLDHLabel(l); err != nil {
			return "", fmt.Errorf("domain %q: %w", ascii, err)
		}
	}
	tld := labels[len(labels)-1]
	if allDigits(tld) {
		return "", fmt.Errorf("domain %q has a numeric top-level label: an address is not a name", ascii)
	}
	if _, local := localTLDs[tld]; local {
		return "", fmt.Errorf("domain %q is in the household-local namespace .%s", ascii, tld)
	}
	return ascii, nil
}

// QueryName normalises a queried name (a DNS question, a TLS SNI, an HTTP
// Host) to the form Domain produces, so a lookup and an indicator meet on
// the same key whichever spelling each side saw.
//
// It is deliberately more lenient than Domain: a query is evidence, not a
// claim, and names such as "_ldap._tcp.dc.example" are legitimate lookups
// whose parent may well be an indicator. Labels that cannot be converted are
// kept lower-cased; they cannot equal any indicator, but their parents can.
// ok is false only for a name with nothing to match.
func QueryName(raw string) (string, bool) {
	if len(raw) > maxRawDomainLen {
		return "", false
	}
	d := strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if d == "" || hasControlOrSpace(d) {
		return "", false
	}
	if ascii, err := idnaProfile.ToASCII(d); err == nil {
		return strings.ToLower(ascii), true
	}
	labels := strings.Split(d, ".")
	for i, l := range labels {
		if isASCII(l) {
			labels[i] = strings.ToLower(l)
			continue
		}
		if a, err := idna.Lookup.ToASCII(l); err == nil {
			labels[i] = strings.ToLower(a)
		} else {
			labels[i] = strings.ToLower(l)
		}
	}
	return strings.Join(labels, "."), true
}

func checkLDHLabel(l string) error {
	if l == "" {
		return fmt.Errorf("empty label")
	}
	if len(l) > 63 {
		return fmt.Errorf("label longer than 63 bytes")
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("label %q starts or ends with a hyphen", l)
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("label %q contains %q", l, c)
		}
	}
	return nil
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
