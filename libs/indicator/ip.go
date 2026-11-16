package indicator

import (
	"fmt"
	"net/netip"
	"strings"
)

// Minimum prefix lengths for CIDR indicators. Only an exact /0 used to be
// refused, so 0.0.0.0/1 plus 128.0.0.0/1 matched every address. A /12 is
// about a million IPv4 addresses, the size of a large ISP; a /32 is the
// smallest regular IPv6 allocation to an ISP. Anything broader is not an
// indicator but a statement about a region of the internet.
const (
	MinIPv4PrefixLen = 12
	MinIPv6PrefixLen = 32
)

// nonGlobalV4 are the IPv4 ranges whose addresses are, or can be, inside the
// household or its ISP's access network: blocking one isolates the gateway,
// a LAN device, the ISP's CGNAT gateway, or the multicast and broadcast
// traffic that discovery protocols depend on. The documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are deliberately absent:
// nothing is ever routed there, so an indicator in them cannot hurt anyone,
// and the repository's fixtures use them as stand-ins for public addresses.
var nonGlobalV4 = mustPrefixes(
	"0.0.0.0/8",      // "this network"
	"10.0.0.0/8",     // private
	"100.64.0.0/10",  // shared address space (CGNAT)
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local
	"172.16.0.0/12",  // private
	"192.0.0.0/24",   // IETF protocol assignments
	"192.88.99.0/24", // deprecated 6to4 relay anycast
	"192.168.0.0/16", // private
	"198.18.0.0/15",  // benchmarking
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved, including 255.255.255.255
)

// globalV6 is the IPv6 global unicast space (RFC 4291). Everything outside
// it — unspecified, loopback, IPv4-mapped, NAT64, unique-local, link-local,
// site-local, multicast — is refused by one rule.
var globalV6 = netip.MustParsePrefix("2000::/3")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// IP validates an IP indicator — a single address, optionally with a port
// ("203.0.113.7:443", "[2001:db8::1]:443"), or a CIDR prefix — and returns
// its canonical form: the address without port, or the masked prefix.
// IPv4-mapped IPv6 spellings are converted to IPv4.
func IP(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if strings.Contains(v, "/") {
		p, err := ParsePrefix(v)
		if err != nil {
			return "", err
		}
		return p.String(), nil
	}
	a, err := ParseAddr(v)
	if err != nil {
		return "", err
	}
	return a.String(), nil
}

// ParseAddr parses and validates a single-address indicator. Only global
// unicast addresses are accepted: an indicator naming the gateway, a LAN
// device, loopback, multicast or broadcast would turn a feed row into a
// local outage. Leading zeros ("203.000.113.007") are refused rather than
// guessed at, since some parsers read them as octal.
func ParseAddr(raw string) (netip.Addr, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return netip.Addr{}, fmt.Errorf("empty IP")
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		ap, perr := netip.ParseAddrPort(v)
		if perr != nil {
			return netip.Addr{}, fmt.Errorf("invalid IP %q", raw)
		}
		a = ap.Addr()
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("refusing scoped address %q", raw)
	}
	a = a.Unmap()
	if !isGlobalUnicast(a) {
		return netip.Addr{}, fmt.Errorf("refusing non-global address %q (private, loopback, "+
			"link-local, multicast, broadcast or reserved)", raw)
	}
	return a, nil
}

// ParsePrefix parses and validates a CIDR indicator. The prefix is masked to
// its network address, IPv4-mapped prefixes are converted to IPv4, and the
// result must be at least MinIPv4PrefixLen / MinIPv6PrefixLen long and lie
// entirely in global unicast space.
func ParsePrefix(raw string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %v", raw, err)
	}
	if p.Addr().Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("refusing scoped prefix %q", raw)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("refusing IPv4-mapped prefix %q shorter than /96", raw)
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	p = p.Masked()

	if p.Addr().Is4() {
		if p.Bits() < MinIPv4PrefixLen {
			return netip.Prefix{}, fmt.Errorf("refusing CIDR %q: broader than /%d", raw, MinIPv4PrefixLen)
		}
		for _, n := range nonGlobalV4 {
			if n.Overlaps(p) {
				return netip.Prefix{}, fmt.Errorf("refusing CIDR %q: overlaps non-global range %s", raw, n)
			}
		}
		return p, nil
	}
	if p.Bits() < MinIPv6PrefixLen {
		return netip.Prefix{}, fmt.Errorf("refusing CIDR %q: broader than /%d", raw, MinIPv6PrefixLen)
	}
	if !globalV6.Contains(p.Addr()) {
		return netip.Prefix{}, fmt.Errorf("refusing CIDR %q: outside IPv6 global unicast space", raw)
	}
	return p, nil
}

// QueryAddr parses an address seen in traffic for lookup. It is strict about
// syntax (no port, no leading zeros) but does not judge the address: a query
// for a private address simply matches nothing.
func QueryAddr(raw string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

func isGlobalUnicast(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	if a.Is4() {
		for _, n := range nonGlobalV4 {
			if n.Contains(a) {
				return false
			}
		}
		return true
	}
	return globalV6.Contains(a)
}
