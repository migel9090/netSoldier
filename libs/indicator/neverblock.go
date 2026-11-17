package indicator

import (
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// The never-block list: hosts that a feed must never turn into an automatic
// block, because blocking one breaks a household's everyday use of the
// internet (a search engine, an update host, a public resolver a device
// hard-codes) or every unrelated tenant of a shared host. The entries and
// where they come from are in neverblock.txt, embedded at build time.
//
// This is a separate check from Value on purpose. Value says whether a
// string has the shape of an indicator — "docs.google.com" does — and every
// caller needs that. NeverBlock says whether acting on it is allowed, which
// only the callers that block (threat-intel-sync's exports, a matcher whose
// hits become enforcement proposals, the killswitch) have to ask. Both
// sides of a match therefore keep agreeing on canonical spellings, while
// each blocking service refuses the same hosts.
//
//go:embed neverblock.txt
var neverBlockFile string

// NeverBlockSnapshot is the date of the ranking snapshot neverblock.txt was
// curated from. Bump it with the list (see the refresh procedure there).
const NeverBlockSnapshot = "2026-11-17"

// Never-block reasons. They are label values of the per-reason counters the
// services export, so they must not change.
const (
	ReasonPopular        = "popular"         // a widely used site or service
	ReasonCDN            = "cdn"             // shared CDN edge infrastructure
	ReasonSharedHosting  = "shared_hosting"  // one operator's names serving many users' content
	ReasonDynamicDNS     = "dynamic_dns"     // the apex of a dynamic-DNS zone
	ReasonPublicResolver = "public_resolver" // a public DNS resolver
)

// NeverBlockReasons returns every reason, in a fixed order, for callers
// that pre-create one counter series per reason.
func NeverBlockReasons() []string {
	return []string{ReasonPopular, ReasonCDN, ReasonSharedHosting, ReasonDynamicDNS, ReasonPublicResolver}
}

// Protection says why a value must never become an automatic block.
type Protection struct {
	Reason string // one of the Reason constants
	Entry  string // the list entry that matched: a domain, an address or a prefix
}

// ErrNeverBlock is wrapped by every *NeverBlockError (errors.Is).
var ErrNeverBlock = errors.New("names a host that must never be blocked automatically")

// NeverBlockError reports an indicator that the never-block list protects.
// It is not a validation failure: the value is well formed, it is only not
// to be acted on.
type NeverBlockError struct {
	Type  string
	Value string
	Protection
}

func (e *NeverBlockError) Error() string {
	return fmt.Sprintf("refusing %s indicator %q: it %s (never-block list: %s %q)",
		e.Type, e.Value, ErrNeverBlock, e.Reason, e.Entry)
}

func (e *NeverBlockError) Unwrap() error { return ErrNeverBlock }

// NeverBlock reports whether an indicator, in the canonical form Value
// returns, names a host on the never-block list, and which entry protects
// it. Only domain and IP indicators can be protected: a URL names one
// resource on its host and a hash names a file, so neither blocks a host.
func NeverBlock(t, canonical string) (Protection, bool) {
	switch t {
	case TypeDomain:
		return NeverBlockDomain(canonical)
	case TypeIP:
		if strings.Contains(canonical, "/") {
			p, err := netip.ParsePrefix(canonical)
			if err != nil {
				return Protection{}, false
			}
			return NeverBlockPrefix(p)
		}
		a, err := netip.ParseAddr(canonical)
		if err != nil {
			return Protection{}, false
		}
		return NeverBlockAddr(a)
	}
	return Protection{}, false
}

// CheckBlockable returns a *NeverBlockError when NeverBlock protects the
// indicator, and nil otherwise. It is the call for a service about to turn
// an indicator, or a match on one, into a block.
func CheckBlockable(t, canonical string) error {
	if p, ok := NeverBlock(t, canonical); ok {
		return &NeverBlockError{Type: t, Value: canonical, Protection: p}
	}
	return nil
}

// NeverBlockDomain reports whether a domain name is protected: it equals a
// "name" entry, or equals or lies under a "tree" entry. The name is expected
// in canonical form (Domain or QueryName); letter case and a trailing dot
// are tolerated.
func NeverBlockDomain(name string) (Protection, bool) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if d == "" {
		return Protection{}, false
	}
	if p, ok := neverBlock.names[d]; ok {
		return p, true
	}
	for s := d; ; {
		if p, ok := neverBlock.trees[s]; ok {
			return p, true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return Protection{}, false
		}
		s = s[i+1:]
	}
}

// NeverBlockAddr reports whether an address is, or lies inside, a protected
// address entry. IPv4-mapped IPv6 addresses are compared as IPv4.
func NeverBlockAddr(a netip.Addr) (Protection, bool) {
	if !a.IsValid() {
		return Protection{}, false
	}
	a = a.WithZone("").Unmap()
	for _, e := range neverBlock.addrs {
		if e.prefix.Contains(a) {
			return e.Protection, true
		}
	}
	return Protection{}, false
}

// NeverBlockPrefix reports whether a CIDR indicator overlaps a protected
// address entry: blocking 8.8.8.0/24 blocks 8.8.8.8 just the same.
func NeverBlockPrefix(p netip.Prefix) (Protection, bool) {
	if !p.IsValid() {
		return Protection{}, false
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	for _, e := range neverBlock.addrs {
		if e.prefix.Overlaps(p) {
			return e.Protection, true
		}
	}
	return Protection{}, false
}

// NeverBlockListInfo describes the embedded list, for start-up logs and
// export headers.
type NeverBlockListInfo struct {
	Snapshot string
	Entries  int
	ByReason map[string]int
}

// NeverBlockList returns a description of the embedded list.
func NeverBlockList() NeverBlockListInfo {
	by := make(map[string]int, len(neverBlock.byReason))
	for k, v := range neverBlock.byReason {
		by[k] = v
	}
	return NeverBlockListInfo{Snapshot: NeverBlockSnapshot, Entries: neverBlock.entries, ByReason: by}
}

type addrEntry struct {
	prefix netip.Prefix
	Protection
}

type neverBlockSet struct {
	names    map[string]Protection // scope "name": the name itself
	trees    map[string]Protection // scope "tree": the name and everything under it
	addrs    []addrEntry           // scope "addr"
	entries  int
	byReason map[string]int
}

// neverBlock is parsed once, at package initialisation. The file is part of
// the source tree and covered by the package's tests, so a malformed line
// is a build defect and panics like a bad regexp.MustCompile would.
var neverBlock = mustParseNeverBlock(neverBlockFile)

func mustParseNeverBlock(src string) *neverBlockSet {
	s, err := parseNeverBlock(src)
	if err != nil {
		panic("libs/indicator: neverblock.txt: " + err.Error())
	}
	return s
}

func parseNeverBlock(src string) (*neverBlockSet, error) {
	s := &neverBlockSet{
		names:    map[string]Protection{},
		trees:    map[string]Protection{},
		byReason: map[string]int{},
	}
	reasons := map[string]bool{}
	for _, r := range NeverBlockReasons() {
		reasons[r] = true
	}
	seen := map[string]int{}
	for n, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("line %d: want \"<reason> <scope> <value>\", got %q", n+1, line)
		}
		reason, scope, value := f[0], f[1], f[2]
		if !reasons[reason] {
			return nil, fmt.Errorf("line %d: unknown reason %q", n+1, reason)
		}
		if prev, dup := seen[value]; dup {
			return nil, fmt.Errorf("line %d: %q is already listed on line %d", n+1, value, prev)
		}
		seen[value] = n + 1
		p := Protection{Reason: reason, Entry: value}
		switch scope {
		case "name", "tree":
			d, err := hostName(value)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n+1, err)
			}
			if d != value {
				return nil, fmt.Errorf("line %d: %q is not in canonical form (%q)", n+1, value, d)
			}
			if scope == "name" {
				s.names[d] = p
			} else {
				s.trees[d] = p
			}
		case "addr":
			pfx, err := parseAddrEntry(value)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", n+1, err)
			}
			s.addrs = append(s.addrs, addrEntry{prefix: pfx, Protection: p})
		default:
			return nil, fmt.Errorf("line %d: unknown scope %q (name, tree or addr)", n+1, scope)
		}
		s.entries++
		s.byReason[reason]++
	}
	return s, nil
}

// parseAddrEntry accepts an address or a prefix in canonical spelling. It
// does not apply the indicator rules: an entry protects, it is never
// matched against traffic.
func parseAddrEntry(v string) (netip.Prefix, error) {
	if strings.Contains(v, "/") {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Masked() != p {
			return netip.Prefix{}, fmt.Errorf("prefix %q is not masked", v)
		}
		return p, nil
	}
	a, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Prefix{}, err
	}
	if a.Zone() != "" || a.Is4In6() || a.String() != v {
		return netip.Prefix{}, fmt.Errorf("address %q is not in canonical form", v)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}
