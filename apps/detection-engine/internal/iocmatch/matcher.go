package iocmatch

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/migel9090/netSoldier/libs/indicator"
)

// IoC is an indicator of compromise with enrichment metadata.
type IoC struct {
	Value      string   `json:"value"`
	Type       string   `json:"type"`
	Source     string   `json:"source"`
	Threat     string   `json:"threat"`
	Confidence int      `json:"confidence"`
	Tags       []string `json:"tags"`
	Severity   string   `json:"severity"`
	MitreID    string   `json:"mitre_id"`
	MitreName  string   `json:"mitre_name"`
}

// LoadStats reports what loading a batch of indicators did.
type LoadStats struct {
	Accepted int // loaded and matchable
	// Invalid indicators failed validation (or carry a type no part of
	// netSoldier defines). This is what the feed-poisoning alert counts.
	Invalid int
	// Unsupported indicators are valid but of a type the matcher has no
	// lookup for (url, cert-sha1, cert-sha256). They used to be counted as
	// invalid, which would have kept the feed-poisoning alert firing on
	// every sync of a perfectly healthy feed.
	Unsupported int
	// UnsupportedByType breaks Unsupported down by type name.
	UnsupportedByType map[string]int
}

// indicatorSet is one collection of indicators, keyed in canonical form.
type indicatorSet struct {
	domains map[string]IoC
	ips     map[netip.Addr]IoC
	cidrs   map[netip.Prefix]IoC
	// v4Lens / v6Lens are the distinct prefix lengths present, longest
	// first: MatchIP masks the address once per length instead of scanning
	// every prefix, and the most specific range wins.
	v4Lens, v6Lens []int
	hashes         map[string]IoC
}

func newIndicatorSet() *indicatorSet {
	return &indicatorSet{
		domains: make(map[string]IoC),
		ips:     make(map[netip.Addr]IoC),
		cidrs:   make(map[netip.Prefix]IoC),
		hashes:  make(map[string]IoC),
	}
}

func (s *indicatorSet) size() int {
	return len(s.domains) + len(s.ips) + len(s.cidrs) + len(s.hashes)
}

// Matcher checks domains, IPs, and hashes against multiple IoC sources.
//
// It holds two independent sets. The static set (Add) is the local threat
// list loaded at start-up; it only ever grows. The feed set (Replace) is
// rebuilt from scratch on every successful sync and swapped in atomically,
// so an indicator a feed withdraws stops matching on the next sync and a
// lowered confidence takes effect. The feed set used to be merged into one
// add-only map: a withdrawn false positive kept matching until the pod
// restarted, and confidence could only go up.
type Matcher struct {
	mu     sync.RWMutex // guards static
	static *indicatorSet
	feed   atomic.Pointer[indicatorSet]
}

func New() *Matcher {
	m := &Matcher{static: newIndicatorSet()}
	m.feed.Store(newIndicatorSet())
	return m
}

// maxInvalidLogs bounds per-batch logging of refused indicators.
const maxInvalidLogs = 10

// Add merges IoCs into the static set. Existing entries with the same key
// are replaced if the new one has equal or higher confidence.
//
// It returns how many indicators were accepted and how many were not loaded
// (invalid or unsupported). Feed data is third-party input, so this is a
// trust boundary: values are validated with libs/indicator — the same rules
// threat-intel-sync applies at ingest — because MatchDomain walks parent
// domains and a single over-broad row would otherwise match the whole
// internet.
func (m *Matcher) Add(iocs []IoC) (added, rejected int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.static.load(iocs)
	return st.Accepted, st.Invalid + st.Unsupported
}

// Replace builds a fresh feed set from iocs and swaps it in atomically,
// leaving the static set untouched. Lookups running concurrently see either
// the old set or the new one, never a mix.
func (m *Matcher) Replace(iocs []IoC) LoadStats {
	set, st := buildSet(iocs)
	m.feed.Store(set)
	return st
}

func buildSet(iocs []IoC) (*indicatorSet, LoadStats) {
	set := newIndicatorSet()
	return set, set.load(iocs)
}

func (s *indicatorSet) load(iocs []IoC) LoadStats {
	var st LoadStats
	for _, ioc := range iocs {
		err := s.add(ioc)
		switch {
		case err == nil:
			st.Accepted++
		case errors.Is(err, errUnsupported):
			st.Unsupported++
			if st.UnsupportedByType == nil {
				st.UnsupportedByType = make(map[string]int)
			}
			st.UnsupportedByType[ioc.Type]++
		default:
			st.Invalid++
			if st.Invalid <= maxInvalidLogs {
				slog.Warn("rejected unsafe indicator", "type", indicator.Text(ioc.Type, 32),
					"value", indicator.Text(ioc.Value, 128), "source", indicator.Text(ioc.Source, 64),
					"error", err)
			}
		}
	}
	if st.Invalid > maxInvalidLogs {
		slog.Warn("further unsafe indicators rejected", "not_logged", st.Invalid-maxInvalidLogs)
	}
	s.v4Lens, s.v6Lens = prefixLens(s.cidrs)
	return st
}

var errUnsupported = errors.New("indicator type not matched by the detection-engine")

// add validates one indicator and inserts it. The value is replaced by its
// canonical form so lookups and indicators meet on one key, and free-text
// fields are cleaned before they can reach an alert.
func (s *indicatorSet) add(ioc IoC) error {
	ioc.Source = indicator.Text(ioc.Source, 4*indicator.MaxSourceLen)
	ioc.Threat = indicator.Text(ioc.Threat, indicator.MaxTextLen)
	ioc.Tags = indicator.Tags(ioc.Tags)
	ioc.Severity = DeriveSeverity(ioc)
	ioc.MitreID, ioc.MitreName = DeriveMitre(ioc)
	if ioc.Confidence < 0 || ioc.Confidence > 100 {
		return fmt.Errorf("confidence %d out of range", ioc.Confidence)
	}

	switch ioc.Type {
	case indicator.TypeDomain:
		d, err := indicator.Domain(ioc.Value)
		if err != nil {
			return err
		}
		ioc.Value = d
		if old, ok := s.domains[d]; !ok || ioc.Confidence >= old.Confidence {
			s.domains[d] = ioc
		}
	case indicator.TypeIP:
		if strings.Contains(ioc.Value, "/") {
			p, err := indicator.ParsePrefix(ioc.Value)
			if err != nil {
				return err
			}
			ioc.Value = p.String()
			if old, ok := s.cidrs[p]; !ok || ioc.Confidence >= old.Confidence {
				s.cidrs[p] = ioc
			}
			return nil
		}
		a, err := indicator.ParseAddr(ioc.Value)
		if err != nil {
			return err
		}
		ioc.Value = a.String()
		if old, ok := s.ips[a]; !ok || ioc.Confidence >= old.Confidence {
			s.ips[a] = ioc
		}
	case indicator.TypeJA3, indicator.TypeTLSFP, indicator.TypeMD5, indicator.TypeSHA256:
		h, err := indicator.Hash(ioc.Type, ioc.Value)
		if err != nil {
			return err
		}
		ioc.Value = h
		if old, ok := s.hashes[h]; !ok || ioc.Confidence >= old.Confidence {
			s.hashes[h] = ioc
		}
	default:
		if indicator.KnownType(ioc.Type) {
			return errUnsupported
		}
		return fmt.Errorf("%w %q", indicator.ErrUnknownType, ioc.Type)
	}
	return nil
}

func prefixLens(cidrs map[netip.Prefix]IoC) (v4, v6 []int) {
	seen4, seen6 := map[int]bool{}, map[int]bool{}
	for p := range cidrs {
		if p.Addr().Is4() {
			if !seen4[p.Bits()] {
				seen4[p.Bits()] = true
				v4 = append(v4, p.Bits())
			}
		} else if !seen6[p.Bits()] {
			seen6[p.Bits()] = true
			v6 = append(v6, p.Bits())
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(v4)))
	sort.Sort(sort.Reverse(sort.IntSlice(v6)))
	return v4, v6
}

// pick returns the better of two candidate matches for the same key: the
// higher confidence, the feed's on a tie (it carries the richer metadata).
func pick(feed IoC, inFeed bool, static IoC, inStatic bool) (IoC, bool) {
	switch {
	case inFeed && inStatic:
		if static.Confidence > feed.Confidence {
			return static, true
		}
		return feed, true
	case inFeed:
		return feed, true
	case inStatic:
		return static, true
	}
	return IoC{}, false
}

// MatchDomain checks a domain and all parent domains against the IoC list.
// The queried name is normalised exactly as indicators are (lower case,
// A-label form, no trailing dot), so "bücher.example" and
// "xn--bcher-kva.example" are the same name on both sides.
func (m *Matcher) MatchDomain(domain string) (IoC, bool) {
	q, ok := indicator.QueryName(domain)
	if !ok {
		return IoC{}, false
	}
	feed := m.feed.Load()
	m.mu.RLock()
	defer m.mu.RUnlock()

	for candidate := q; ; {
		f, inFeed := feed.domains[candidate]
		s, inStatic := m.static.domains[candidate]
		if ioc, ok := pick(f, inFeed, s, inStatic); ok {
			return ioc, true
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 {
			return IoC{}, false
		}
		candidate = candidate[dot+1:]
	}
}

// MatchIP checks an IP against exact matches and CIDR ranges, the most
// specific range first. IPv4-mapped IPv6 spellings match their IPv4 form.
func (m *Matcher) MatchIP(ip string) (IoC, bool) {
	a, ok := indicator.QueryAddr(ip)
	if !ok {
		return IoC{}, false
	}
	feed := m.feed.Load()
	m.mu.RLock()
	defer m.mu.RUnlock()

	f, inFeed := feed.ips[a]
	s, inStatic := m.static.ips[a]
	if ioc, ok := pick(f, inFeed, s, inStatic); ok {
		return ioc, true
	}
	if ioc, ok := feed.matchCIDR(a); ok {
		if s, inStatic := m.static.matchCIDR(a); inStatic && s.Confidence > ioc.Confidence {
			return s, true
		}
		return ioc, true
	}
	return m.static.matchCIDR(a)
}

func (s *indicatorSet) matchCIDR(a netip.Addr) (IoC, bool) {
	lens := s.v6Lens
	if a.Is4() {
		lens = s.v4Lens
	}
	for _, bits := range lens {
		p, err := a.Prefix(bits)
		if err != nil {
			continue
		}
		if ioc, ok := s.cidrs[p]; ok {
			return ioc, true
		}
	}
	return IoC{}, false
}

// MatchHash checks a fingerprint/hash (JA3, tls_client_fp, MD5, SHA256)
// against the IoC list.
func (m *Matcher) MatchHash(hash string) (IoC, bool) {
	key := strings.ToLower(strings.TrimSpace(hash))
	feed := m.feed.Load()
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, inFeed := feed.hashes[key]
	s, inStatic := m.static.hashes[key]
	return pick(f, inFeed, s, inStatic)
}

// Size returns the total number of IoCs across all types, static and feed.
func (m *Matcher) Size() int {
	feed := m.feed.Load()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.static.size() + feed.size()
}

// CIDRCount reports how many distinct prefixes are loaded, static and feed.
func (m *Matcher) CIDRCount() int {
	feed := m.feed.Load()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.static.cidrs) + len(feed.cidrs)
}

// LoadDomainsFromFile reads a domain-per-line threat list and returns IoCs.
func LoadDomainsFromFile(path string) ([]IoC, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	var iocs []IoC
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		iocs = append(iocs, IoC{
			Value:      strings.ToLower(line),
			Type:       "domain",
			Source:     "local",
			Confidence: 80,
			Tags:       []string{"static"},
		})
	}
	return iocs, scanner.Err()
}
