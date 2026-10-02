package iocmatch

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
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

type cidrEntry struct {
	net *net.IPNet
	ioc IoC
}

// Matcher checks domains, IPs, and hashes against multiple IoC sources.
type Matcher struct {
	mu      sync.RWMutex
	domains map[string]IoC
	ips     map[string]IoC
	// cidrs is keyed by the canonical prefix string. It used to be a slice
	// that Add() appended to unconditionally, while SyncLoop re-added the
	// full feed every 5 minutes — so Spamhaus DROP's ~1000 prefixes grew by
	// ~288k entries a day, MatchIP scanned all of them linearly for every
	// DNS answer, and the pod OOMed within days. Map semantics make a
	// re-sync idempotent, like the other indicator types already were.
	cidrs  map[string]cidrEntry
	hashes map[string]IoC
}

func New() *Matcher {
	return &Matcher{
		domains: make(map[string]IoC),
		ips:     make(map[string]IoC),
		cidrs:   make(map[string]cidrEntry),
		hashes:  make(map[string]IoC),
	}
}

// Add merges new IoCs into the matcher. Existing entries with the same
// key are replaced if the new one has higher confidence.
//
// It returns how many indicators were accepted and how many were rejected as
// unsafe to match on. Feed data is third-party input, so this is a trust
// boundary: an indicator that is too broad (a bare TLD, a public suffix) is
// dropped with a log line rather than loaded, because MatchDomain walks parent
// domains and a single bad row would otherwise match the whole internet.
func (m *Matcher) Add(iocs []IoC) (added, rejected int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ioc := range iocs {
		ioc.Severity = DeriveSeverity(ioc)
		ioc.MitreID, ioc.MitreName = DeriveMitre(ioc)

		switch ioc.Type {
		case "domain":
			domain, err := ValidateDomainIndicator(ioc.Value)
			if err != nil {
				rejected++
				slog.Warn("rejected unsafe domain indicator",
					"value", ioc.Value, "source", ioc.Source, "error", err)
				continue
			}
			ioc.Value = domain
			if old, ok := m.domains[domain]; !ok || ioc.Confidence >= old.Confidence {
				m.domains[domain] = ioc
			}
			added++
		case "ip":
			if strings.Contains(ioc.Value, "/") {
				_, ipnet, err := net.ParseCIDR(strings.TrimSpace(ioc.Value))
				if err != nil {
					rejected++
					slog.Warn("rejected malformed CIDR indicator",
						"value", ioc.Value, "source", ioc.Source, "error", err)
					continue
				}
				if ones, bits := ipnet.Mask.Size(); ones == 0 && bits > 0 {
					// 0.0.0.0/0 or ::/0 would match every address.
					rejected++
					slog.Warn("rejected catch-all CIDR indicator",
						"value", ioc.Value, "source", ioc.Source)
					continue
				}
				key := ipnet.String()
				if old, ok := m.cidrs[key]; !ok || ioc.Confidence >= old.ioc.Confidence {
					m.cidrs[key] = cidrEntry{net: ipnet, ioc: ioc}
				}
				added++
				continue
			}

			host := strings.TrimSpace(ioc.Value)
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			// Normalize through net.IP so 2001:DB8::1 and 2001:db8::1 are
			// the same key; raw string comparison missed those detections.
			parsed := net.ParseIP(host)
			if parsed == nil {
				rejected++
				slog.Warn("rejected malformed IP indicator",
					"value", ioc.Value, "source", ioc.Source)
				continue
			}
			key := parsed.String()
			if old, ok := m.ips[key]; !ok || ioc.Confidence >= old.Confidence {
				ioc.Value = key
				m.ips[key] = ioc
			}
			added++
		case "ja3", "tlsfp", "md5", "sha256":
			key := strings.ToLower(strings.TrimSpace(ioc.Value))
			if key == "" {
				rejected++
				continue
			}
			if old, ok := m.hashes[key]; !ok || ioc.Confidence >= old.Confidence {
				m.hashes[key] = ioc
			}
			added++
		default:
			rejected++
		}
	}
	return added, rejected
}

// MatchDomain checks a domain and all parent domains against the IoC list.
func (m *Matcher) MatchDomain(domain string) (IoC, bool) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	m.mu.RLock()
	defer m.mu.RUnlock()

	parts := strings.Split(domain, ".")
	for i := range parts {
		candidate := strings.Join(parts[i:], ".")
		if ioc, ok := m.domains[candidate]; ok {
			return ioc, true
		}
	}
	return IoC{}, false
}

// MatchIP checks an IP against exact matches and CIDR ranges.
func (m *Matcher) MatchIP(ip string) (IoC, bool) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return IoC{}, false
	}
	key := parsed.String()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if ioc, ok := m.ips[key]; ok {
		return ioc, true
	}
	for _, entry := range m.cidrs {
		if entry.net.Contains(parsed) {
			return entry.ioc, true
		}
	}
	return IoC{}, false
}

// MatchHash checks a fingerprint/hash (JA3, tls_client_fp, MD5, SHA256)
// against the IoC list.
func (m *Matcher) MatchHash(hash string) (IoC, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ioc, ok := m.hashes[strings.ToLower(hash)]
	return ioc, ok
}

// Size returns the total number of IoCs across all types.
func (m *Matcher) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.domains) + len(m.ips) + len(m.cidrs) + len(m.hashes)
}

// CIDRCount reports how many distinct prefixes are loaded. MatchIP scans them
// linearly, so this is the number to watch for lookup cost.
func (m *Matcher) CIDRCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.cidrs)
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
