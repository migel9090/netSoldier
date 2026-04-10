package iocmatch

import (
	"bufio"
	"fmt"
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
	cidrs   []cidrEntry
	hashes  map[string]IoC
}

func New() *Matcher {
	return &Matcher{
		domains: make(map[string]IoC),
		ips:     make(map[string]IoC),
		hashes:  make(map[string]IoC),
	}
}

// Add merges new IoCs into the matcher. Existing entries with the same
// key are replaced if the new one has higher confidence.
func (m *Matcher) Add(iocs []IoC) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, ioc := range iocs {
		ioc.Severity = DeriveSeverity(ioc)
		ioc.MitreID, ioc.MitreName = DeriveMitre(ioc)

		switch ioc.Type {
		case "domain":
			key := strings.ToLower(ioc.Value)
			if old, ok := m.domains[key]; !ok || ioc.Confidence >= old.Confidence {
				m.domains[key] = ioc
			}
		case "ip":
			if strings.Contains(ioc.Value, "/") {
				_, ipnet, err := net.ParseCIDR(ioc.Value)
				if err == nil {
					m.cidrs = append(m.cidrs, cidrEntry{net: ipnet, ioc: ioc})
				}
			} else {
				host := ioc.Value
				if h, _, err := net.SplitHostPort(ioc.Value); err == nil {
					host = h
				}
				if old, ok := m.ips[host]; !ok || ioc.Confidence >= old.Confidence {
					m.ips[host] = ioc
				}
			}
		case "ja3", "ja4", "md5", "sha256":
			key := strings.ToLower(ioc.Value)
			if old, ok := m.hashes[key]; !ok || ioc.Confidence >= old.Confidence {
				m.hashes[key] = ioc
			}
		}
	}
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
	m.mu.RLock()
	defer m.mu.RUnlock()

	if ioc, ok := m.ips[ip]; ok {
		return ioc, true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return IoC{}, false
	}
	for _, entry := range m.cidrs {
		if entry.net.Contains(parsed) {
			return entry.ioc, true
		}
	}
	return IoC{}, false
}

// MatchHash checks a hash (JA3, JA4, MD5, SHA256) against the IoC list.
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
