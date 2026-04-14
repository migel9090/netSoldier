package policy

import (
	"strings"
	"sync"
)

// Allowlist holds critical devices that must NEVER be blocked (fail-open).
// A blocked critical device (router, DNS server, sensor) could take the
// entire network offline — the allowlist prevents that by design.
type Allowlist struct {
	mu   sync.RWMutex
	macs map[string]struct{}
	ips  map[string]struct{}
}

func (a *Allowlist) AddMAC(mac string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.macs == nil {
		a.macs = make(map[string]struct{})
	}
	a.macs[strings.ToLower(mac)] = struct{}{}
}

func (a *Allowlist) AddIP(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ips == nil {
		a.ips = make(map[string]struct{})
	}
	a.ips[ip] = struct{}{}
}

func (a *Allowlist) RemoveMAC(mac string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.macs, strings.ToLower(mac))
}

func (a *Allowlist) RemoveIP(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.ips, ip)
}

// Contains returns true if the device identified by MAC or IP is allowlisted.
func (a *Allowlist) Contains(mac, ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if mac != "" {
		if _, ok := a.macs[strings.ToLower(mac)]; ok {
			return true
		}
	}
	if ip != "" {
		if _, ok := a.ips[ip]; ok {
			return true
		}
	}
	return false
}

// MACs returns all allowlisted MAC addresses.
func (a *Allowlist) MACs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.macs))
	for m := range a.macs {
		out = append(out, m)
	}
	return out
}

// IPs returns all allowlisted IP addresses.
func (a *Allowlist) IPs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.ips))
	for ip := range a.ips {
		out = append(out, ip)
	}
	return out
}
