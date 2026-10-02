package policy

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

// Allowlist holds critical devices that must NEVER be blocked (fail-open).
// A blocked critical device (router, DNS server, sensor) could take the
// entire network offline — the allowlist prevents that by design.
//
// Entries are NORMALIZED on the way in and on every lookup. That matters
// more than it looks: before step 124 a MAC was only lowercased, so an
// operator who wrote the router as "AA-BB-CC-DD-EE-FF" (the format Windows
// and most router UIs show) never matched the "aa:bb:cc:dd:ee:ff" the
// detection pipeline produces, and the one device that must never be cut off
// was silently unprotected. Same class of bug for "2001:DB8::1" vs
// "2001:db8::1". Normalizing through net.ParseMAC / netip.ParseAddr makes
// every accepted spelling equivalent, and rejecting unparseable entries at
// load time turns a silent gap into a startup error.
type Allowlist struct {
	mu    sync.RWMutex
	macs  map[string]struct{}
	addrs map[netip.Addr]struct{}
	nets  []netip.Prefix
}

// NormalizeMAC parses any accepted MAC spelling (colon, hyphen, dotted or
// bare hex) and returns the canonical lowercase colon form.
func NormalizeMAC(mac string) (string, error) {
	s := strings.TrimSpace(mac)
	if s == "" {
		return "", fmt.Errorf("empty MAC")
	}
	hw, err := net.ParseMAC(s)
	if err != nil {
		// net.ParseMAC rejects bare hex ("aabbccddeeff"); accept it too
		// rather than leave a device unprotected over punctuation.
		bare := strings.Map(func(r rune) rune {
			if r == ':' || r == '-' || r == '.' {
				return -1
			}
			return r
		}, s)
		if len(bare) == 12 {
			var sb strings.Builder
			for i := 0; i < 12; i += 2 {
				if i > 0 {
					sb.WriteByte(':')
				}
				sb.WriteString(bare[i : i+2])
			}
			if hw2, err2 := net.ParseMAC(sb.String()); err2 == nil {
				return strings.ToLower(hw2.String()), nil
			}
		}
		return "", fmt.Errorf("invalid MAC %q: %w", mac, err)
	}
	return strings.ToLower(hw.String()), nil
}

// AddMAC adds a MAC address in any accepted spelling.
func (a *Allowlist) AddMAC(mac string) error {
	norm, err := NormalizeMAC(mac)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.macs == nil {
		a.macs = make(map[string]struct{})
	}
	a.macs[norm] = struct{}{}
	return nil
}

// AddIP adds a single address or a CIDR prefix. CIDR support lets an operator
// protect the whole infrastructure range (e.g. 192.168.1.0/29) instead of
// chasing individual DHCP leases.
func (a *Allowlist) AddIP(entry string) error {
	s := strings.TrimSpace(entry)
	if s == "" {
		return fmt.Errorf("empty IP entry")
	}

	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", entry, err)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.nets = append(a.nets, prefix.Masked())
		return nil
	}

	addr, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("invalid IP %q: %w", entry, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.addrs == nil {
		a.addrs = make(map[netip.Addr]struct{})
	}
	a.addrs[canonicalAddr(addr)] = struct{}{}
	return nil
}

// canonicalAddr collapses IPv4-in-IPv6 forms so ::ffff:192.168.1.1 and
// 192.168.1.1 are the same key, and strips any zone.
func canonicalAddr(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.WithZone("")
}

// RemoveMAC removes a MAC address in any accepted spelling.
func (a *Allowlist) RemoveMAC(mac string) {
	norm, err := NormalizeMAC(mac)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.macs, norm)
}

// RemoveIP removes a single address (not a CIDR).
func (a *Allowlist) RemoveIP(ip string) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.addrs, canonicalAddr(addr))
}

// Contains returns true if the device identified by MAC or IP is allowlisted.
// An unparseable MAC or IP on the detection side cannot match anything, so it
// returns false — the device is evaluated normally rather than accidentally
// protected or accidentally exposed.
func (a *Allowlist) Contains(mac, ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if mac != "" {
		if norm, err := NormalizeMAC(mac); err == nil {
			if _, ok := a.macs[norm]; ok {
				return true
			}
		}
	}

	if ip != "" {
		if addr, err := netip.ParseAddr(strings.TrimSpace(ip)); err == nil {
			canon := canonicalAddr(addr)
			if _, ok := a.addrs[canon]; ok {
				return true
			}
			for _, prefix := range a.nets {
				if prefix.Contains(canon) {
					return true
				}
			}
		}
	}

	return false
}

// Len reports how many entries protect devices. A zero-length allowlist means
// nothing is protected — including the router — which the controller refuses
// to auto-enforce against (see main.go).
func (a *Allowlist) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.macs) + len(a.addrs) + len(a.nets)
}

// MACs returns all allowlisted MAC addresses in canonical form.
func (a *Allowlist) MACs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.macs))
	for m := range a.macs {
		out = append(out, m)
	}
	return out
}

// IPs returns all allowlisted addresses and CIDR prefixes.
func (a *Allowlist) IPs() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]string, 0, len(a.addrs)+len(a.nets))
	for addr := range a.addrs {
		out = append(out, addr.String())
	}
	for _, prefix := range a.nets {
		out = append(out, prefix.String())
	}
	return out
}
