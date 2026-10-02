package drivers

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
)

// TargetGuard refuses enforcement against infrastructure that must stay
// reachable. It duplicates the policy allowlist on purpose: the allowlist is
// configuration and can be mistyped, empty, or bypassed by a detection that
// arrives with only an IP, while this check sits in the one place every
// destructive action has to pass through.
//
// The gateway case is the reason it exists. Devices commonly use the router
// as their DNS forwarder, so every household query can appear to come FROM
// the router — one feed match and the killswitch would ARP-isolate the
// default gateway and take the whole network down. The ARP driver already
// knows the gateway's address; refusing it costs one comparison.
type TargetGuard struct {
	mu    sync.RWMutex
	ips   map[netip.Addr]struct{}
	macs  map[string]struct{}
	nets  []netip.Prefix
	names []string
}

// ProtectIP marks an address or CIDR as never-enforceable.
func (g *TargetGuard) ProtectIP(entry string) {
	s := strings.TrimSpace(entry)
	if s == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if strings.Contains(s, "/") {
		if prefix, err := netip.ParsePrefix(s); err == nil {
			g.nets = append(g.nets, prefix.Masked())
		}
		return
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return
	}
	if g.ips == nil {
		g.ips = make(map[netip.Addr]struct{})
	}
	g.ips[normalizeAddr(addr)] = struct{}{}
}

// ProtectMAC marks a hardware address as never-enforceable.
func (g *TargetGuard) ProtectMAC(mac string) {
	s := normalizeMACKey(mac)
	if s == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.macs == nil {
		g.macs = make(map[string]struct{})
	}
	g.macs[s] = struct{}{}
}

// ProtectName records a human-readable label for log messages.
func (g *TargetGuard) ProtectName(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.names = append(g.names, name)
}

// Check returns an error when the target must not be enforced against.
func (g *TargetGuard) Check(mac, ip string) error {
	if g == nil {
		return nil
	}
	g.mu.RLock()
	defer g.mu.RUnlock()

	if key := normalizeMACKey(mac); key != "" {
		if _, ok := g.macs[key]; ok {
			return fmt.Errorf("refusing to enforce against protected device %s", mac)
		}
	}

	if s := strings.TrimSpace(ip); s != "" {
		if addr, err := netip.ParseAddr(s); err == nil {
			canon := normalizeAddr(addr)
			if _, ok := g.ips[canon]; ok {
				return fmt.Errorf("refusing to enforce against protected address %s", ip)
			}
			for _, prefix := range g.nets {
				if prefix.Contains(canon) {
					return fmt.Errorf("refusing to enforce against protected range %s (%s)", prefix, ip)
				}
			}
		}
	}

	return nil
}

func normalizeAddr(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	return addr.WithZone("")
}

// normalizeMACKey reduces a MAC to bare lowercase hex so separator style
// never decides whether a device is protected.
func normalizeMACKey(mac string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(mac)) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			sb.WriteRune(r)
		case r == ':' || r == '-' || r == '.':
		default:
			return ""
		}
	}
	if sb.Len() != 12 {
		return ""
	}
	return sb.String()
}
