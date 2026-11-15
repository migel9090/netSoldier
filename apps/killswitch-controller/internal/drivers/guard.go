package drivers

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Reasons the guard refuses a target, used as metric label values.
const (
	refusedNoGuard           = "no_guard"
	refusedMissingIdentifier = "missing_identifier"
	refusedInvalidIdentifier = "invalid_identifier"
	refusedProtectedDevice   = "protected_device"
)

var guardRefusals = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "killswitch",
	Name:      "guard_refusals_total",
	Help:      "Device enforcement requests the target guard refused, by reason.",
}, []string{"reason"})

func init() {
	prometheus.MustRegister(guardRefusals)
	for _, r := range []string{refusedNoGuard, refusedMissingIdentifier,
		refusedInvalidIdentifier, refusedProtectedDevice} {
		guardRefusals.WithLabelValues(r)
	}
}

// TargetGuard refuses enforcement against infrastructure that must stay
// reachable. It duplicates the policy allowlist on purpose: the allowlist is
// configuration and can be mistyped, empty, or bypassed by a detection that
// arrives with only an IP, while this check sits in the one place every
// destructive action has to pass through.
//
// The gateway case is the reason it exists. Devices commonly use the router
// as their DNS forwarder, so every household query can appear to come FROM
// the router — one feed match and the killswitch would ARP-isolate the
// default gateway and take the whole network down.
//
// It fails closed. A device is only approved when BOTH its MAC and its IP
// are present and parse as exactly one device, and neither is protected:
// with one identifier missing the guard cannot tell whether the other one
// belongs to the router, and an identifier it cannot parse is one it cannot
// compare. Skipping what it did not understand is how "192.168.001.001" and
// "aa bb cc dd ee ff" used to reach the switch webhook.
type TargetGuard struct {
	mu    sync.RWMutex
	ips   map[netip.Addr]struct{}
	macs  map[string]struct{}
	nets  []netip.Prefix
	names []string
}

// Device is a target the guard approved, in the canonical forms it checked:
// lower-case colon-separated MAC, canonical IP. Drivers send these rather
// than the raw strings, so whatever acts on the request parses exactly what
// the guard compared.
type Device struct {
	MAC string
	IP  string
}

// ProtectIP marks an address or CIDR as never-enforceable. An entry that
// does not parse is an error: a protection that silently did nothing is the
// failure this type exists to prevent.
func (g *TargetGuard) ProtectIP(entry string) error {
	s := strings.TrimSpace(entry)
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("protect %q: %w", entry, err)
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		g.nets = append(g.nets, prefix.Masked())
		return nil
	}
	addr, err := parseDeviceIP(s)
	if err != nil {
		return fmt.Errorf("protect %q: %w", entry, err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ips == nil {
		g.ips = make(map[netip.Addr]struct{})
	}
	g.ips[addr] = struct{}{}
	return nil
}

// ProtectMAC marks a hardware address as never-enforceable.
func (g *TargetGuard) ProtectMAC(mac string) error {
	key, err := parseDeviceMAC(mac)
	if err != nil {
		return fmt.Errorf("protect %q: %w", mac, err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.macs == nil {
		g.macs = make(map[string]struct{})
	}
	g.macs[key] = struct{}{}
	return nil
}

// ProtectName records a human-readable label for log messages.
func (g *TargetGuard) ProtectName(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.names = append(g.names, name)
}

// Check returns an error when the target must not be enforced against.
func (g *TargetGuard) Check(mac, ip string) error {
	_, err := g.Vet(mac, ip)
	return err
}

// Vet approves a target and returns it in canonical form, or refuses it.
func (g *TargetGuard) Vet(mac, ip string) (Device, error) {
	if g == nil {
		return Device{}, refuse(refusedNoGuard, mac, ip, errors.New("no target guard configured"))
	}
	if strings.TrimSpace(mac) == "" || strings.TrimSpace(ip) == "" {
		return Device{}, refuse(refusedMissingIdentifier, mac, ip,
			fmt.Errorf("target needs both a MAC and an IP (got mac=%q ip=%q): "+
				"with one missing the guard cannot tell whether the other belongs to a protected device",
				mac, ip))
	}
	key, err := parseDeviceMAC(mac)
	if err != nil {
		return Device{}, refuse(refusedInvalidIdentifier, mac, ip, fmt.Errorf("target MAC: %w", err))
	}
	addr, err := parseDeviceIP(ip)
	if err != nil {
		return Device{}, refuse(refusedInvalidIdentifier, mac, ip, fmt.Errorf("target IP: %w", err))
	}

	g.mu.RLock()
	defer g.mu.RUnlock()
	if _, ok := g.macs[key]; ok {
		return Device{}, refuse(refusedProtectedDevice, mac, ip,
			fmt.Errorf("refusing to enforce against protected device %s", formatMACKey(key)))
	}
	if _, ok := g.ips[addr]; ok {
		return Device{}, refuse(refusedProtectedDevice, mac, ip,
			fmt.Errorf("refusing to enforce against protected address %s", addr))
	}
	for _, prefix := range g.nets {
		if prefix.Contains(addr) {
			return Device{}, refuse(refusedProtectedDevice, mac, ip,
				fmt.Errorf("refusing to enforce against protected range %s (%s)", prefix, addr))
		}
	}
	return Device{MAC: formatMACKey(key), IP: addr.String()}, nil
}

func refuse(reason, mac, ip string, err error) error {
	guardRefusals.WithLabelValues(reason).Inc()
	slog.Warn("target guard refused enforcement", "reason", reason,
		"target_mac", mac, "target_ip", ip, "error", err)
	return err
}

// parseDeviceIP accepts exactly one device address: netip's strict grammar
// (no leading zeros, hex or octal), no prefix and no zone, IPv4-mapped IPv6
// folded to IPv4.
func parseDeviceIP(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%q is not a single IP address", s)
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("%q is zoned: a zone names a local interface, not a device", s)
	}
	return addr.Unmap(), nil
}

// parseDeviceMAC reduces a 48-bit MAC in colon, hyphen, dotted or bare-hex
// spelling to bare lower-case hex, and refuses anything else.
func parseDeviceMAC(mac string) (string, error) {
	if key := normalizeMACKey(mac); key != "" {
		return key, nil
	}
	return "", fmt.Errorf("%q is not a 48-bit MAC address", mac)
}

func formatMACKey(key string) string {
	var sb strings.Builder
	for i := 0; i < len(key); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(key[i : i+2])
	}
	return sb.String()
}

// normalizeMACKey reduces a MAC to bare lowercase hex so separator style
// never decides whether a device is protected. It returns "" for anything
// that is not 12 hex digits once separators are removed.
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
