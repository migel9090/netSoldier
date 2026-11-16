// Package isolate is the ARP isolation engine (contract v2 section 8.2) and
// the guard in front of it. The guard is configured when the agent starts
// and cannot be changed by a caller: whoever controls the killswitch can ask
// for an isolation, but cannot make the agent poison the gateway, itself, a
// protected device, a group address or anything off its own subnet, nor
// isolate anything while the host would forward the intercepted traffic.
package isolate

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

// Refusal is a command the guard or the engine turned down. Code is a short
// stable word for counting; Reason is what the caller and the log are told.
type Refusal struct {
	Code   string
	Reason string
}

func (r *Refusal) Error() string { return "refused: " + r.Reason }

func refuse(code, format string, args ...any) *Refusal {
	return &Refusal{Code: code, Reason: fmt.Sprintf(format, args...)}
}

// Local is what the host's own interfaces look like at check time.
type Local struct {
	MACs    []wire.MAC     // every interface's address
	IPs     []netip.Addr   // every interface's addresses
	Subnets []netip.Prefix // the isolation interface's IPv4 prefixes
}

// Guard decides whether a target may be isolated. Its fields are set once,
// from the agent's configuration; GatewayMAC in particular is pinned there
// and never learned from the neighbour table or from anything on the wire
// (audit KS-8: any LAN device can forge those).
type Guard struct {
	Interface     string
	GatewayIP     netip.Addr
	GatewayMAC    wire.MAC
	ProtectedMACs map[wire.MAC]bool
	ProtectedIPs  map[netip.Addr]bool
	MaxTTL        time.Duration
	// Local and Forwarding are read at every check: addresses change, and
	// so can the host's forwarding setting.
	Local      func() (Local, error)
	Forwarding func() (bool, error)
}

// Check validates an arp_isolate request and returns the target and TTL.
// The order puts the cheap structural refusals first; every rule is
// independent, so the order does not change what is refused.
func (g *Guard) Check(mac, ip string, ttlSeconds int64) (wire.Host, time.Duration, error) {
	t, err := g.target(mac, ip)
	if err != nil {
		return wire.Host{}, 0, err
	}
	if ttlSeconds <= 0 || time.Duration(ttlSeconds)*time.Second > g.MaxTTL {
		return wire.Host{}, 0, refuse("ttl", "ttl_seconds must be between 1 and %d", int64(g.MaxTTL/time.Second))
	}
	on, err := g.Forwarding()
	if err != nil {
		return wire.Host{}, 0, refuse("forwarding", "cannot read the host's IP forwarding setting")
	}
	if on {
		// Audit KS-9: with forwarding on, the poisoned traffic is routed on
		// to its destination and the "isolation" is a man-in-the-middle.
		return wire.Host{}, 0, refuse("forwarding", "IP forwarding is enabled on this host; isolation would forward the traffic instead of dropping it")
	}
	return t, time.Duration(ttlSeconds) * time.Second, nil
}

// target applies every rule about the addresses themselves.
func (g *Guard) target(mac, ip string) (wire.Host, error) {
	m, err := wire.ParseMAC(mac)
	if err != nil {
		return wire.Host{}, refuse("malformed", "target MAC is malformed")
	}
	// Audit KS-5: a group MAC would make the poison reach every host.
	if m[0]&0x01 != 0 {
		return wire.Host{}, refuse("group_mac", "target MAC is a broadcast or multicast address")
	}
	if m == (wire.MAC{}) {
		return wire.Host{}, refuse("zero_mac", "target MAC is all zeros")
	}
	a, err := wire.ParseIPv4(ip)
	if err != nil {
		return wire.Host{}, refuse("malformed", "target IP is not an IPv4 address")
	}
	if !hostAddress(a) {
		return wire.Host{}, refuse("unusable_ip", "target IP is not a unicast host address")
	}
	if a == g.GatewayIP || m == g.GatewayMAC {
		return wire.Host{}, refuse("gateway", "target is the gateway")
	}
	local, err := g.Local()
	if err != nil {
		return wire.Host{}, refuse("local", "cannot read this host's addresses")
	}
	for _, own := range local.MACs {
		if m == own {
			return wire.Host{}, refuse("self", "target is one of this agent's own addresses")
		}
	}
	for _, own := range local.IPs {
		if a == own {
			return wire.Host{}, refuse("self", "target is one of this agent's own addresses")
		}
	}
	if g.ProtectedMACs[m] || g.ProtectedIPs[a] {
		return wire.Host{}, refuse("protected", "target is a protected device")
	}
	if !onSubnet(a, local.Subnets) {
		return wire.Host{}, refuse("off_subnet", "target is not a host on %s's subnet", g.Interface)
	}
	return wire.Host{MAC: m, IP: a}, nil
}

// hostAddress refuses addresses no single LAN station holds: unspecified,
// this-network (0/8), loopback, link-local, multicast, reserved (240/4) and
// limited broadcast.
func hostAddress(a netip.Addr) bool {
	b := a.As4()
	return !a.IsUnspecified() && b[0] != 0 && !a.IsLoopback() && !a.IsLinkLocalUnicast() &&
		!a.IsMulticast() && b[0] < 240
}

// onSubnet reports whether a is a host address in one of the prefixes: not
// their network or directed-broadcast address (for prefixes up to /30).
func onSubnet(a netip.Addr, subnets []netip.Prefix) bool {
	for _, p := range subnets {
		if !p.Addr().Is4() || !p.Contains(a) {
			continue
		}
		if p.Bits() <= 30 {
			network := p.Masked().Addr()
			if a == network || a == directedBroadcast(p) {
				return false
			}
		}
		return true
	}
	return false
}

func directedBroadcast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= uint32(1)<<(32-p.Bits()) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// ProcForwarding reads the host's IPv4 forwarding state: the global switch
// and the interface's own. Either one on means packets arriving on the
// interface can be routed onward, which is what isolation must not do. With
// hostNetwork the agent sees the node's /proc/sys/net, not a pod's.
func ProcForwarding(iface string) func() (bool, error) {
	return func() (bool, error) {
		for _, path := range []string{"/proc/sys/net/ipv4/ip_forward", "/proc/sys/net/ipv4/conf/" + iface + "/forwarding"} {
			b, err := os.ReadFile(path)
			if err != nil {
				return false, err
			}
			if strings.TrimSpace(string(b)) != "0" {
				return true, nil
			}
		}
		return false, nil
	}
}
