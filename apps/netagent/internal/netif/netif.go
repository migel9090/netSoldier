// Package netif resolves the capture interface and reads the host's
// addresses. The isolation guard and the prober read these at check time,
// not once at start, because an interface's addresses can change.
package netif

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/migel9090/netSoldier/apps/netagent/internal/isolate"
	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

// Resolve returns the named interface, requiring it to be up and to carry a
// unicast Ethernet address.
func Resolve(name string) (*net.Interface, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", name, err)
	}
	if ifi.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %q is down", name)
	}
	if len(ifi.HardwareAddr) != 6 || !wire.MAC(ifi.HardwareAddr).Unicast() {
		return nil, fmt.Errorf("interface %q has no unicast Ethernet address", name)
	}
	return ifi, nil
}

// Prefixes returns the IPv4 prefixes configured on ifi (host bits intact), by
// index so a renumbering is picked up.
func Prefixes(ifi *net.Interface) ([]netip.Prefix, error) {
	cur, err := net.InterfaceByIndex(ifi.Index)
	if err != nil {
		return nil, err
	}
	addrs, err := cur.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() {
			continue
		}
		ones, _ := n.Mask.Size()
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out, nil
}

// Local reads every interface's unicast MAC and IPv4 addresses, plus the
// capture interface's own IPv4 subnets. The guard refuses any target equal
// to one of these addresses and anything off these subnets.
func Local(ifi *net.Interface) func() (isolate.Local, error) {
	return func() (isolate.Local, error) {
		var l isolate.Local
		ifaces, err := net.Interfaces()
		if err != nil {
			return l, err
		}
		for _, cur := range ifaces {
			if len(cur.HardwareAddr) == 6 && wire.MAC(cur.HardwareAddr).Unicast() {
				l.MACs = append(l.MACs, wire.MAC(cur.HardwareAddr))
			}
			addrs, err := cur.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				n, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip, ok := netip.AddrFromSlice(n.IP)
				if !ok {
					continue
				}
				ip = ip.Unmap()
				if ip.Is4() {
					l.IPs = append(l.IPs, ip)
				}
			}
		}
		if l.Subnets, err = Prefixes(ifi); err != nil {
			return l, err
		}
		return l, nil
	}
}
