// Package wire is the only code in the agent that puts anything on the
// network. It does not accept bytes: it builds exactly three kinds of ARP
// frame from typed addresses (a broadcast probe, the isolation pair, the
// restoration pair), so no request from a peer can become a frame of the
// peer's choosing. Callers check policy (the isolation guard, the probe
// limits); this package only refuses addresses that no ARP frame of ours may
// ever carry, as a second line behind them.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

const (
	etherTypeARP = 0x0806
	frameLen     = 14 + 28 // Ethernet header + ARP for IPv4 over Ethernet
	opRequest    = 1
	opReply      = 2
)

// MAC is an Ethernet address.
type MAC [6]byte

var broadcast = MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (m MAC) String() string { return net.HardwareAddr(m[:]).String() }

// Unicast reports whether m can identify one station: not a group
// (multicast or broadcast) address and not all zeros. 11:22:33:44:55:66 has
// the group bit set and is NOT unicast.
func (m MAC) Unicast() bool { return m[0]&0x01 == 0 && m != MAC{} }

// Host is one station on the segment: a unicast MAC and an IPv4 address.
type Host struct {
	MAC MAC
	IP  netip.Addr
}

// ParseMAC accepts exactly "xx:xx:xx:xx:xx:xx" (hex, either case). Other
// spellings net.ParseMAC allows (dashes, dots, 8- and 20-byte addresses)
// are refused, so one address has one accepted form.
func ParseMAC(s string) (MAC, error) {
	var m MAC
	if len(s) != 17 {
		return m, fmt.Errorf("%q is not a MAC address (want xx:xx:xx:xx:xx:xx)", clip(s))
	}
	for i := 0; i < 6; i++ {
		if i > 0 && s[3*i-1] != ':' {
			return m, fmt.Errorf("%q is not a MAC address (want xx:xx:xx:xx:xx:xx)", clip(s))
		}
		hi, ok1 := unhex(s[3*i])
		lo, ok2 := unhex(s[3*i+1])
		if !ok1 || !ok2 {
			return m, fmt.Errorf("%q is not a MAC address (want xx:xx:xx:xx:xx:xx)", clip(s))
		}
		m[i] = hi<<4 | lo
	}
	return m, nil
}

// ParseIPv4 accepts a dotted-quad IPv4 address only. netip refuses leading
// zeros ("192.168.001.001") and the hex and integer forms
// ("0xc0a80101"); IPv4-mapped IPv6 and zoned addresses are refused here.
func ParseIPv4(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("%q is not an IPv4 address", clip(s))
	}
	return a, nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// arpFrame lays out one ARP packet for IPv4 over Ethernet. Every field has a
// fixed offset and width; nothing variable-length is copied in.
func arpFrame(ethDst, ethSrc MAC, op uint16, sha MAC, spa netip.Addr, tha MAC, tpa netip.Addr) []byte {
	f := make([]byte, frameLen)
	copy(f[0:6], ethDst[:])
	copy(f[6:12], ethSrc[:])
	binary.BigEndian.PutUint16(f[12:14], etherTypeARP)
	binary.BigEndian.PutUint16(f[14:16], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(f[16:18], 0x0800) // protocol type: IPv4
	f[18], f[19] = 6, 4
	binary.BigEndian.PutUint16(f[20:22], op)
	copy(f[22:28], sha[:])
	s4, t4 := spa.As4(), tpa.As4()
	copy(f[28:32], s4[:])
	copy(f[32:38], tha[:])
	copy(f[38:42], t4[:])
	return f
}

// ErrAddress is returned for an address no frame of ours may carry.
var ErrAddress = errors.New("wire: refusing a non-unicast MAC or non-IPv4 address")

func (h Host) valid() bool { return h.MAC.Unicast() && h.IP.Is4() && !h.IP.IsUnspecified() }

// Sender transmits on one interface. Its socket is opened with protocol 0,
// so the kernel never queues a received frame on it.
type Sender struct {
	fd      int
	ifindex int
	mac     MAC
	send    func(dst MAC, frame []byte) error // replaced in tests
}

// Open opens the transmit socket for ifi, which must have a unicast Ethernet
// address (every frame we build is sent from it). It needs CAP_NET_RAW.
func Open(ifi *net.Interface) (*Sender, error) {
	var mac MAC
	if len(ifi.HardwareAddr) != 6 || !MAC(ifi.HardwareAddr).Unicast() {
		return nil, fmt.Errorf("interface %s has no unicast Ethernet address", ifi.Name)
	}
	copy(mac[:], ifi.HardwareAddr)
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_PACKET socket (the binary needs CAP_NET_RAW): %w", err)
	}
	s := &Sender{fd: fd, ifindex: ifi.Index, mac: mac}
	s.send = s.sendto
	return s, nil
}

func (s *Sender) sendto(dst MAC, frame []byte) error {
	addr := unix.SockaddrLinklayer{Protocol: htons(etherTypeARP), Ifindex: s.ifindex, Halen: 6}
	copy(addr.Addr[:6], dst[:])
	if err := unix.Sendto(s.fd, frame, 0, &addr); err != nil {
		return fmt.Errorf("send to %s: %w", dst, err)
	}
	return nil
}

// MAC is the address every frame is sent from.
func (s *Sender) MAC() MAC { return s.mac }

// Probe broadcasts "who has target? tell sender", from this interface.
func (s *Sender) Probe(sender, target netip.Addr) error {
	if !sender.Is4() || !target.Is4() {
		return ErrAddress
	}
	return s.send(broadcast, arpFrame(broadcast, s.mac, opRequest, s.mac, sender, MAC{}, target))
}

// Apply steers one target's gateway traffic onto this interface: it tells
// target that the gateway's address is at this interface, and the gateway
// that target's address is at this interface. Both frames are unicast
// replies, so nothing else on the segment hears them. With IP forwarding off
// (the isolation guard insists on that), the redirected traffic is dropped
// here, which is the isolation; this is the only effect wanted.
func (s *Sender) Apply(target, gateway Host) error {
	if !target.valid() || !gateway.valid() {
		return ErrAddress
	}
	if err := s.send(target.MAC, arpFrame(target.MAC, s.mac, opReply, s.mac, gateway.IP, target.MAC, target.IP)); err != nil {
		return fmt.Errorf("apply to target: %w", err)
	}
	if err := s.send(gateway.MAC, arpFrame(gateway.MAC, s.mac, opReply, s.mac, target.IP, gateway.MAC, gateway.IP)); err != nil {
		return fmt.Errorf("apply to gateway: %w", err)
	}
	return nil
}

// Lift undoes Apply: it tells target the gateway's real address, and the
// gateway target's, so the two reach each other directly again. The Ethernet
// source stays this interface (a frame sourced from the gateway's MAC would
// teach the switch that the gateway lives on our port); only the ARP sender
// fields carry the other station's real address.
func (s *Sender) Lift(target, gateway Host) error {
	if !target.valid() || !gateway.valid() {
		return ErrAddress
	}
	if err := s.send(target.MAC, arpFrame(target.MAC, s.mac, opReply, gateway.MAC, gateway.IP, target.MAC, target.IP)); err != nil {
		return fmt.Errorf("lift towards target: %w", err)
	}
	if err := s.send(gateway.MAC, arpFrame(gateway.MAC, s.mac, opReply, target.MAC, target.IP, gateway.MAC, gateway.IP)); err != nil {
		return fmt.Errorf("lift towards gateway: %w", err)
	}
	return nil
}

// Close releases the socket.
func (s *Sender) Close() error { return unix.Close(s.fd) }

// htons converts to network byte order, which sockaddr_ll expects.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

// Htons is htons for the capture package.
func Htons(v uint16) uint16 { return htons(v) }
