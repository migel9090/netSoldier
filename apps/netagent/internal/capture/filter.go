package capture

import (
	"net"
	"net/netip"

	"golang.org/x/net/bpf"
)

// Protocol is one capture: the socket's EtherType, the kernel filter that
// decides which frames are copied to the agent at all, the multicast groups
// the interface must accept for those frames to arrive, and the length
// bounds the agent checks itself. Nothing here looks past the headers the
// filter needs; the frames are parsed by device-inventory, in its sandbox.
type Protocol struct {
	Name      string
	EtherType uint16
	Filter    []bpf.Instruction
	// LinkGroups are joined with PACKET_ADD_MEMBERSHIP: the NIC drops
	// link-local groups such as LLDP's unless something asks for them.
	LinkGroups []net.HardwareAddr
	// IPGroup, if valid, is also joined at the IP level on an unbound UDP
	// socket, so the kernel sends IGMP reports: a switch doing IGMP
	// snooping forwards 239.255.255.250 only to ports that asked for it.
	IPGroup netip.Addr
	// MinLen and MaxLen bound a frame. The kernel truncates to MaxLen+1,
	// so a longer frame is recognised and dropped instead of forwarded cut.
	MinLen, MaxLen int
}

const (
	etherIPv4 = 0x0800
	etherARP  = 0x0806
	etherLLDP = 0x88cc

	// MaxFrame is the largest frame any protocol forwards: a 9000-byte
	// mDNS packet (RFC 6762 section 17) with its Ethernet header and one
	// VLAN tag. Everything else is bounded by a 1500-byte MTU.
	MaxFrame   = 14 + 9000 + 4
	mtuFrame   = 14 + 1500 + 4
	udpHeaders = 14 + 20 + 8
)

var (
	mdnsGroup = netip.AddrFrom4([4]byte{224, 0, 0, 251})
	ssdpGroup = netip.AddrFrom4([4]byte{239, 255, 255, 250})
)

// Protocols lists every capture the agent can run, in a stable order.
var Protocols = []Protocol{
	{
		Name: "arp", EtherType: etherARP,
		Filter: etherTypeFilter(etherARP, 128+1),
		MinLen: 14 + 28, MaxLen: 128,
	},
	{
		// Client to server only (destination port 67): that is what
		// device-inventory learns from.
		Name: "dhcp", EtherType: etherIPv4,
		Filter: udpFilter(netip.Addr{}, 67, mtuFrame+1),
		MinLen: udpHeaders + 240, MaxLen: mtuFrame,
	},
	{
		Name: "lldp", EtherType: etherLLDP,
		Filter: etherTypeFilter(etherLLDP, mtuFrame+1),
		LinkGroups: []net.HardwareAddr{
			{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}, // nearest bridge
			{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}, // nearest non-TPMR bridge
			{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}, // nearest customer bridge
		},
		MinLen: 14 + 2, MaxLen: mtuFrame,
	},
	{
		Name: "mdns", EtherType: etherIPv4,
		Filter:     udpFilter(mdnsGroup, 5353, MaxFrame+1),
		LinkGroups: []net.HardwareAddr{{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}},
		IPGroup:    mdnsGroup,
		MinLen:     udpHeaders + 12, MaxLen: MaxFrame,
	},
	{
		Name: "ssdp", EtherType: etherIPv4,
		Filter:     udpFilter(ssdpGroup, 1900, mtuFrame+1),
		LinkGroups: []net.HardwareAddr{{0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa}},
		IPGroup:    ssdpGroup,
		MinLen:     udpHeaders + 16, MaxLen: mtuFrame,
	},
}

// Lookup returns the protocol called name.
func Lookup(name string) (Protocol, bool) {
	for _, p := range Protocols {
		if p.Name == name {
			return p, true
		}
	}
	return Protocol{}, false
}

// Names lists every protocol name in order.
func Names() []string {
	out := make([]string, len(Protocols))
	for i, p := range Protocols {
		out[i] = p.Name
	}
	return out
}

// dropMark stands for "jump to the final drop" until resolve fills in the
// distance.
const dropMark = 0xff

func etherTypeFilter(etherType uint16, snap uint32) []bpf.Instruction {
	return resolve([]bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(etherType), SkipTrue: dropMark},
		bpf.RetConstant{Val: snap},
		bpf.RetConstant{Val: 0},
	})
}

// udpFilter accepts unfragmented IPv4/UDP to port, and to group if it is
// valid. Fragments are dropped in the kernel: a first fragment carries a
// truncated payload and a later one no UDP header at all.
func udpFilter(group netip.Addr, port uint16, snap uint32) []bpf.Instruction {
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: 12, Size: 2}, // EtherType
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: etherIPv4, SkipTrue: dropMark},
		bpf.LoadAbsolute{Off: 23, Size: 1}, // IP protocol
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: 17, SkipTrue: dropMark},
		bpf.LoadAbsolute{Off: 20, Size: 2}, // flags and fragment offset
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x3fff, SkipTrue: dropMark},
	}
	if group.IsValid() {
		g := group.As4()
		prog = append(prog,
			bpf.LoadAbsolute{Off: 30, Size: 4}, // IP destination
			bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(g[0])<<24 | uint32(g[1])<<16 | uint32(g[2])<<8 | uint32(g[3]), SkipTrue: dropMark})
	}
	return resolve(append(prog,
		bpf.LoadMemShift{Off: 14},          // X = IP header length
		bpf.LoadIndirect{Off: 16, Size: 2}, // UDP destination port
		bpf.JumpIf{Cond: bpf.JumpNotEqual, Val: uint32(port), SkipTrue: dropMark},
		bpf.RetConstant{Val: snap},
		bpf.RetConstant{Val: 0},
	))
}

// resolve points every dropMark jump at the program's last instruction,
// which must be the drop.
func resolve(prog []bpf.Instruction) []bpf.Instruction {
	last := len(prog) - 1
	for i, ins := range prog {
		if j, ok := ins.(bpf.JumpIf); ok && j.SkipTrue == dropMark {
			j.SkipTrue = uint8(last - i - 1)
			prog[i] = j
		}
	}
	return prog
}
