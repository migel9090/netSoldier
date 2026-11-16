package discovery

import "net"

// Ethernet/IPv4/UDP header sizes. These are the only headers the inventory
// unwraps; everything deeper is a protocol payload for a parser.
const (
	ethHeaderLen = 14
	ethTypeIPv4  = 0x0800
	minIHL       = 20
	udpHeaderLen = 8
	protoUDP     = 17
)

// UDPPayload unwraps an Ethernet/IPv4/UDP frame and returns the UDP payload
// and the sender's IPv4 source address. It is the header-stripping that mDNS
// and SSDP need now that the agent hands device-inventory whole frames rather
// than datagrams from a bound socket. It faces attacker-controlled bytes, so
// every field is bounds-checked and nothing is trusted: a frame that is
// truncated, not IPv4/UDP, a fragment, or not to dstPort yields ok=false.
//
// It returns a sub-slice of frame; callers must not retain it past the
// frame's lifetime.
func UDPPayload(frame []byte, dstPort uint16) (payload []byte, src net.IP, ok bool) {
	if len(frame) < ethHeaderLen+minIHL+udpHeaderLen {
		return nil, nil, false
	}
	if uint16(frame[12])<<8|uint16(frame[13]) != ethTypeIPv4 {
		return nil, nil, false
	}
	ip := frame[ethHeaderLen:]
	if ip[0]>>4 != 4 {
		return nil, nil, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < minIHL || len(ip) < ihl+udpHeaderLen {
		return nil, nil, false
	}
	if ip[9] != protoUDP {
		return nil, nil, false
	}
	// Drop fragments: a non-zero fragment offset or the more-fragments flag
	// (the low 13 bits of the flags/offset word) means this is not a whole
	// datagram, so the UDP header may be absent or the payload truncated.
	if (uint16(ip[6])<<8|uint16(ip[7]))&0x3fff != 0 {
		return nil, nil, false
	}
	// Trust the IP total-length field only as far as the frame allows, so
	// trailing Ethernet padding is dropped without ever reading past the end.
	if total := int(uint16(ip[2])<<8 | uint16(ip[3])); total >= ihl+udpHeaderLen && total <= len(ip) {
		ip = ip[:total]
	}
	udp := ip[ihl:]
	if uint16(udp[2])<<8|uint16(udp[3]) != dstPort {
		return nil, nil, false
	}
	payload = udp[udpHeaderLen:]
	if ulen := int(uint16(udp[4])<<8 | uint16(udp[5])); ulen >= udpHeaderLen && ulen-udpHeaderLen <= len(payload) {
		payload = payload[:ulen-udpHeaderLen]
	}
	srcAddr, ok := UsableIPv4(net.IP(ip[12:16]))
	if !ok {
		return nil, nil, false
	}
	return payload, net.ParseIP(srcAddr), true
}
