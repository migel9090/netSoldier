// Package dhcp parses DHCP client messages out of captured Ethernet frames
// into sightings. netagent captures the frames and hands them to
// device-inventory over HTTP (ADR-0004); this package opens no socket and
// holds no capability.
package dhcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

const (
	minPacketLen = 240
	magicCookie  = 0x63825363

	opBootRequest = 1
	htypeEthernet = 1

	optPad         = 0
	optEnd         = 255
	optHostName    = 12
	optRequestedIP = 50
	optMessageType = 53
	optPRL         = 55
	optVendorClass = 60

	msgDiscover = 1
	msgRequest  = 3
	msgInform   = 8

	ethPIPv4   = 0x0800
	ethHdrLen  = 14
	serverPort = 67
)

// ParseFrame unwraps Ethernet, IPv4 and UDP and returns the client's claim.
// The chaddr must be the Ethernet source; relayed messages (giaddr set) come
// from the relay agent's MAC, cannot be checked, and are refused.
func ParseFrame(frame []byte) (discovery.Sighting, error) {
	if len(frame) < ethHdrLen+20+8 {
		return discovery.Sighting{}, discovery.ErrMalformed
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethPIPv4 {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	ip := frame[ethHdrLen:]
	ihl := int(ip[0]&0x0f) * 4
	if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+8 {
		return discovery.Sighting{}, discovery.ErrMalformed
	}
	if ip[9] != 17 || binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 { // UDP, not fragmented
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	if total := int(binary.BigEndian.Uint16(ip[2:4])); total >= ihl+8 && total < len(ip) {
		ip = ip[:total] // drop Ethernet padding
	}
	udp := ip[ihl:]
	if binary.BigEndian.Uint16(udp[2:4]) != serverPort {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	payload := udp[8:]
	if ulen := int(binary.BigEndian.Uint16(udp[4:6])); ulen >= 8 && ulen-8 < len(payload) {
		payload = payload[:ulen-8]
	}

	m, err := parsePacket(payload)
	if err != nil {
		return discovery.Sighting{}, err
	}
	if !net.IP(m.giaddr).Equal(net.IPv4zero) {
		return discovery.Sighting{}, fmt.Errorf("%w: relayed by %s", discovery.ErrIgnored, net.IP(m.giaddr))
	}
	if !bytes.Equal(m.chaddr, frame[6:12]) {
		return discovery.Sighting{}, fmt.Errorf("%w: chaddr %s", discovery.ErrLinkMismatch, net.HardwareAddr(m.chaddr))
	}
	return m.sighting()
}

type message struct {
	msgType     byte
	chaddr      []byte
	ciaddr      []byte
	giaddr      []byte
	requestedIP []byte
	hostname    string
	fingerprint string
	vendorClass string
}

// parsePacket parses a BOOTP/DHCP client message. Only Ethernet clients
// (htype 1, hlen 6) are accepted: any other length used to produce keys that
// were not MAC addresses at all.
func parsePacket(data []byte) (message, error) {
	if len(data) < minPacketLen {
		return message{}, fmt.Errorf("%w: packet too short: %d", discovery.ErrMalformed, len(data))
	}
	if data[0] != opBootRequest {
		return message{}, fmt.Errorf("%w: not a client request (op=%d)", discovery.ErrIgnored, data[0])
	}
	if data[1] != htypeEthernet || data[2] != 6 {
		return message{}, fmt.Errorf("%w: htype=%d hlen=%d", discovery.ErrIgnored, data[1], data[2])
	}
	if cookie := binary.BigEndian.Uint32(data[236:240]); cookie != magicCookie {
		return message{}, fmt.Errorf("%w: bad magic cookie: %08x", discovery.ErrMalformed, cookie)
	}

	opts := parseOptions(data[240:])
	m := message{
		chaddr: data[28:34],
		ciaddr: data[12:16],
		giaddr: data[24:28],
	}
	if t := opts[optMessageType]; len(t) == 1 {
		m.msgType = t[0]
	}
	if ip := opts[optRequestedIP]; len(ip) == 4 {
		m.requestedIP = ip
	}
	if hn, ok := opts[optHostName]; ok {
		m.hostname = discovery.SanitizeText(string(hn), discovery.MaxNameLen)
	}
	if prl := opts[optPRL]; len(prl) > 0 {
		parts := make([]string, len(prl))
		for i, b := range prl {
			parts[i] = fmt.Sprintf("%d", b)
		}
		m.fingerprint = strings.Join(parts, ",")
	}
	if vc, ok := opts[optVendorClass]; ok {
		m.vendorClass = discovery.SanitizeText(string(vc), discovery.MaxVendorClassLen)
	}
	return m, nil
}

// claimedIP is the address the message says the client holds, by message
// type (RFC 2131 4.3.2, 4.4.1). A DISCOVER's option 50 is a wish, a
// DECLINE's is an address the client refuses because another host has it,
// and a RELEASE gives its address up: none of those is a binding.
func (m message) claimedIP() net.IP {
	switch m.msgType {
	case msgRequest:
		if m.requestedIP != nil { // SELECTING, INIT-REBOOT
			return net.IP(m.requestedIP)
		}
		return net.IP(m.ciaddr) // RENEWING, REBINDING
	case msgInform:
		return net.IP(m.ciaddr)
	}
	return nil
}

func (m message) sighting() (discovery.Sighting, error) {
	mac, ok := discovery.CanonicalMAC(m.chaddr)
	if !ok {
		return discovery.Sighting{}, fmt.Errorf("%w: chaddr %s is not a unicast MAC", discovery.ErrMalformed, net.HardwareAddr(m.chaddr))
	}
	s := discovery.Sighting{Source: discovery.SourceDHCP, MAC: mac, Name: m.hostname}
	// Only DISCOVER and REQUEST carry the profile fingerprinting is built on;
	// Windows, for one, asks for a different option 55 list in INFORM, and
	// mixing them would look like a second device behind the same MAC.
	if m.msgType == msgDiscover || m.msgType == msgRequest {
		s.Fingerprint, s.VendorClass = m.fingerprint, m.vendorClass
	}
	if ip, ok := discovery.UsableIPv4(m.claimedIP()); ok {
		s.IP = ip
	}
	return s, nil
}

func parseOptions(data []byte) map[byte][]byte {
	opts := make(map[byte][]byte)
	for i := 0; i < len(data); {
		code := data[i]
		if code == optPad {
			i++
			continue
		}
		if code == optEnd {
			break
		}
		if i+1 >= len(data) {
			break
		}
		length := int(data[i+1])
		if i+2+length > len(data) {
			break
		}
		if _, dup := opts[code]; !dup {
			opts[code] = data[i+2 : i+2+length]
		}
		i += 2 + length
	}
	return opts
}
