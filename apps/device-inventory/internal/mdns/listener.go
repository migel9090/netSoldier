// Package mdns parses mDNS responses into sightings, offering the responder's
// own .local name for the device holding the source address. netagent
// captures the frames (ADR-0004); this package opens no socket.
package mdns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

const port = 5353

// ParseFrame unwraps an Ethernet/IPv4/UDP frame carrying mDNS (UDP 5353) and
// returns the sighting ParseDatagram derives from its payload. The agent
// captures whole frames; this is where device-inventory strips the link, IP
// and UDP headers, inside its sandbox and facing attacker-controlled bytes.
func ParseFrame(frame []byte) (discovery.Sighting, error) {
	payload, src, ok := discovery.UDPPayload(frame, port)
	if !ok {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	return ParseDatagram(payload, src)
}

// ParseDatagram turns an mDNS payload received from src into a sighting: the
// responder's own name, offered for whoever holds src. It does no I/O.
func ParseDatagram(payload []byte, src net.IP) (discovery.Sighting, error) {
	ip, ok := discovery.UsableIPv4(src)
	if !ok {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	name := extractHostname(payload, src)
	if name == "" {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	return discovery.Sighting{Source: discovery.SourceMDNS, IP: ip, Name: name}, nil
}

// Name limits from RFC 1035: 255 bytes per name. A real name needs one or two
// compression pointers; sixteen is generous and keeps a hostile chain cheap.
const (
	maxNameLen  = 255
	maxPointers = 16
)

var errBadName = errors.New("bad DNS name")

// extractHostname returns the first .local host name from an A record in an
// mDNS response whose address is the datagram's own source: a responder
// naming itself. Records about other addresses (sleep proxies, forgeries)
// are ignored. The result is sanitised; "" means nothing usable.
func extractHostname(pkt []byte, src net.IP) string {
	if len(pkt) < 12 || pkt[2]&0x80 == 0 { // header, QR=response
		return ""
	}
	src4 := src.To4()
	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	nscount := int(binary.BigEndian.Uint16(pkt[8:10]))
	arcount := int(binary.BigEndian.Uint16(pkt[10:12]))

	offset := 12
	for i := 0; i < qdcount; i++ {
		_, next, err := parseDNSName(pkt, offset)
		if err != nil || next+4 > len(pkt) {
			return ""
		}
		offset = next + 4 // QTYPE + QCLASS
	}
	// mDNS responders put their address records in answers or additionals.
	for i := 0; i < ancount+nscount+arcount; i++ {
		name, next, err := parseDNSName(pkt, offset)
		if err != nil || next+10 > len(pkt) {
			return ""
		}
		rtype := binary.BigEndian.Uint16(pkt[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdlen > len(pkt) {
			return ""
		}
		offset = rdata + rdlen

		if rtype != 1 || rdlen != 4 || src4 == nil || !net.IP(pkt[rdata:rdata+4]).Equal(src4) {
			continue
		}
		if len(name) <= len(".local") || !strings.EqualFold(name[len(name)-len(".local"):], ".local") {
			continue
		}
		if host := discovery.SanitizeText(name[:len(name)-len(".local")], discovery.MaxNameLen); host != "" {
			return host
		}
	}
	return ""
}

// parseDNSName decodes the (possibly compressed) name at off and returns it
// with the offset just past it in the record. It refuses forward or
// self-referencing pointers, more than maxPointers jumps, names longer than
// 255 bytes and the reserved label types, so every input terminates after a
// bounded amount of work and memory.
func parseDNSName(pkt []byte, off int) (string, int, error) {
	name := make([]byte, 0, 64)
	next := -1
	jumps := 0
	for {
		if off >= len(pkt) {
			return "", 0, errBadName
		}
		l := int(pkt[off])
		switch {
		case l == 0:
			if next < 0 {
				next = off + 1
			}
			return string(name), next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(pkt) {
				return "", 0, errBadName
			}
			target := (l&0x3F)<<8 | int(pkt[off+1])
			jumps++
			if target >= off || jumps > maxPointers {
				return "", 0, errBadName
			}
			if next < 0 {
				next = off + 2
			}
			off = target
		case l&0xC0 != 0:
			return "", 0, errBadName
		default:
			off++
			if off+l > len(pkt) || len(name)+l+1 > maxNameLen {
				return "", 0, errBadName
			}
			if len(name) > 0 {
				name = append(name, '.')
			}
			name = append(name, pkt[off:off+l]...)
			off += l
		}
	}
}
