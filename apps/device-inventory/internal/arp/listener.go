// Package arp parses Ethernet/ARP frames into sightings. The frames are
// captured by netagent and handed to device-inventory over HTTP (ADR-0004):
// this package opens no socket and holds no capability, so a parser bug here
// cannot reach the network.
package arp

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

const (
	ethPARP   = 0x0806
	ethHdrLen = 14
	arpLen    = 28 // hardware type (2) + proto type (2) + hw len (1) + proto len (1) + op (2) + SHA (6) + SPA (4) + THA (6) + TPA (4)
)

// ParseFrame validates an Ethernet/ARP frame and returns the sender's claim.
// The sender hardware address must be the frame's Ethernet source: an ARP
// packet that speaks for some other MAC is exactly what ARP spoofing looks
// like, and it is refused with ErrLinkMismatch. Probes (sender IP 0.0.0.0)
// and unusable sender addresses still prove the MAC is present, so they
// yield a sighting without an IP.
func ParseFrame(frame []byte) (discovery.Sighting, error) {
	if len(frame) < ethHdrLen+arpLen {
		return discovery.Sighting{}, discovery.ErrMalformed
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethPARP {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	a := frame[ethHdrLen:]
	hwType := binary.BigEndian.Uint16(a[0:2])
	protoType := binary.BigEndian.Uint16(a[2:4])
	op := binary.BigEndian.Uint16(a[6:8])
	if hwType != 1 || protoType != 0x0800 || a[4] != 6 || a[5] != 4 || (op != 1 && op != 2) {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	sha := a[8:14]
	if !bytes.Equal(sha, frame[6:12]) {
		return discovery.Sighting{}, discovery.ErrLinkMismatch
	}
	mac, ok := discovery.CanonicalMAC(sha)
	if !ok {
		return discovery.Sighting{}, discovery.ErrMalformed
	}
	s := discovery.Sighting{Source: discovery.SourceARP, MAC: mac}
	if ip, ok := discovery.UsableIPv4(net.IP(a[14:18])); ok {
		s.IP = ip
	}
	return s, nil
}
