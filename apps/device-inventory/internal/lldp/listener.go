// Package lldp parses LLDP frames into sightings, offering the system name
// for the frame's source MAC. netagent captures the frames (ADR-0004); this
// package opens no socket.
//
// LLDP contributes a name only. The chassis ID and management address are
// claims inside the payload: switches commonly send LLDP from per-port MACs
// while managing themselves from another MAC and VLAN, so binding the
// management address to the frame source would be wrong as often as right.
package lldp

import (
	"encoding/binary"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

const (
	ethPLLDP   = 0x88CC
	ethHdrLen  = 14
	tlvEnd     = 0
	tlvSysName = 5
)

// ParseFrame returns the system name an LLDP frame announces for its own
// Ethernet source.
func ParseFrame(frame []byte) (discovery.Sighting, error) {
	if len(frame) <= ethHdrLen {
		return discovery.Sighting{}, discovery.ErrMalformed
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethPLLDP {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	mac, ok := discovery.CanonicalMAC(frame[6:12])
	if !ok {
		return discovery.Sighting{}, discovery.ErrMalformed
	}
	name := discovery.SanitizeText(parseSysName(frame[ethHdrLen:]), discovery.MaxNameLen)
	if name == "" {
		return discovery.Sighting{}, discovery.ErrIgnored
	}
	return discovery.Sighting{Source: discovery.SourceLLDP, MAC: mac, Name: name}, nil
}

// parseSysName walks the TLV list and returns the System Name TLV's value.
// Every step advances by at least the 2-byte header, so it terminates.
func parseSysName(data []byte) string {
	offset := 0
	for offset+2 <= len(data) {
		header := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvType := int(header >> 9)
		tlvLen := int(header & 0x01FF)
		offset += 2

		if tlvType == tlvEnd || offset+tlvLen > len(data) {
			break
		}
		if tlvType == tlvSysName {
			return string(data[offset : offset+tlvLen])
		}
		offset += tlvLen
	}
	return ""
}
