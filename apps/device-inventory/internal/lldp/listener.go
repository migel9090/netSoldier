package lldp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/capture"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
)

const (
	ethPLLDP   = 0x88CC
	ethHdrLen  = 14
	tlvEnd     = 0
	tlvSysName = 5
)

// The LLDP destination groups (IEEE 802.1AB). NICs drop them unless joined.
var (
	nearestBridge  = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}
	nonTPMRBridge  = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}
	customerBridge = net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}
)

// Listener passively captures LLDP frames on one interface and offers the
// system name for the frame's source MAC. Requires CAP_NET_RAW.
//
// LLDP contributes a name only. The chassis ID and management address are
// claims inside the payload: switches commonly send LLDP from per-port MACs
// while managing themselves from another MAC and VLAN, so binding the
// management address to the frame source would be wrong as often as right.
type Listener struct {
	iface string
	ch    chan<- discovery.Sighting
}

// NewListener returns a listener for iface ("" = default-route interface).
func NewListener(iface string, ch chan<- discovery.Sighting) *Listener {
	return &Listener{iface: iface, ch: ch}
}

// Run reads until ctx is done or the socket fails.
func (l *Listener) Run(ctx context.Context, up func()) error {
	ifi, err := capture.ResolveInterface(l.iface)
	if err != nil {
		return err
	}
	conn, err := capture.OpenPacket(ifi, ethPLLDP, nil, nearestBridge, nonTPMRBridge, customerBridge)
	if err != nil {
		return err
	}
	defer conn.Close()
	up()

	buf := make([]byte, 1518)
	for ctx.Err() == nil {
		n, err := conn.Read(buf)
		if errors.Is(err, capture.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		metrics.FramesReceived.WithLabelValues("lldp").Inc()
		s, err := ParseFrame(buf[:n])
		if err != nil {
			metrics.FramesRejected.WithLabelValues("lldp", discovery.RejectReason(err)).Inc()
			continue
		}
		select {
		case l.ch <- s:
		case <-ctx.Done():
		}
	}
	return nil
}

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
