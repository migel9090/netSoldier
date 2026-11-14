package arp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/capture"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
)

const (
	ethPARP   = 0x0806
	ethHdrLen = 14
	arpLen    = 28 // hardware type (2) + proto type (2) + hw len (1) + proto len (1) + op (2) + SHA (6) + SPA (4) + THA (6) + TPA (4)
)

// Listener passively captures ARP traffic on one interface to learn which
// MAC uses which IPv4 address. Requires CAP_NET_RAW.
type Listener struct {
	iface    string
	ch       chan<- discovery.Sighting
	mismatch discovery.LogLimiter
}

// NewListener returns a listener for iface ("" = default-route interface).
func NewListener(iface string, ch chan<- discovery.Sighting) *Listener {
	return &Listener{iface: iface, ch: ch, mismatch: discovery.LogLimiter{Interval: 10 * time.Second}}
}

// Run reads until ctx is done or the socket fails.
func (l *Listener) Run(ctx context.Context, up func()) error {
	ifi, err := capture.ResolveInterface(l.iface)
	if err != nil {
		return err
	}
	conn, err := capture.OpenPacket(ifi, ethPARP, nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	up()

	buf := make([]byte, 128)
	for ctx.Err() == nil {
		n, err := conn.Read(buf)
		if errors.Is(err, capture.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		metrics.FramesReceived.WithLabelValues("arp").Inc()
		s, err := ParseFrame(buf[:n])
		if err != nil {
			l.reject(buf[:n], err)
			continue
		}
		select {
		case l.ch <- s:
		case <-ctx.Done():
		}
	}
	return nil
}

func (l *Listener) reject(frame []byte, err error) {
	metrics.FramesRejected.WithLabelValues("arp", discovery.RejectReason(err)).Inc()
	if !errors.Is(err, discovery.ErrLinkMismatch) {
		return
	}
	if ok, suppressed := l.mismatch.Allow(time.Now()); ok {
		slog.Warn("arp claim does not match its link-layer source; ignored",
			"eth_src", net.HardwareAddr(frame[6:12]).String(),
			"arp_sha", net.HardwareAddr(frame[ethHdrLen+8:ethHdrLen+14]).String(),
			"suppressed_since_last", suppressed)
	}
}

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
