package arp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"syscall"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

const (
	ethPARP   = 0x0806
	ethHdrLen = 14
	arpLen    = 28 // hardware type (2) + proto type (2) + hw len (1) + proto len (1) + op (2) + SHA (6) + SPA (4) + THA (6) + TPA (4)
)

// Listener passively captures ARP traffic to discover MAC-IP pairs.
// Requires CAP_NET_RAW.
type Listener struct {
	ch chan<- discovery.Info
}

func NewListener(ch chan<- discovery.Info) *Listener {
	return &Listener{ch: ch}
}

func (l *Listener) Run(ctx context.Context) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPARP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 2}); err != nil {
		return fmt.Errorf("set timeout: %w", err)
	}

	slog.Info("arp listener started")
	buf := make([]byte, 64)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return fmt.Errorf("recvfrom: %w", err)
		}
		if n < ethHdrLen+arpLen {
			continue
		}

		arp := buf[ethHdrLen:]
		hwType := binary.BigEndian.Uint16(arp[0:2])
		protoType := binary.BigEndian.Uint16(arp[2:4])
		hwLen := arp[4]
		protoLen := arp[5]

		if hwType != 1 || protoType != 0x0800 || hwLen != 6 || protoLen != 4 {
			continue
		}

		senderMAC := net.HardwareAddr(arp[8:14]).String()
		senderIP := net.IPv4(arp[14], arp[15], arp[16], arp[17]).String()

		if senderIP == "0.0.0.0" {
			continue
		}

		l.ch <- discovery.Info{
			MAC:      senderMAC,
			IP:       senderIP,
			Protocol: "arp",
		}
	}
}

func htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}
