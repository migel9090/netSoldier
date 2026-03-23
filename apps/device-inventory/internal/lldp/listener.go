package lldp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

const (
	ethPLLDP    = 0x88CC
	ethHdrLen   = 14
	tlvEnd      = 0
	tlvChassis  = 1
	tlvSysName  = 5
	tlvSysDesc  = 6
	tlvMgmtAddr = 8

	chassisSubMAC = 4
)

// Listener passively captures LLDP frames on the local network and
// extracts system name, chassis MAC, and system description.
// Requires CAP_NET_RAW.
type Listener struct {
	ch chan<- discovery.Info
}

func NewListener(ch chan<- discovery.Info) *Listener {
	return &Listener{ch: ch}
}

func (l *Listener) Run(ctx context.Context) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPLLDP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)

	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 2}); err != nil {
		return fmt.Errorf("set timeout: %w", err)
	}

	slog.Info("lldp listener started")
	buf := make([]byte, 1518)

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
		if n <= ethHdrLen {
			continue
		}

		srcMAC := net.HardwareAddr(buf[6:12]).String()
		info := parseLLDP(buf[ethHdrLen:n])
		if info.Hostname == "" && info.Meta == "" {
			continue
		}
		info.MAC = srcMAC
		info.Protocol = "lldp"

		l.ch <- info
	}
}

func parseLLDP(data []byte) discovery.Info {
	var info discovery.Info
	offset := 0

	for offset+2 <= len(data) {
		header := binary.BigEndian.Uint16(data[offset : offset+2])
		tlvType := int(header >> 9)
		tlvLen := int(header & 0x01FF)
		offset += 2

		if tlvType == tlvEnd || offset+tlvLen > len(data) {
			break
		}

		value := data[offset : offset+tlvLen]
		switch tlvType {
		case tlvChassis:
			if tlvLen >= 7 && value[0] == chassisSubMAC {
				info.MAC = net.HardwareAddr(value[1:7]).String()
			}
		case tlvSysName:
			info.Hostname = string(value)
		case tlvSysDesc:
			info.Meta = string(value)
		case tlvMgmtAddr:
			if ip := parseMgmtAddr(value); ip != "" {
				info.IP = ip
			}
		}
		offset += tlvLen
	}
	return info
}

func parseMgmtAddr(value []byte) string {
	if len(value) < 6 {
		return ""
	}
	addrLen := int(value[0])
	subtype := value[1]
	if subtype == 1 && addrLen == 5 && len(value) >= 6 {
		return net.IPv4(value[2], value[3], value[4], value[5]).String()
	}
	return ""
}

func htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

// SetReadDeadline is unused but kept for documentation: raw sockets use
// SO_RCVTIMEO set in Run() instead of per-read deadlines.
func init() {
	_ = time.Second
}
