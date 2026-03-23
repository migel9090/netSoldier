package mdns

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
)

// Listener passively captures mDNS announcements on the local network
// and extracts hostnames from A/AAAA records.
type Listener struct {
	ch chan<- discovery.Info
}

func NewListener(ch chan<- discovery.Info) *Listener {
	return &Listener{ch: ch}
}

func (l *Listener) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", "224.0.0.251:5353")
	if err != nil {
		return err
	}
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	slog.Info("mdns listener started")
	buf := make([]byte, 4096)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		if src == nil || n < 12 {
			continue
		}

		hostname := extractHostname(buf[:n])
		if hostname == "" {
			continue
		}

		l.ch <- discovery.Info{
			IP:       src.IP.String(),
			Hostname: hostname,
			Protocol: "mdns",
		}
	}
}

// extractHostname parses a DNS packet and returns the first .local hostname
// found in A (type 1) or AAAA (type 28) answer records.
func extractHostname(pkt []byte) string {
	if len(pkt) < 12 {
		return ""
	}

	qdcount := int(binary.BigEndian.Uint16(pkt[4:6]))
	ancount := int(binary.BigEndian.Uint16(pkt[6:8]))
	if ancount == 0 {
		return ""
	}

	offset := 12
	for i := 0; i < qdcount && offset < len(pkt); i++ {
		_, offset = parseDNSName(pkt, offset)
		offset += 4 // QTYPE (2) + QCLASS (2)
	}

	for i := 0; i < ancount && offset+10 < len(pkt); i++ {
		name, newOff := parseDNSName(pkt, offset)
		offset = newOff
		if offset+10 > len(pkt) {
			break
		}
		rtype := binary.BigEndian.Uint16(pkt[offset : offset+2])
		rdlen := binary.BigEndian.Uint16(pkt[offset+8 : offset+10])
		offset += 10 + int(rdlen)

		if (rtype == 1 || rtype == 28) && strings.HasSuffix(name, ".local") {
			host := strings.TrimSuffix(name, ".local")
			if host != "" {
				return host
			}
		}
	}
	return ""
}

func parseDNSName(pkt []byte, offset int) (string, int) {
	var parts []string
	jumped := false
	retOff := 0

	for offset < len(pkt) {
		length := int(pkt[offset])
		if length == 0 {
			if !jumped {
				retOff = offset + 1
			}
			break
		}
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(pkt) {
				break
			}
			if !jumped {
				retOff = offset + 2
				jumped = true
			}
			offset = int(pkt[offset]&0x3F)<<8 | int(pkt[offset+1])
			continue
		}
		offset++
		if offset+length > len(pkt) {
			break
		}
		parts = append(parts, string(pkt[offset:offset+length]))
		offset += length
	}

	if !jumped {
		retOff = offset
	}
	return strings.Join(parts, "."), retOff
}
