package dhcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"syscall"
)

const (
	minPacketLen = 244
	magicCookie  = 0x63825363

	opBootRequest = 1

	optPad         = 0
	optEnd         = 255
	optHostName    = 12
	optRequestedIP = 50
	optPRL         = 55
	optVendorClass = 60
)

type DeviceInfo struct {
	MAC         string
	IP          string
	Hostname    string
	Fingerprint string // Option 55: comma-separated codes in request order
	VendorClass string // Option 60
}

type Listener struct {
	ch chan<- DeviceInfo
}

func NewListener(ch chan<- DeviceInfo) *Listener {
	return &Listener{ch: ch}
}

func (l *Listener) Run(ctx context.Context) error {
	lc := net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var err error
			cerr := c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if cerr != nil {
				return cerr
			}
			return err
		},
	}

	conn, err := lc.ListenPacket(ctx, "udp4", ":67")
	if err != nil {
		return fmt.Errorf("listen udp:67: %w", err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	slog.Info("dhcp listener started", "port", 67)
	buf := make([]byte, 1500)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("dhcp read error", "error", err)
			continue
		}

		info, err := parsePacket(buf[:n])
		if err != nil {
			slog.Debug("dhcp parse skipped", "error", err)
			continue
		}

		select {
		case l.ch <- info:
		case <-ctx.Done():
			return nil
		}
	}
}

func parsePacket(data []byte) (DeviceInfo, error) {
	if len(data) < minPacketLen {
		return DeviceInfo{}, fmt.Errorf("packet too short: %d", len(data))
	}

	if data[0] != opBootRequest {
		return DeviceInfo{}, fmt.Errorf("not a client request (op=%d)", data[0])
	}

	cookie := binary.BigEndian.Uint32(data[236:240])
	if cookie != magicCookie {
		return DeviceInfo{}, fmt.Errorf("bad magic cookie: %08x", cookie)
	}

	hlen := int(data[2])
	if hlen < 1 || hlen > 16 {
		hlen = 6
	}

	mac := make(net.HardwareAddr, hlen)
	copy(mac, data[28:28+hlen])
	ciaddr := net.IP(data[12:16])

	opts := parseOptions(data[240:])

	info := DeviceInfo{MAC: mac.String()}

	if ip, ok := opts[optRequestedIP]; ok && len(ip) == 4 {
		info.IP = net.IP(ip).String()
	} else if !ciaddr.IsUnspecified() {
		info.IP = ciaddr.String()
	}

	if hn, ok := opts[optHostName]; ok {
		info.Hostname = string(hn)
	}

	if prl, ok := opts[optPRL]; ok && len(prl) > 0 {
		parts := make([]string, len(prl))
		for i, b := range prl {
			parts[i] = fmt.Sprintf("%d", b)
		}
		info.Fingerprint = strings.Join(parts, ",")
	}

	if vc, ok := opts[optVendorClass]; ok {
		info.VendorClass = string(vc)
	}

	return info, nil
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
		val := make([]byte, length)
		copy(val, data[i+2:i+2+length])
		opts[code] = val
		i += 2 + length
	}
	return opts
}
