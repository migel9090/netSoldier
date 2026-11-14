package dhcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/capture"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
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

// serverPortFilter is classic BPF for "ip and udp dst port 67 and not a
// fragment", the equivalent of tcpdump's `udp dst port 67` for IPv4. Without
// it the AF_PACKET socket would copy every IPv4 frame on the interface to
// user space.
var serverPortFilter = []unix.SockFilter{
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 12},                        // 0: A = EtherType
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 8, K: ethPIPv4},   // 1
	{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 23},                        // 2: A = IP protocol
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 6, K: 17},         // 3: UDP
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 20},                        // 4: A = flags + fragment offset
	{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, Jt: 4, Jf: 0, K: 0x1fff},    // 5: non-first fragment
	{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 14},                       // 6: X = IP header length
	{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 16},                        // 7: A = UDP destination port
	{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: serverPort}, // 8
	{Code: unix.BPF_RET | unix.BPF_K, K: 0x40000},                                 // 9: accept
	{Code: unix.BPF_RET | unix.BPF_K, K: 0},                                       // 10: drop
}

// Listener passively captures DHCP client messages on one interface.
//
// It reads Ethernet frames rather than binding UDP port 67: only the frame
// shows who actually sent a message, so the client hardware address it
// claims can be checked against the Ethernet source, and a raw socket does
// not compete with a DHCP server running on the same host. Requires
// CAP_NET_RAW.
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
	conn, err := capture.OpenPacket(ifi, ethPIPv4, serverPortFilter)
	if err != nil {
		return err
	}
	defer conn.Close()
	up()

	buf := make([]byte, 1600)
	for ctx.Err() == nil {
		n, err := conn.Read(buf)
		if errors.Is(err, capture.ErrTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		metrics.FramesReceived.WithLabelValues("dhcp").Inc()
		s, err := ParseFrame(buf[:n])
		if err != nil {
			l.reject(buf[:n], err)
			continue
		}
		metrics.DHCPPackets.Inc()
		select {
		case l.ch <- s:
		case <-ctx.Done():
		}
	}
	return nil
}

func (l *Listener) reject(frame []byte, err error) {
	metrics.FramesRejected.WithLabelValues("dhcp", discovery.RejectReason(err)).Inc()
	if !errors.Is(err, discovery.ErrLinkMismatch) {
		slog.Debug("dhcp frame skipped", "error", err)
		return
	}
	if ok, suppressed := l.mismatch.Allow(time.Now()); ok {
		slog.Warn("dhcp chaddr does not match its link-layer source; ignored",
			"eth_src", net.HardwareAddr(frame[6:12]).String(), "error", err,
			"suppressed_since_last", suppressed)
	}
}

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
