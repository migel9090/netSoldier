package arp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/capture"
)

// maxScanHostBits bounds the subnet the scanner sweeps: a /16 is 65,534
// requests, about five minutes at the sweep pace. Anything wider is a
// configuration mistake, and enumerating it would allocate gigabytes.
const maxScanHostBits = 16

// Scanner sends ARP WHO-HAS requests for each IP in a subnet.
// Replies are captured by the passive Listener running in parallel.
// Requires CAP_NET_RAW.
type Scanner struct {
	subnet   *net.IPNet
	iface    *net.Interface
	localIP  net.IP
	interval time.Duration
}

// NewScanner creates an active ARP scanner for the given CIDR subnet.
// interval controls how long to wait between full scans.
func NewScanner(cidr string, interval time.Duration) (*Scanner, error) {
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse CIDR: %w", err)
	}
	ones, bits := subnet.Mask.Size()
	if bits != 32 || bits-ones > maxScanHostBits {
		return nil, fmt.Errorf("subnet %s: only IPv4 subnets of /%d or smaller can be scanned", cidr, 32-maxScanHostBits)
	}
	if interval <= 0 {
		return nil, fmt.Errorf("scan interval must be positive, got %s", interval)
	}

	iface, ip, err := findInterface(subnet)
	if err != nil {
		return nil, fmt.Errorf("find interface: %w", err)
	}

	return &Scanner{
		subnet:   subnet,
		iface:    iface,
		localIP:  ip,
		interval: interval,
	}, nil
}

// FrameSender transmits one complete Ethernet frame. The scanner only builds
// requests; how they reach the wire (a local AF_PACKET socket today) is
// behind this interface.
type FrameSender interface {
	Send(frame []byte) error
}

// Run sweeps the subnet every interval until ctx is done. The socket only
// transmits; replies arrive on the passive Listener's socket.
func (s *Scanner) Run(ctx context.Context, up func()) error {
	sender, err := capture.OpenSender(s.iface)
	if err != nil {
		return err
	}
	defer sender.Close()
	up()

	slog.Info("arp scanner started", "subnet", s.subnet, "iface", s.iface.Name, "interval", s.interval)

	for {
		if err := s.sweep(ctx, sender); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.interval):
		}
	}
}

func (s *Scanner) sweep(ctx context.Context, sender FrameSender) error {
	ips := subnetIPs(s.subnet)
	slog.Debug("arp scan starting", "hosts", len(ips))

	failed := 0
	var lastErr error
	for _, ip := range ips {
		if ctx.Err() != nil {
			return nil
		}
		if err := sender.Send(s.request(ip)); err != nil {
			failed++
			lastErr = err
		}
		time.Sleep(5 * time.Millisecond)
	}
	if failed > 0 && failed == len(ips) {
		return fmt.Errorf("every ARP request in the sweep failed: %w", lastErr)
	}
	if failed > 0 {
		slog.Warn("arp scan: some requests failed", "failed", failed, "of", len(ips), "error", lastErr)
	}
	return nil
}

// request builds a broadcast WHO-HAS for targetIP from this host.
func (s *Scanner) request(targetIP net.IP) []byte {
	frame := make([]byte, ethHdrLen+arpLen)

	// Ethernet header
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // broadcast
	copy(frame[6:12], s.iface.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], ethPARP)

	// ARP header
	binary.BigEndian.PutUint16(frame[14:16], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800) // protocol type: IPv4
	frame[18] = 6                                    // hardware addr len
	frame[19] = 4                                    // protocol addr len
	binary.BigEndian.PutUint16(frame[20:22], 1)      // operation: request
	copy(frame[22:28], s.iface.HardwareAddr)         // sender MAC
	copy(frame[28:32], s.localIP.To4())              // sender IP
	// frame[32:38] target MAC stays zero
	copy(frame[38:42], targetIP.To4()) // target IP
	return frame
}

func findInterface(subnet *net.IPNet) (*net.Interface, net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ip := ipnet.IP.To4(); ip != nil && subnet.Contains(ip) {
				return &iface, ip, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no interface in %s", subnet)
}

func subnetIPs(subnet *net.IPNet) []net.IP {
	var ips []net.IP
	ip := make(net.IP, 4)
	copy(ip, subnet.IP.To4())

	for inc(ip); subnet.Contains(ip); inc(ip) {
		out := make(net.IP, 4)
		copy(out, ip)
		ips = append(ips, out)
	}
	if len(ips) > 1 {
		ips = ips[:len(ips)-1] // exclude broadcast
	}
	return ips
}

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
