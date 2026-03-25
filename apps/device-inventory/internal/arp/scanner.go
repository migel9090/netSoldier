package arp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"
)

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

func (s *Scanner) Run(ctx context.Context) error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPARP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}
	defer syscall.Close(fd)

	slog.Info("arp scanner started", "subnet", s.subnet, "iface", s.iface.Name, "interval", s.interval)

	for {
		s.sweep(fd)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.interval):
		}
	}
}

func (s *Scanner) sweep(fd int) {
	ips := subnetIPs(s.subnet)
	slog.Debug("arp scan starting", "hosts", len(ips))

	for _, ip := range ips {
		if err := s.sendRequest(fd, ip); err != nil {
			slog.Debug("arp send failed", "target", ip, "error", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *Scanner) sendRequest(fd int, targetIP net.IP) error {
	frame := make([]byte, ethHdrLen+arpLen)

	// Ethernet header
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}) // broadcast
	copy(frame[6:12], s.iface.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], ethPARP)

	// ARP header
	binary.BigEndian.PutUint16(frame[14:16], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)  // protocol type: IPv4
	frame[18] = 6                                      // hardware addr len
	frame[19] = 4                                      // protocol addr len
	binary.BigEndian.PutUint16(frame[20:22], 1)       // operation: request
	copy(frame[22:28], s.iface.HardwareAddr)           // sender MAC
	copy(frame[28:32], s.localIP.To4())                // sender IP
	// frame[32:38] target MAC stays zero
	copy(frame[38:42], targetIP.To4())                 // target IP

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  s.iface.Index,
		Halen:    6,
		Addr:     [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
	return syscall.Sendto(fd, frame, 0, &addr)
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
