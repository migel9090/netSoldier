package drivers

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

const (
	ethPARP   = 0x0806
	ethHdrLen = 14
	arpHdrLen = 28
	arpReply  = 2
)

// ARPIsolateDriver isolates a device at Layer 2 by poisoning its ARP
// cache and the gateway's ARP cache. While active, the target device
// cannot reach the gateway (and vice versa), effectively cutting
// network access.
//
// Safeguards:
//   - Allowlist is enforced by the policy engine before this driver runs
//   - Continuous poisoning stops immediately on Revert (context cancel)
//   - Restore packets are sent on revert to speed up ARP cache recovery
//   - If the controller crashes, ARP caches expire naturally (~30-60s)
//   - Requires CAP_NET_RAW
type ARPIsolateDriver struct {
	iface      *net.Interface
	gatewayIP  net.IP
	gatewayMAC net.HardwareAddr

	mu     sync.Mutex
	active map[string]context.CancelFunc
}

// NewARPIsolateDriver creates a driver for the given interface and gateway.
// gatewayMAC is resolved from the system ARP table or via ARP request.
func NewARPIsolateDriver(ifaceName string, gatewayIP net.IP) (*ARPIsolateDriver, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}

	gwMAC, err := resolveMAC(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway MAC for %s: %w", gatewayIP, err)
	}

	slog.Info("arp-isolate driver ready",
		"interface", ifaceName,
		"gateway_ip", gatewayIP,
		"gateway_mac", gwMAC,
	)

	return &ARPIsolateDriver{
		iface:      iface,
		gatewayIP:  gatewayIP.To4(),
		gatewayMAC: gwMAC,
		active:     make(map[string]context.CancelFunc),
	}, nil
}

func (d *ARPIsolateDriver) Name() string { return "arp_isolate" }

// Apply starts ARP cache poisoning against the target device.
// A background goroutine sends poison packets every 2 seconds until
// Revert is called or the context is cancelled.
func (d *ARPIsolateDriver) Apply(_ context.Context, action *events.EnforcementAction) error {
	targetIP := net.ParseIP(action.TargetIP).To4()
	if targetIP == nil {
		return fmt.Errorf("invalid target IP: %s", action.TargetIP)
	}

	targetMAC, err := net.ParseMAC(action.TargetMAC)
	if err != nil || len(targetMAC) != 6 {
		return fmt.Errorf("invalid target MAC: %s", action.TargetMAC)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPARP)))
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	d.mu.Lock()
	if old, ok := d.active[action.ID]; ok {
		old()
	}
	d.active[action.ID] = cancel
	d.mu.Unlock()

	go d.poisonLoop(ctx, fd, targetIP, targetMAC)

	slog.Info("arp isolation applied",
		"action_id", action.ID,
		"target_ip", action.TargetIP,
		"target_mac", action.TargetMAC,
	)
	return nil
}

// Revert stops the poisoning goroutine and sends correct ARP entries
// to restore connectivity.
func (d *ARPIsolateDriver) Revert(_ context.Context, action *events.EnforcementAction) error {
	d.mu.Lock()
	cancel, ok := d.active[action.ID]
	if ok {
		cancel()
		delete(d.active, action.ID)
	}
	d.mu.Unlock()

	if !ok {
		return nil
	}

	targetIP := net.ParseIP(action.TargetIP).To4()
	targetMAC, _ := net.ParseMAC(action.TargetMAC)
	if targetIP == nil || len(targetMAC) != 6 {
		return nil
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPARP)))
	if err != nil {
		return fmt.Errorf("raw socket for restore: %w", err)
	}
	defer syscall.Close(fd)

	for i := 0; i < 3; i++ {
		d.sendARP(fd, targetMAC, d.gatewayIP, d.gatewayMAC, targetIP)
		d.sendARP(fd, d.gatewayMAC, targetIP, targetMAC, d.gatewayIP)
		time.Sleep(500 * time.Millisecond)
	}

	slog.Info("arp isolation reverted",
		"action_id", action.ID,
		"target_ip", action.TargetIP,
	)
	return nil
}

func (d *ARPIsolateDriver) poisonLoop(ctx context.Context, fd int, targetIP net.IP, targetMAC net.HardwareAddr) {
	defer syscall.Close(fd)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	d.sendPoison(fd, targetIP, targetMAC)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.sendPoison(fd, targetIP, targetMAC)
		}
	}
}

func (d *ARPIsolateDriver) sendPoison(fd int, targetIP net.IP, targetMAC net.HardwareAddr) {
	sensorMAC := d.iface.HardwareAddr

	// Tell target: gateway is at our MAC (poison target → gateway mapping)
	d.sendARP(fd, targetMAC, d.gatewayIP, sensorMAC, targetIP)

	// Tell gateway: target is at our MAC (poison gateway → target mapping)
	d.sendARP(fd, d.gatewayMAC, targetIP, sensorMAC, d.gatewayIP)
}

func (d *ARPIsolateDriver) sendARP(fd int, dstMAC net.HardwareAddr, senderIP net.IP, senderMAC net.HardwareAddr, targetIP net.IP) {
	frame := make([]byte, ethHdrLen+arpHdrLen)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], d.iface.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], ethPARP)

	binary.BigEndian.PutUint16(frame[14:16], 1)      // hw type: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)  // proto type: IPv4
	frame[18] = 6                                      // hw addr len
	frame[19] = 4                                      // proto addr len
	binary.BigEndian.PutUint16(frame[20:22], arpReply) // operation: reply
	copy(frame[22:28], senderMAC)                      // sender MAC
	copy(frame[28:32], senderIP.To4())                 // sender IP
	copy(frame[32:38], dstMAC)                         // target MAC
	copy(frame[38:42], targetIP.To4())                 // target IP

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  d.iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:6], dstMAC)
	syscall.Sendto(fd, frame, 0, &addr)
}

func htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

func resolveMAC(ip net.IP) (net.HardwareAddr, error) {
	// Read the system ARP table
	neighbors, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	_ = neighbors

	// Fallback: parse /proc/net/arp
	return resolveFromProcARP(ip)
}

func resolveFromProcARP(ip net.IP) (net.HardwareAddr, error) {
	data, err := readFile("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/arp: %w", err)
	}

	target := ip.String()
	lines := splitLines(data)
	for _, line := range lines[1:] { // skip header
		fields := splitFields(line)
		if len(fields) >= 4 && fields[0] == target {
			return net.ParseMAC(fields[3])
		}
	}
	return nil, fmt.Errorf("no ARP entry for %s", ip)
}

func readFile(path string) (string, error) {
	b := make([]byte, 4096)
	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)
	n, err := syscall.Read(fd, b)
	if err != nil {
		return "", err
	}
	return string(b[:n]), nil
}

func splitLines(s string) []string {
	var lines []string
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != '\n' {
			i++
		}
		lines = append(lines, s[:i])
		if i < len(s) {
			i++
		}
		s = s[i:]
	}
	return lines
}

func splitFields(s string) []string {
	var fields []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		j := i
		for j < len(s) && s[j] != ' ' && s[j] != '\t' {
			j++
		}
		if j > i {
			fields = append(fields, s[i:j])
		}
		i = j
	}
	return fields
}
