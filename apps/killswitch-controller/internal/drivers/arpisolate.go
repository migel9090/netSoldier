package drivers

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
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

	poisonInterval = 2 * time.Second
	// gatewayMACTTL bounds how long a resolved gateway MAC is trusted. The
	// address was previously resolved once at startup and kept forever, so
	// after a router reboot that changed its MAC the poison packets went to
	// a stale address (isolation silently stopped working) and the restore
	// packets on revert wrote a WRONG gateway entry into the target's ARP
	// cache — leaving the device broken by the revert.
	gatewayMACTTL = 5 * time.Minute
)

// ARPIsolateDriver isolates a device at Layer 2 by poisoning its ARP
// cache and the gateway's ARP cache. While active, the target device
// cannot reach the gateway (and vice versa), effectively cutting
// network access.
//
// Safeguards:
//   - TargetGuard refuses the gateway and any protected device outright
//   - Every raw send is checked; a failure fails Apply instead of pretending
//     the device is isolated
//   - IP forwarding is checked at startup, because a node with
//     net.ipv4.ip_forward=1 (the default on k3s) would FORWARD the
//     intercepted traffic instead of dropping it — turning an isolation
//     into a silent man-in-the-middle
//   - Continuous poisoning stops immediately on Revert (context cancel)
//   - Restore packets are sent on revert to speed up ARP cache recovery
//   - If the controller crashes, ARP caches expire naturally (~30-60s)
//   - Requires CAP_NET_RAW
type ARPIsolateDriver struct {
	iface     *net.Interface
	gatewayIP net.IP
	guard     *TargetGuard

	mu         sync.Mutex
	gatewayMAC net.HardwareAddr
	gatewayAt  time.Time
	active     map[string]context.CancelFunc
}

// NewARPIsolateDriver creates a driver for the given interface and gateway.
// It fails if the gateway MAC cannot be resolved or CAP_NET_RAW is missing:
// an isolation driver that cannot send is worse than no driver, because the
// caller would be told the device was cut off.
func NewARPIsolateDriver(ifaceName string, gatewayIP net.IP, guard *TargetGuard) (*ARPIsolateDriver, error) {
	if gatewayIP == nil {
		return nil, fmt.Errorf("gateway IP is required")
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifaceName, err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, fmt.Errorf("interface %s has no usable hardware address", ifaceName)
	}

	gwMAC, err := resolveFromProcARP(gatewayIP)
	if err != nil {
		return nil, fmt.Errorf("resolve gateway MAC for %s: %w", gatewayIP, err)
	}

	// Fail fast on a missing capability rather than at the first enforcement.
	fd, err := openARPSocket()
	if err != nil {
		return nil, fmt.Errorf("raw socket unavailable (CAP_NET_RAW?): %w", err)
	}
	_ = syscall.Close(fd)

	if forwarding, err := ipForwardingEnabled(); err == nil && forwarding {
		slog.Warn("net.ipv4.ip_forward=1 on this host: intercepted traffic would be " +
			"FORWARDED to the target, so ARP isolation will not actually isolate and " +
			"the sensor becomes a man-in-the-middle. Disable IP forwarding or use the " +
			"dns_sinkhole / switch_acl drivers instead.")
	}

	d := &ARPIsolateDriver{
		iface:      iface,
		gatewayIP:  gatewayIP.To4(),
		guard:      guard,
		gatewayMAC: gwMAC,
		gatewayAt:  time.Now(),
		active:     make(map[string]context.CancelFunc),
	}
	if d.gatewayIP == nil {
		return nil, fmt.Errorf("gateway IP %s is not IPv4; ARP isolation is IPv4-only", gatewayIP)
	}

	// The gateway must never be a target, whatever the policy says.
	if guard != nil {
		guard.ProtectIP(d.gatewayIP.String())
		guard.ProtectMAC(gwMAC.String())
		guard.ProtectName("default gateway")
	}

	slog.Info("arp-isolate driver ready",
		"interface", ifaceName,
		"gateway_ip", gatewayIP,
		"gateway_mac", gwMAC,
	)
	return d, nil
}

func (d *ARPIsolateDriver) Name() string { return "arp_isolate" }

// Apply starts ARP cache poisoning against the target device.
// A background goroutine sends poison packets every 2 seconds until
// Revert is called or the context is cancelled.
func (d *ARPIsolateDriver) Apply(ctx context.Context, action *events.EnforcementAction) error {
	targetIP, targetMAC, err := d.parseTarget(action)
	if err != nil {
		return err
	}

	// Refuse protected infrastructure before opening a socket.
	if err := d.guard.Check(action.TargetMAC, action.TargetIP); err != nil {
		return err
	}
	if targetIP.Equal(d.gatewayIP) {
		return fmt.Errorf("refusing to isolate the default gateway %s", targetIP)
	}
	if bytes.Equal(targetMAC, d.currentGatewayMAC()) {
		return fmt.Errorf("refusing to isolate the default gateway MAC %s", targetMAC)
	}
	if bytes.Equal(targetMAC, d.iface.HardwareAddr) {
		return fmt.Errorf("refusing to isolate the sensor's own interface %s", targetMAC)
	}

	gwMAC, err := d.gatewayHardwareAddr()
	if err != nil {
		return fmt.Errorf("gateway MAC unavailable: %w", err)
	}

	fd, err := openARPSocket()
	if err != nil {
		return fmt.Errorf("raw socket: %w", err)
	}

	// Send the first pair synchronously so a failure is reported to the
	// caller. Previously every send error was discarded, Apply returned nil,
	// and the action was marked active — the operator saw "isolated" while
	// not a single packet had left the host.
	if err := d.sendPoison(fd, targetIP, targetMAC, gwMAC); err != nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("initial poison failed: %w", err)
	}

	// Derive from context.Background(): the poison loop must outlive the
	// HTTP request that started it, and is stopped by Revert.
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))

	d.mu.Lock()
	if old, ok := d.active[action.ID]; ok {
		old()
	}
	d.active[action.ID] = cancel
	d.mu.Unlock()

	go d.poisonLoop(loopCtx, fd, targetIP, targetMAC)

	slog.Info("arp isolation applied",
		"action_id", action.ID,
		"target_ip", action.TargetIP,
		"target_mac", action.TargetMAC,
	)
	return nil
}

// Revert stops the poisoning goroutine and sends correct ARP entries
// to restore connectivity. It reports an error if the restore packets could
// not be sent, so the caller does not mark the action reverted while the
// target's ARP cache still points at the sensor.
func (d *ARPIsolateDriver) Revert(ctx context.Context, action *events.EnforcementAction) error {
	d.mu.Lock()
	cancel, wasActive := d.active[action.ID]
	if wasActive {
		cancel()
		delete(d.active, action.ID)
	}
	d.mu.Unlock()

	targetIP, targetMAC, err := d.parseTarget(action)
	if err != nil {
		// Nothing we can restore; the poison loop (if any) is already stopped
		// and caches expire on their own within ~60s.
		slog.Warn("arp revert: unparseable target, relying on ARP cache expiry",
			"action_id", action.ID, "error", err)
		return nil
	}

	gwMAC, err := d.gatewayHardwareAddr()
	if err != nil {
		return fmt.Errorf("gateway MAC unavailable for restore: %w", err)
	}

	fd, err := openARPSocket()
	if err != nil {
		return fmt.Errorf("raw socket for restore: %w", err)
	}
	defer syscall.Close(fd)

	// Three rounds of corrective ARP, honouring the caller's deadline.
	var lastErr error
	for i := 0; i < 3; i++ {
		if err := d.sendARP(fd, targetMAC, d.gatewayIP, gwMAC, targetIP); err != nil {
			lastErr = err
		}
		if err := d.sendARP(fd, gwMAC, targetIP, targetMAC, d.gatewayIP); err != nil {
			lastErr = err
		}
		if i == 2 {
			break
		}
		select {
		case <-ctx.Done():
			// Poisoning has stopped, which is the part that matters; the
			// caches will time out shortly.
			slog.Warn("arp revert interrupted after stopping poisoning",
				"action_id", action.ID, "error", ctx.Err())
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
	if lastErr != nil {
		return fmt.Errorf("restore ARP send failed: %w", lastErr)
	}

	slog.Info("arp isolation reverted",
		"action_id", action.ID,
		"target_ip", action.TargetIP,
	)
	return nil
}

func (d *ARPIsolateDriver) parseTarget(action *events.EnforcementAction) (net.IP, net.HardwareAddr, error) {
	targetIP := net.ParseIP(action.TargetIP)
	if targetIP == nil || targetIP.To4() == nil {
		return nil, nil, fmt.Errorf("invalid IPv4 target IP: %q", action.TargetIP)
	}
	targetMAC, err := net.ParseMAC(action.TargetMAC)
	if err != nil || len(targetMAC) != 6 {
		return nil, nil, fmt.Errorf("invalid target MAC: %q", action.TargetMAC)
	}
	return targetIP.To4(), targetMAC, nil
}

// gatewayHardwareAddr returns a fresh-enough gateway MAC, re-resolving it
// when the cached value has aged out.
func (d *ARPIsolateDriver) gatewayHardwareAddr() (net.HardwareAddr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if time.Since(d.gatewayAt) < gatewayMACTTL && len(d.gatewayMAC) == 6 {
		return d.gatewayMAC, nil
	}
	mac, err := resolveFromProcARP(d.gatewayIP)
	if err != nil {
		if len(d.gatewayMAC) == 6 {
			// Keep using the last known value rather than failing closed on
			// a transient empty neighbour table, but say so.
			slog.Warn("gateway MAC re-resolution failed, using cached value",
				"gateway_ip", d.gatewayIP, "age", time.Since(d.gatewayAt), "error", err)
			return d.gatewayMAC, nil
		}
		return nil, err
	}
	if !bytes.Equal(mac, d.gatewayMAC) {
		slog.Warn("gateway MAC changed", "old", d.gatewayMAC, "new", mac)
		if d.guard != nil {
			d.guard.ProtectMAC(mac.String())
		}
	}
	d.gatewayMAC = mac
	d.gatewayAt = time.Now()
	return mac, nil
}

func (d *ARPIsolateDriver) currentGatewayMAC() net.HardwareAddr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gatewayMAC
}

func (d *ARPIsolateDriver) poisonLoop(ctx context.Context, fd int, targetIP net.IP, targetMAC net.HardwareAddr) {
	defer syscall.Close(fd)

	ticker := time.NewTicker(poisonInterval)
	defer ticker.Stop()

	consecutiveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gwMAC, err := d.gatewayHardwareAddr()
			if err != nil {
				slog.Error("poison loop: gateway MAC unavailable", "error", err)
				continue
			}
			if err := d.sendPoison(fd, targetIP, targetMAC, gwMAC); err != nil {
				consecutiveFailures++
				// Log every failure but escalate wording once it is clearly
				// not transient: the enforcement has effectively stopped.
				if consecutiveFailures >= 3 {
					slog.Error("arp poisoning has stopped working — device is likely NOT isolated",
						"target_ip", targetIP, "failures", consecutiveFailures, "error", err)
				} else {
					slog.Warn("arp poison send failed", "target_ip", targetIP, "error", err)
				}
				continue
			}
			consecutiveFailures = 0
		}
	}
}

func (d *ARPIsolateDriver) sendPoison(fd int, targetIP net.IP, targetMAC, gatewayMAC net.HardwareAddr) error {
	sensorMAC := d.iface.HardwareAddr

	// Tell target: gateway is at our MAC (poison target → gateway mapping)
	if err := d.sendARP(fd, targetMAC, d.gatewayIP, sensorMAC, targetIP); err != nil {
		return fmt.Errorf("poison target: %w", err)
	}
	// Tell gateway: target is at our MAC (poison gateway → target mapping)
	if err := d.sendARP(fd, gatewayMAC, targetIP, sensorMAC, d.gatewayIP); err != nil {
		return fmt.Errorf("poison gateway: %w", err)
	}
	return nil
}

func (d *ARPIsolateDriver) sendARP(fd int, dstMAC net.HardwareAddr, senderIP net.IP,
	senderMAC net.HardwareAddr, targetIP net.IP) error {
	sender4 := senderIP.To4()
	target4 := targetIP.To4()
	if sender4 == nil || target4 == nil {
		return fmt.Errorf("ARP requires IPv4 addresses")
	}
	if len(dstMAC) != 6 || len(senderMAC) != 6 {
		return fmt.Errorf("ARP requires 6-byte hardware addresses")
	}

	frame := make([]byte, ethHdrLen+arpHdrLen)

	copy(frame[0:6], dstMAC)
	copy(frame[6:12], d.iface.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:14], ethPARP)

	binary.BigEndian.PutUint16(frame[14:16], 1)        // hw type: Ethernet
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)   // proto type: IPv4
	frame[18] = 6                                      // hw addr len
	frame[19] = 4                                      // proto addr len
	binary.BigEndian.PutUint16(frame[20:22], arpReply) // operation: reply
	copy(frame[22:28], senderMAC)                      // sender MAC
	copy(frame[28:32], sender4)                        // sender IP
	copy(frame[32:38], dstMAC)                         // target MAC
	copy(frame[38:42], target4)                        // target IP

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  d.iface.Index,
		Halen:    6,
	}
	copy(addr.Addr[:6], dstMAC)

	if err := syscall.Sendto(fd, frame, 0, &addr); err != nil {
		return fmt.Errorf("sendto %s: %w", dstMAC, err)
	}
	return nil
}

func openARPSocket() (int, error) {
	return syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPARP)))
}

func htons(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

// ipForwardingEnabled reports whether the kernel routes between interfaces,
// which would defeat ARP-based isolation.
func ipForwardingEnabled() (bool, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(b)) == "1", nil
}

// resolveFromProcARP looks the address up in the kernel neighbour table.
// It reads the WHOLE file: a fixed 4 KiB buffer held roughly 58 entries, so on
// a busier network the gateway's row could fall outside it and the driver
// would fail to initialise for no real reason.
func resolveFromProcARP(ip net.IP) (net.HardwareAddr, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("read /proc/net/arp: %w", err)
	}

	target := ip.String()
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] { // skip header
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == target {
			mac, err := net.ParseMAC(fields[3])
			if err != nil {
				return nil, fmt.Errorf("neighbour entry for %s has invalid MAC %q: %w",
					target, fields[3], err)
			}
			// 00:00:00:00:00:00 means "incomplete" — an unresolved entry is
			// not an answer, and poisoning towards it does nothing.
			if mac.String() == "00:00:00:00:00:00" {
				return nil, fmt.Errorf("neighbour entry for %s is incomplete", target)
			}
			return mac, nil
		}
	}
	return nil, fmt.Errorf("no ARP entry for %s (is the host reachable?)", ip)
}
