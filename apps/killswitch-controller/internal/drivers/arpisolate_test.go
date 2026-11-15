package drivers

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

// The ARP driver needs CAP_NET_RAW and a real interface, so these tests cover
// the parts that are pure logic — target validation and the gateway refusal
// that stands between a bad detection and the whole network going down.

func TestARPParseTargetRejectsBadInput(t *testing.T) {
	d := &ARPIsolateDriver{
		iface:     &net.Interface{Index: 1, HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}},
		gatewayIP: net.IPv4(192, 168, 1, 1).To4(),
	}

	cases := []struct {
		name   string
		action *events.EnforcementAction
	}{
		{"empty IP", &events.EnforcementAction{TargetMAC: "aa:bb:cc:dd:ee:ff"}},
		{"empty MAC", &events.EnforcementAction{TargetIP: "192.168.1.50"}},
		{"garbage IP", &events.EnforcementAction{TargetIP: "not-an-ip", TargetMAC: "aa:bb:cc:dd:ee:ff"}},
		{"garbage MAC", &events.EnforcementAction{TargetIP: "192.168.1.50", TargetMAC: "zz"}},
		{
			// ARP is IPv4-only; an IPv6 target would otherwise be built into
			// a malformed frame.
			"IPv6 target",
			&events.EnforcementAction{TargetIP: "2001:db8::1", TargetMAC: "aa:bb:cc:dd:ee:ff"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := d.parseTarget(tc.action); err == nil {
				t.Error("expected a validation error")
			}
		})
	}

	valid := &events.EnforcementAction{TargetIP: "192.168.1.50", TargetMAC: "aa:bb:cc:dd:ee:ff"}
	ip, mac, err := d.parseTarget(valid)
	if err != nil {
		t.Fatalf("valid target rejected: %v", err)
	}
	if !ip.Equal(net.IPv4(192, 168, 1, 50)) {
		t.Errorf("parsed IP = %v", ip)
	}
	if mac.String() != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("parsed MAC = %v", mac)
	}
}

// TestARPApplyRefusesGateway is the safety property that matters most here.
// Devices often use the router as their DNS forwarder, so household queries
// can appear to come FROM the gateway — one feed match and ARP isolation
// would cut off the default gateway and take the network down.
func TestARPApplyRefusesGateway(t *testing.T) {
	gwMAC := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	var guard TargetGuard
	mustProtect(t, &guard, []string{"192.168.1.1"}, []string{gwMAC.String()})

	d := &ARPIsolateDriver{
		iface:      &net.Interface{Index: 1, HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}},
		gatewayIP:  net.IPv4(192, 168, 1, 1).To4(),
		gatewayMAC: gwMAC,
		guard:      &guard,
		active:     map[string]context.CancelFunc{},
	}

	byIP := &events.EnforcementAction{
		ID: "ACT-1", TargetIP: "192.168.1.1", TargetMAC: "11:22:33:44:55:66",
	}
	if err := d.Apply(context.Background(), byIP); err == nil {
		t.Error("isolating the gateway by IP must be refused")
	}

	byMAC := &events.EnforcementAction{
		ID: "ACT-2", TargetIP: "192.168.1.77", TargetMAC: gwMAC.String(),
	}
	if err := d.Apply(context.Background(), byMAC); err == nil {
		t.Error("isolating the gateway by MAC must be refused")
	}
}

func TestARPApplyRefusesOwnInterface(t *testing.T) {
	sensorMAC := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	d := &ARPIsolateDriver{
		iface:      &net.Interface{Index: 1, HardwareAddr: sensorMAC},
		gatewayIP:  net.IPv4(192, 168, 1, 1).To4(),
		gatewayMAC: net.HardwareAddr{0xaa, 0, 0, 0, 0, 1},
		guard:      &TargetGuard{},
		active:     map[string]context.CancelFunc{},
	}
	action := &events.EnforcementAction{
		ID: "ACT-1", TargetIP: "192.168.1.50", TargetMAC: sensorMAC.String(),
	}
	if err := d.Apply(context.Background(), action); err == nil ||
		!strings.Contains(err.Error(), "sensor's own interface") {
		t.Errorf("isolating the sensor's own interface must be refused, got %v", err)
	}
}

func TestARPRevertUnknownActionIsSafe(t *testing.T) {
	d := &ARPIsolateDriver{
		iface:     &net.Interface{Index: 1, HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}},
		gatewayIP: net.IPv4(192, 168, 1, 1).To4(),
		active:    map[string]context.CancelFunc{},
	}
	// Unparseable target: nothing to restore, and caches expire on their own.
	action := &events.EnforcementAction{ID: "ACT-unknown", TargetIP: "", TargetMAC: ""}
	if err := d.Revert(context.Background(), action); err != nil {
		t.Errorf("revert of an unknown action should be a no-op, got %v", err)
	}
}

func TestNewARPIsolateDriverRequiresGateway(t *testing.T) {
	gw := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	if _, err := NewARPIsolateDriver("lo", nil, gw, &TargetGuard{}); err == nil {
		t.Error("a nil gateway IP must be rejected")
	}
}

// TestNewARPIsolateDriverRequiresPinnedGatewayMAC: the gateway MAC used to
// be read from the neighbour table at start-up. It has to come from
// configuration, and be something that can be one router.
func TestNewARPIsolateDriverRequiresPinnedGatewayMAC(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 1)
	for _, mac := range []net.HardwareAddr{
		nil,
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		{0x01, 0x00, 0x5e, 0x00, 0x00, 0x01},
		{0, 0, 0, 0, 0, 0},
		{0xaa, 0, 0, 0, 0, 1, 2, 3},
	} {
		if _, err := NewARPIsolateDriver("lo", ip, mac, &TargetGuard{}); err == nil ||
			!strings.Contains(err.Error(), "GATEWAY_MAC") {
			t.Errorf("gateway MAC %v: got %v, want a refusal naming GATEWAY_MAC", mac, err)
		}
	}
	if _, err := NewARPIsolateDriver("lo", ip, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, nil); err == nil {
		t.Error("a driver without a guard cannot protect the gateway it knows")
	}
}

// fixedNeighbour stands in for the kernel neighbour table.
type fixedNeighbour struct {
	mac net.HardwareAddr
	err error
}

func (f *fixedNeighbour) lookup(net.IP) (net.HardwareAddr, error) { return f.mac, f.err }

func pinnedDriver(t *testing.T, seen *fixedNeighbour) (*ARPIsolateDriver, *TargetGuard) {
	t.Helper()
	gw := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	var guard TargetGuard
	mustProtect(t, &guard, []string{"192.168.1.1"}, []string{gw.String()})
	return &ARPIsolateDriver{
		iface:          &net.Interface{Index: 1, HardwareAddr: net.HardwareAddr{0x02, 1, 2, 3, 4, 5}},
		gatewayIP:      net.IPv4(192, 168, 1, 1).To4(),
		gatewayMAC:     gw,
		guard:          &guard,
		observeGateway: seen.lookup,
		active:         map[string]context.CancelFunc{},
	}, &guard
}

// TestARPGatewayMACIsNeverLearned is the auditor's spoof: a LAN device
// answers ARP for the gateway IP. The driver used to adopt that MAC as the
// gateway — redirecting its poison and restore frames — and add it to the
// protected set for good, making the impersonator immune to enforcement.
// Now it is an alarm, the driver sends nothing, and nothing is adopted.
func TestARPGatewayMACIsNeverLearned(t *testing.T) {
	attacker := net.HardwareAddr{0x02, 0xde, 0xad, 0xbe, 0xef, 0x01}
	seen := &fixedNeighbour{mac: attacker}
	d, guard := pinnedDriver(t, seen)

	before := counterValue(t, "killswitch_gateway_mac_conflicts_total", nil)
	err := d.Apply(context.Background(), &events.EnforcementAction{
		ID: "ACT-ATT", TargetMAC: "02:00:00:00:00:66", TargetIP: "192.168.1.66"})
	if err == nil || !strings.Contains(err.Error(), "gateway MAC conflict") {
		t.Fatalf("apply during a gateway MAC conflict must refuse to act, got %v", err)
	}
	if got := counterValue(t, "killswitch_gateway_mac_conflicts_total", nil); got != before+1 {
		t.Errorf("conflict not counted: %v → %v", before, got)
	}
	if !bytes.Equal(d.gatewayMAC, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}) {
		t.Errorf("pinned gateway MAC changed to %s", d.gatewayMAC)
	}
	if err := guard.Check(attacker.String(), "192.168.1.66"); err != nil {
		t.Errorf("the impersonator must not become a protected device: %v", err)
	}
	if err := guard.Check("aa:00:00:00:00:01", "192.168.1.66"); err == nil {
		t.Error("the real gateway MAC must stay protected")
	}

	// Revert stops poisoning and withholds restore frames rather than
	// asserting a gateway identity it cannot trust.
	stopped := false
	d.active["ACT-ATT"] = func() { stopped = true }
	if err := d.Revert(context.Background(), &events.EnforcementAction{
		ID: "ACT-ATT", TargetMAC: "02:00:00:00:00:66", TargetIP: "192.168.1.66"}); err != nil {
		t.Fatalf("revert during a conflict: %v", err)
	}
	if !stopped || len(d.active) != 0 {
		t.Error("revert must stop the poison loop even while the gateway is in doubt")
	}
}

func TestARPTrustedGatewayMAC(t *testing.T) {
	pinned := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	for name, seen := range map[string]*fixedNeighbour{
		"agrees":     {mac: pinned},
		"no entry":   {err: errors.New("no ARP entry")},
		"incomplete": {err: errors.New("neighbour entry is incomplete")},
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := pinnedDriver(t, seen)
			got, err := d.trustedGatewayMAC()
			if err != nil || !bytes.Equal(got, pinned) {
				t.Fatalf("got %s, %v; want the pinned MAC: nothing contradicts it", got, err)
			}
		})
	}
	d, _ := pinnedDriver(t, &fixedNeighbour{mac: net.HardwareAddr{0xaa, 0, 0, 0, 0, 2}})
	if _, err := d.trustedGatewayMAC(); err == nil {
		t.Fatal("a different MAC for the gateway IP is a conflict")
	}
}

func TestHtons(t *testing.T) {
	if got := htons(0x0806); got != 0x0608 {
		t.Errorf("htons(0x0806) = %#04x, want 0x0608", got)
	}
}
