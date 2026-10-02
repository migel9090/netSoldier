package drivers

import (
	"context"
	"net"
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
	guard.ProtectIP("192.168.1.1")
	guard.ProtectMAC(gwMAC.String())

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
		active:     map[string]context.CancelFunc{},
	}
	action := &events.EnforcementAction{
		ID: "ACT-1", TargetIP: "192.168.1.50", TargetMAC: sensorMAC.String(),
	}
	if err := d.Apply(context.Background(), action); err == nil {
		t.Error("isolating the sensor's own interface must be refused")
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
	if _, err := NewARPIsolateDriver("lo", nil, nil); err == nil {
		t.Error("a nil gateway IP must be rejected")
	}
}

func TestHtons(t *testing.T) {
	if got := htons(0x0806); got != 0x0608 {
		t.Errorf("htons(0x0806) = %#04x, want 0x0608", got)
	}
}
