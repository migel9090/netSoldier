package drivers

import (
	"context"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

// TestARPGatewayPinnedInNamespace runs the gateway-trust path against the
// real kernel neighbour table and a real raw socket, so it only runs inside
// a throwaway user+network namespace where the frames cannot leave:
//
//	go test -c -o drivers.test ./internal/drivers
//	unshare -Urn env KILLSWITCH_ARP_NETNS_TEST=1 ./drivers.test -test.run TestARPGatewayPinnedInNamespace -test.v
//
// It refuses to run if it sees any interface it did not create.
func TestARPGatewayPinnedInNamespace(t *testing.T) {
	if os.Getenv("KILLSWITCH_ARP_NETNS_TEST") != "1" {
		t.Skip("namespace-only: run under `unshare -Urn` with KILLSWITCH_ARP_NETNS_TEST=1")
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifaces {
		if i.Name != "lo" && i.Name != "veth0" && i.Name != "veth1" {
			t.Fatalf("refusing to run: interface %q exists, this is not a throwaway network namespace", i.Name)
		}
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %s: %v %s", strings.Join(args, " "), err, out)
		}
	}
	if len(ifaces) == 1 {
		ip("link", "set", "lo", "up")
		ip("link", "add", "veth0", "type", "veth", "peer", "name", "veth1")
		ip("addr", "add", "192.168.77.10/24", "dev", "veth0")
		ip("link", "set", "veth0", "up")
		ip("link", "set", "veth1", "up")
	}

	gwIP := net.IPv4(192, 168, 77, 1)
	gwMAC := net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}
	const attacker = "02:de:ad:be:ef:01"
	setGatewayNeighbour := func(mac string) {
		ip("neigh", "replace", gwIP.String(), "lladdr", mac, "dev", "veth0", "nud", "reachable")
	}
	setGatewayNeighbour(gwMAC.String())

	var guard TargetGuard
	d, err := NewARPIsolateDriver("veth0", gwIP, gwMAC, &guard)
	if err != nil {
		t.Fatalf("driver: %v", err)
	}
	peer, err := net.InterfaceByName("veth1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	victim := &events.EnforcementAction{ID: "ACT-NS-1", TargetIP: "192.168.77.50", TargetMAC: peer.HardwareAddr.String()}
	if err := d.Apply(ctx, victim); err != nil {
		t.Fatalf("with the neighbour table agreeing, apply should work: %v", err)
	}
	if err := d.Revert(ctx, victim); err != nil {
		t.Fatalf("revert: %v", err)
	}

	// A LAN device answers for the gateway IP: the sensor's neighbour entry
	// now points at it, exactly as a forged ARP reply would leave it.
	setGatewayNeighbour(attacker)
	before := counterValue(t, "killswitch_gateway_mac_conflicts_total", nil)
	err = d.Apply(ctx, &events.EnforcementAction{ID: "ACT-NS-2", TargetIP: "192.168.77.66", TargetMAC: attacker})
	if err == nil || !strings.Contains(err.Error(), "gateway MAC conflict") {
		t.Fatalf("apply during a spoof must refuse to act, got %v", err)
	}
	if counterValue(t, "killswitch_gateway_mac_conflicts_total", nil) <= before {
		t.Error("the conflict must be counted")
	}
	if err := guard.Check(attacker, "192.168.77.66"); err != nil {
		t.Errorf("the impersonator must not have become a protected device: %v", err)
	}
	if err := guard.Check(gwMAC.String(), "192.168.77.66"); err == nil {
		t.Error("the pinned gateway MAC must stay protected")
	}

	// Once the table agrees with the configuration again, the driver acts.
	setGatewayNeighbour(gwMAC.String())
	victim.ID = "ACT-NS-3"
	if err := d.Apply(ctx, victim); err != nil {
		t.Fatalf("after the conflict cleared: %v", err)
	}
	if err := d.Revert(ctx, victim); err != nil {
		t.Fatalf("revert: %v", err)
	}
}
