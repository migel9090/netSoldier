package drivers

import (
	"context"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

// counterValue reads one series from the default registry, so tests can
// assert that a refusal path is visible on /metrics.
func counterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	metrics:
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if v, ok := labels[l.GetName()]; ok && v != l.GetValue() {
					continue metrics
				}
			}
			return m.GetCounter().GetValue()
		}
	}
	return 0
}

func mustProtect(t *testing.T, g *TargetGuard, ips, macs []string) {
	t.Helper()
	for _, ip := range ips {
		if err := g.ProtectIP(ip); err != nil {
			t.Fatal(err)
		}
	}
	for _, mac := range macs {
		if err := g.ProtectMAC(mac); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGuardProtectsGatewayAcrossSpellings(t *testing.T) {
	var g TargetGuard
	mustProtect(t, &g, []string{"192.168.1.1"}, []string{"AA:BB:CC:DD:EE:FF"})

	if err := g.Check("02:22:33:44:55:66", "192.168.1.1"); err == nil {
		t.Error("protected IP should be refused")
	}
	for _, spelling := range []string{
		"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", "aabb.ccdd.eeff",
	} {
		if err := g.Check(spelling, "192.168.1.50"); err == nil {
			t.Errorf("protected MAC spelling %q should be refused", spelling)
		}
	}
	if err := g.Check("02:22:33:44:55:66", "192.168.1.50"); err != nil {
		t.Errorf("unprotected device should pass: %v", err)
	}
}

func TestGuardProtectsCIDR(t *testing.T) {
	var g TargetGuard
	mustProtect(t, &g, []string{"10.0.0.0/30"}, nil)

	for _, ip := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.3"} {
		if err := g.Check("02:00:00:00:00:01", ip); err == nil {
			t.Errorf("%s is inside the protected range and should be refused", ip)
		}
	}
	if err := g.Check("02:00:00:00:00:01", "10.0.0.4"); err != nil {
		t.Errorf("10.0.0.4 is outside the range and should pass: %v", err)
	}
}

func TestGuardIPv4In6Equivalence(t *testing.T) {
	var g TargetGuard
	mustProtect(t, &g, []string{"192.168.1.1"}, nil)
	if err := g.Check("02:00:00:00:00:01", "::ffff:192.168.1.1"); err == nil {
		t.Error("IPv4-in-IPv6 form of a protected address should be refused")
	}
}

// TestGuardNilRefuses: a driver built without a guard used to enforce
// against anything.
func TestGuardNilRefuses(t *testing.T) {
	var g *TargetGuard
	before := counterValue(t, "killswitch_guard_refusals_total", map[string]string{"reason": refusedNoGuard})
	if err := g.Check("02:00:00:00:00:01", "10.0.0.1"); err == nil {
		t.Error("a nil guard must refuse, not wave everything through")
	}
	if counterValue(t, "killswitch_guard_refusals_total", map[string]string{"reason": refusedNoGuard}) != before+1 {
		t.Error("refusal not counted")
	}
}

// TestGuardRejectsUnparseableEntries: a protection that silently did
// nothing is the failure the guard exists to prevent.
func TestGuardRejectsUnparseableEntries(t *testing.T) {
	var g TargetGuard
	for _, ip := range []string{"not-an-ip", "", "192.168.001.001", "10.0.0.0/99"} {
		if err := g.ProtectIP(ip); err == nil {
			t.Errorf("ProtectIP(%q) should fail", ip)
		}
	}
	for _, mac := range []string{"not-a-mac", "", "aa bb cc dd ee ff"} {
		if err := g.ProtectMAC(mac); err == nil {
			t.Errorf("ProtectMAC(%q) should fail", mac)
		}
	}
}

// TestGuardFailsClosedOnUnusableTargets is the auditor's probe: each of
// these used to pass the guard because it could not be parsed, and was then
// forwarded verbatim to the switch webhook.
func TestGuardFailsClosedOnUnusableTargets(t *testing.T) {
	var g TargetGuard
	mustProtect(t, &g, []string{"192.168.1.1"}, []string{"aa:bb:cc:dd:ee:ff"})
	sw := newFakeSwitch(t)
	d := NewSwitchPortDriver(sw.srv.URL, 0, "s", &g)

	cases := []struct {
		mac, ip, reason string
	}{
		{"02:00:00:00:00:09", "192.168.001.001", refusedInvalidIdentifier}, // leading zeros
		{"02:00:00:00:00:09", "192.168.1.1/32", refusedInvalidIdentifier},  // CIDR spelling
		{"02:00:00:00:00:09", "0xc0a80101", refusedInvalidIdentifier},      // inet_aton hex
		{"02:00:00:00:00:09", "fe80::1%eth0", refusedInvalidIdentifier},    // zoned
		{"aa bb cc dd ee ff", "192.168.1.50", refusedInvalidIdentifier},    // space-separated
		{"0xaabbccddeeff", "192.168.1.50", refusedInvalidIdentifier},
		{"aa:bb:cc:dd:ee:ff:00:11", "192.168.1.50", refusedInvalidIdentifier}, // EUI-64
		{"", "192.168.001.001", refusedMissingIdentifier},
		{"aa bb cc dd ee ff", "", refusedMissingIdentifier},
		{"", "", refusedMissingIdentifier},                                   // no target at all
		{"aa:bb:cc:dd:ee:ff\t", "192.168.1.50", refusedProtectedDevice},      // trimmed, then protected
		{"02:00:00:00:00:09", " ::ffff:192.168.1.1", refusedProtectedDevice}, // mapped, then protected
	}
	for _, tc := range cases {
		label := map[string]string{"reason": tc.reason}
		before := counterValue(t, "killswitch_guard_refusals_total", label)
		err := d.Apply(context.Background(), &events.EnforcementAction{ID: "X", TargetMAC: tc.mac, TargetIP: tc.ip})
		if err == nil {
			t.Errorf("mac=%q ip=%q: must be refused", tc.mac, tc.ip)
		}
		if got := counterValue(t, "killswitch_guard_refusals_total", label); got != before+1 {
			t.Errorf("mac=%q ip=%q: refusal counted under %q %v→%v", tc.mac, tc.ip, tc.reason, before, got)
		}
	}
	if n := len(sw.calls); n != 0 {
		t.Fatalf("%d webhook calls reached the switch, want 0", n)
	}
}

// TestSwitchSendsTheIdentifiersTheGuardChecked: an adapter that parsed a
// raw string differently from the guard could act on a device the guard
// never compared.
func TestSwitchSendsTheIdentifiersTheGuardChecked(t *testing.T) {
	var g TargetGuard
	sw := newFakeSwitch(t)
	d := NewSwitchPortDriver(sw.srv.URL, 0, "s", &g)
	action := &events.EnforcementAction{ID: "ACT-1", TargetMAC: "02-AA-BB-CC-DD-EE", TargetIP: "::ffff:192.168.1.50"}
	if err := d.Apply(context.Background(), action); err != nil {
		t.Fatal(err)
	}
	if got := sw.last().req; got.TargetMAC != "02:aa:bb:cc:dd:ee" || got.TargetIP != "192.168.1.50" {
		t.Fatalf("webhook got %q / %q, want the canonical forms", got.TargetMAC, got.TargetIP)
	}
	if err := d.Revert(context.Background(), action); err != nil {
		t.Fatal(err)
	}
	if got := sw.last().req; got.Operation != "restore" || got.TargetMAC != "02:aa:bb:cc:dd:ee" || got.TargetIP != "192.168.1.50" {
		t.Fatalf("restore must name the device the way apply did, got %+v", got)
	}
}

func TestGuardVetReturnsCanonicalDevice(t *testing.T) {
	var g TargetGuard
	dev, err := g.Vet(" AABB.CCDD.EEFF ", "2001:DB8::1")
	if err != nil {
		t.Fatal(err)
	}
	if dev.MAC != "aa:bb:cc:dd:ee:ff" || dev.IP != "2001:db8::1" {
		t.Fatalf("Vet = %+v", dev)
	}
	if err := g.Check("02:00:00:00:00:01", "192.168.1.1"); err != nil {
		t.Fatalf("an empty guard protects nothing but still approves well-formed targets: %v", err)
	}
	if err := (&TargetGuard{}).Check("02:00:00:00:00:01", "x"); err == nil || !strings.Contains(err.Error(), "target IP") {
		t.Fatalf("error should say which identifier was refused: %v", err)
	}
}

func TestNormalizeMACKey(t *testing.T) {
	want := "aabbccddeeff"
	for _, in := range []string{
		"aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff",
		"aabb.ccdd.eeff", "AABBCCDDEEFF", "  aa:bb:cc:dd:ee:ff  ",
	} {
		if got := normalizeMACKey(in); got != want {
			t.Errorf("normalizeMACKey(%q) = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "aa:bb", "zz:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff:00"} {
		if got := normalizeMACKey(in); got != "" {
			t.Errorf("normalizeMACKey(%q) = %q, want empty", in, got)
		}
	}
}

// TestGuardRefusesTargetsThatAreNotOneDevice: the ARP driver accepted a
// broadcast or multicast target MAC — which poisons every host on the
// segment — and the MAC 11:22:33:44:55:66 used throughout the tests is
// itself multicast.
func TestGuardRefusesTargetsThatAreNotOneDevice(t *testing.T) {
	var g TargetGuard
	label := map[string]string{"reason": refusedNotUnicast}
	for _, tc := range []struct{ mac, ip string }{
		{"ff:ff:ff:ff:ff:ff", "192.168.1.50"},
		{"01:00:5e:00:00:01", "192.168.1.50"},
		{"33:33:00:00:00:01", "192.168.1.50"},
		{"11:22:33:44:55:66", "192.168.1.50"},
		{"00:00:00:00:00:00", "192.168.1.50"},
		{"02:00:00:00:00:01", "255.255.255.255"},
		{"02:00:00:00:00:01", "0.0.0.0"},
		{"02:00:00:00:00:01", "224.0.0.1"},
		{"02:00:00:00:00:01", "127.0.0.1"},
		{"02:00:00:00:00:01", "::"},
		{"02:00:00:00:00:01", "ff02::1"},
	} {
		before := counterValue(t, "killswitch_guard_refusals_total", label)
		if _, err := g.Vet(tc.mac, tc.ip); err == nil {
			t.Errorf("mac=%s ip=%s must be refused", tc.mac, tc.ip)
		}
		if got := counterValue(t, "killswitch_guard_refusals_total", label); got != before+1 {
			t.Errorf("mac=%s ip=%s: not counted as %s", tc.mac, tc.ip, refusedNotUnicast)
		}
	}
	for _, mac := range []string{"02:00:00:00:00:01", "aa:bb:cc:dd:ee:ff", "00:11:22:33:44:55"} {
		if _, err := g.Vet(mac, "192.168.1.50"); err != nil {
			t.Errorf("unicast %s refused: %v", mac, err)
		}
	}
}
