package drivers

import "testing"

func TestGuardProtectsGatewayAcrossSpellings(t *testing.T) {
	var g TargetGuard
	g.ProtectIP("192.168.1.1")
	g.ProtectMAC("AA:BB:CC:DD:EE:FF")

	if err := g.Check("", "192.168.1.1"); err == nil {
		t.Error("protected IP should be refused")
	}
	for _, spelling := range []string{
		"aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff",
	} {
		if err := g.Check(spelling, ""); err == nil {
			t.Errorf("protected MAC spelling %q should be refused", spelling)
		}
	}
	if err := g.Check("11:22:33:44:55:66", "192.168.1.50"); err != nil {
		t.Errorf("unprotected device should pass: %v", err)
	}
}

func TestGuardProtectsCIDR(t *testing.T) {
	var g TargetGuard
	g.ProtectIP("10.0.0.0/30")

	for _, ip := range []string{"10.0.0.0", "10.0.0.1", "10.0.0.3"} {
		if err := g.Check("", ip); err == nil {
			t.Errorf("%s is inside the protected range and should be refused", ip)
		}
	}
	if err := g.Check("", "10.0.0.4"); err != nil {
		t.Errorf("10.0.0.4 is outside the range and should pass: %v", err)
	}
}

func TestGuardIPv4In6Equivalence(t *testing.T) {
	var g TargetGuard
	g.ProtectIP("192.168.1.1")
	if err := g.Check("", "::ffff:192.168.1.1"); err == nil {
		t.Error("IPv4-in-IPv6 form of a protected address should be refused")
	}
}

func TestGuardNilIsPermissive(t *testing.T) {
	var g *TargetGuard
	if err := g.Check("aa:bb:cc:dd:ee:ff", "10.0.0.1"); err != nil {
		t.Errorf("nil guard should not block: %v", err)
	}
}

func TestGuardIgnoresUnparseableEntries(t *testing.T) {
	var g TargetGuard
	g.ProtectIP("not-an-ip")
	g.ProtectMAC("not-a-mac")
	if err := g.Check("aa:bb:cc:dd:ee:ff", "10.0.0.1"); err != nil {
		t.Errorf("garbage entries should not protect unrelated devices: %v", err)
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
