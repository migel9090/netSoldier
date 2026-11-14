package dhcpfp

import "testing"

func TestLookup(t *testing.T) {
	cases := []struct {
		fp, vc   string
		os, kind string
	}{
		{"", "android-dhcp-14", "Android", "phone"},
		{"", "MSFT 5.0", "Windows", "desktop"},
		{"", "dhcpcd-9.4.1:Linux-6.1.21-v8+:aarch64:BCM2835", "Linux", "desktop"},
		{"", "udhcp 1.36.1", "Linux", "iot"},
		{"", "Roku/DVP-9.10", "Roku OS", "tv"},
		{"", "PS5", "PlayStation", "console"},
		{"1,121,3,6,15,119,252", "", "iOS", "phone"},
		{"1,3,6,15,26,28,51,58,59,43", "", "Android", "phone"},
		// The vendor class wins over the fingerprint.
		{"1,121,3,6,15,119,252", "MSFT 5.0", "Windows", "desktop"},
	}
	for _, c := range cases {
		p := Lookup(c.fp, c.vc)
		if p == nil || p.OS != c.os || p.DeviceType != c.kind {
			t.Errorf("Lookup(%q, %q) = %+v, want %s/%s", c.fp, c.vc, p, c.os, c.kind)
		}
	}
	for _, c := range [][2]string{{"", ""}, {"9,9,9", ""}, {"", "something-unknown"}} {
		if p := Lookup(c[0], c[1]); p != nil {
			t.Errorf("Lookup(%q, %q) = %+v, want nil", c[0], c[1], p)
		}
	}
	// Results are copies: a caller cannot corrupt the table.
	p := Lookup("1,3,6", "")
	p.OS = "tampered"
	if Lookup("1,3,6", "").OS == "tampered" {
		t.Error("Lookup returned a pointer into the table")
	}
}

func FuzzLookup(f *testing.F) {
	f.Add("1,3,6,15", "MSFT 5.0")
	f.Fuzz(func(t *testing.T, fp, vc string) { _ = Lookup(fp, vc) })
}
