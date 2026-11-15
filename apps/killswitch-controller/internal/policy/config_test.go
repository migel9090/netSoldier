package policy

import (
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

// TestAllowlistTypoRefusesToStart: a typo in the router's MAC was a log
// line; the service started with the router unprotected and auto-block on.
// It must not start, and the error must name every bad entry.
func TestAllowlistTypoRefusesToStart(t *testing.T) {
	t.Setenv("ALLOWLIST_MACS", "aa:bb:cc:dd:ee:fg")
	t.Setenv("ALLOWLIST_IPS", "192.168.1.53,192.168.1.1-192.168.1.5")

	p, err := LoadFromEnv()
	if err == nil {
		t.Fatalf("a rejected allowlist entry must stop the service, got policy %+v", p)
	}
	for _, want := range []string{`ALLOWLIST_MACS entry "aa:bb:cc:dd:ee:fg"`,
		`ALLOWLIST_IPS entry "192.168.1.1-192.168.1.5"`, "ALLOWLIST_ON_INVALID=pending-only"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "192.168.1.53") {
		t.Errorf("a valid entry is not a problem: %q", err)
	}
}

// TestAllowlistTypoPendingOnlyOverride: with the explicit override the
// service starts, but nothing is enforced without a human.
func TestAllowlistTypoPendingOnlyOverride(t *testing.T) {
	t.Setenv("ALLOWLIST_MACS", "aa:bb:cc:dd:ee:fg")
	t.Setenv("ALLOWLIST_IPS", "192.168.1.53")
	t.Setenv("ALLOWLIST_ON_INVALID", OnInvalidPendingOnly)
	t.Setenv("POLICY_ALLOW_EMPTY_ALLOWLIST", "true") // must not reopen it either

	p := mustLoad(t)
	if len(p.RejectedEntries) != 1 || !strings.Contains(p.RejectedEntries[0], "aa:bb:cc:dd:ee:fg") {
		t.Fatalf("RejectedEntries = %v", p.RejectedEntries)
	}
	if p.AutoBlockEnabled() {
		t.Fatal("auto-block must be disabled while a protection entry is rejected")
	}
	d := p.Evaluate(feedMatch(99, events.SeverityCritical))
	if d.Action != "pending" || d.Withheld != WithheldInvalidProtection {
		t.Fatalf("got %+v, want pending withheld by %s", d, WithheldInvalidProtection)
	}
	if !p.Allowlist.Contains("", "192.168.1.53") {
		t.Error("the valid entries still protect")
	}
}

func TestAllowlistOnInvalidRejectsUnknownMode(t *testing.T) {
	t.Setenv("ALLOWLIST_MACS", "not-a-mac")
	t.Setenv("ALLOWLIST_ON_INVALID", "ignore")
	if _, err := LoadFromEnv(); err == nil || !strings.Contains(err.Error(), `"ignore"`) {
		t.Fatalf("an unknown override must not be read as permission, got %v", err)
	}
	// and an override with nothing to override is harmless
	t.Setenv("ALLOWLIST_MACS", "aa:bb:cc:dd:ee:ff")
	if p := mustLoad(t); !p.AutoBlockEnabled() {
		t.Error("a valid allowlist with the override set should enable auto-block")
	}
}

// TestGatewayIsPinnedFromConfiguration: GATEWAY_IP / GATEWAY_MAC protect
// the router by both identifiers, independently of the allowlist.
func TestGatewayIsPinnedFromConfiguration(t *testing.T) {
	t.Setenv("ALLOWLIST_IPS", "192.168.1.53")
	t.Setenv("GATEWAY_IP", "192.168.1.1")
	t.Setenv("GATEWAY_MAC", "AA-00-00-00-00-01")
	p := mustLoad(t)

	if p.GatewayIP.String() != "192.168.1.1" || p.GatewayMAC != "aa:00:00:00:00:01" {
		t.Fatalf("gateway = %s / %s", p.GatewayIP, p.GatewayMAC)
	}
	byMAC := feedMatch(99, events.SeverityCritical)
	byMAC.ClientMAC = "aa:00:00:00:00:01"
	if d := p.Evaluate(byMAC); d.Action != "ignore" {
		t.Fatalf("an event from the gateway's MAC must be ignored, got %+v", d)
	}
	if p.Allowlist.Len() != 1 {
		t.Error("the gateway is infrastructure, not an operator allowlist entry")
	}
}

func TestGatewayConfigRejections(t *testing.T) {
	cases := []struct{ key, value, want string }{
		{"GATEWAY_IP", "192.168.001.001", "not a single IP address"},
		{"GATEWAY_IP", "192.168.1.1/32", "not a single IP address"},
		{"GATEWAY_IP", "fe80::1%eth0", "zoned"},
		{"GATEWAY_MAC", "ff:ff:ff:ff:ff:ff", "group"},
		{"GATEWAY_MAC", "01:00:5e:00:00:01", "group"},
		{"GATEWAY_MAC", "00:00:00:00:00:00", "all-zero"},
		{"GATEWAY_MAC", "aa bb cc dd ee ff", "invalid MAC"},
		{"ARP_GATEWAY_IP", "192.168.1.1", "renamed: set GATEWAY_IP"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv("ALLOWLIST_IPS", "192.168.1.53")
			t.Setenv(tc.key, tc.value)
			_, err := LoadFromEnv()
			if err == nil || !strings.Contains(err.Error(), tc.key) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%s=%q: got %v, want an error naming it (%q)", tc.key, tc.value, err, tc.want)
			}
		})
	}
}

func TestAllowEmptyAllowlistFromEnv(t *testing.T) {
	if p := mustLoad(t); p.AutoBlockEnabled() {
		t.Fatal("an empty allowlist disables auto-block by default")
	}
	t.Setenv("POLICY_ALLOW_EMPTY_ALLOWLIST", "true")
	if p := mustLoad(t); !p.AutoBlockEnabled() {
		t.Fatal("POLICY_ALLOW_EMPTY_ALLOWLIST=true should enable it")
	}
}

func TestParseHostAddr(t *testing.T) {
	for in, want := range map[string]string{
		"192.168.1.1": "192.168.1.1", " ::ffff:192.168.1.1 ": "192.168.1.1", "2001:DB8::1": "2001:db8::1",
	} {
		got, err := ParseHostAddr(in)
		if err != nil || got.String() != want {
			t.Errorf("ParseHostAddr(%q) = %v, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"", "0xc0a80101", "192.168.1", "192.168.1.1/24"} {
		if _, err := ParseHostAddr(in); err == nil {
			t.Errorf("ParseHostAddr(%q) should fail", in)
		}
	}
}
