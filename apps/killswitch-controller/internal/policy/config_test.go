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
	t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)       // switched on, and still held
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
	t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)
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
	t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)
	if p := mustLoad(t); p.AutoBlockEnabled() {
		t.Fatal("an empty allowlist disables auto-block by default")
	}
	t.Setenv("POLICY_ALLOW_EMPTY_ALLOWLIST", "true")
	if p := mustLoad(t); !p.AutoBlockEnabled() {
		t.Fatal("POLICY_ALLOW_EMPTY_ALLOWLIST=true should enable it")
	}
}

// TestAllowlistDoesNotSwitchAutoBlockOn: a non-empty allowlist used to be
// what enabled automation, so "never touch this server" — or an installer
// protecting the host's own address — turned it on as a side effect. Only
// POLICY_AUTO_BLOCK=on does; the allowlist keeps protecting either way.
func TestAllowlistDoesNotSwitchAutoBlockOn(t *testing.T) {
	t.Setenv("ALLOWLIST_IPS", "192.168.1.1,192.168.1.53")
	t.Setenv("ALLOWLIST_MACS", "aa:bb:cc:dd:ee:ff")
	protected := feedMatch(99, events.SeverityCritical)
	protected.ClientIP = "192.168.1.53"

	for _, setting := range []string{"", AutoBlockOff} {
		t.Run("POLICY_AUTO_BLOCK="+setting, func(t *testing.T) {
			t.Setenv("POLICY_AUTO_BLOCK", setting)
			p := mustLoad(t)
			if p.AutoBlock || p.AutoBlockEnabled() {
				t.Fatal("auto-block is on without POLICY_AUTO_BLOCK=on")
			}
			d := p.Evaluate(feedMatch(99, events.SeverityCritical))
			if d.Action != "pending" || d.Withheld != WithheldAutoBlockOff ||
				!strings.Contains(d.Reason, "auto-block disabled: POLICY_AUTO_BLOCK=off; every other auto-block condition held") {
				t.Fatalf("got %+v, want pending withheld by %s", d, WithheldAutoBlockOff)
			}
			if reason, label := p.AutoBlockHold(); label != WithheldAutoBlockOff || reason == "" {
				t.Errorf("AutoBlockHold = %q, %q", reason, label)
			}
			if d := p.Evaluate(protected); d.Action != "ignore" {
				t.Errorf("an allowlisted device must still be ignored, got %+v", d)
			}
			if d := p.Evaluate(feedMatch(60, events.SeverityMedium)); d.Action != "pending" || d.Withheld != "" {
				t.Errorf("only events that would have auto-blocked are withheld, got %+v", d)
			}
		})
	}

	t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)
	p := mustLoad(t)
	if d := p.Evaluate(feedMatch(99, events.SeverityCritical)); d.Action != "auto_block" {
		t.Fatalf("POLICY_AUTO_BLOCK=on with an allowlist should auto-block, got %+v", d)
	}
	if d := p.Evaluate(protected); d.Action != "ignore" {
		t.Errorf("an allowlisted device must still be ignored, got %+v", d)
	}
}

// TestAutoBlockOnStillNeedsProtection: switching automation on does not
// waive the conditions that held it before.
func TestAutoBlockOnStillNeedsProtection(t *testing.T) {
	t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)
	if _, label := mustLoad(t).AutoBlockHold(); label != WithheldEmptyAllowlist {
		t.Errorf("on with an empty allowlist: held by %q, want %q", label, WithheldEmptyAllowlist)
	}
	t.Setenv("ALLOWLIST_MACS", "aa:bb:cc:dd:ee:fg")
	t.Setenv("ALLOWLIST_ON_INVALID", OnInvalidPendingOnly)
	if _, label := mustLoad(t).AutoBlockHold(); label != WithheldInvalidProtection {
		t.Errorf("on with a rejected entry: held by %q, want %q", label, WithheldInvalidProtection)
	}
	// Off is the first reason: fixing the entry alone would not enable it.
	t.Setenv("POLICY_AUTO_BLOCK", "")
	if _, label := mustLoad(t).AutoBlockHold(); label != WithheldAutoBlockOff {
		t.Errorf("off with a rejected entry: held by %q, want %q", label, WithheldAutoBlockOff)
	}
}

// TestAutoBlockSettingIsOnOrOff: anything else refuses the start. Read as
// off it would silently drop the automation the operator asked for; read as
// on it would enforce without a human nobody agreed to.
func TestAutoBlockSettingIsOnOrOff(t *testing.T) {
	t.Setenv("ALLOWLIST_IPS", "192.168.1.1")
	for _, v := range []string{"true", "1", "yes", "ON", "On", " on", "off ", "disabled"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("POLICY_AUTO_BLOCK", v)
			p, err := LoadFromEnv()
			if err == nil {
				t.Fatalf("POLICY_AUTO_BLOCK=%q loaded a policy with AutoBlock=%v", v, p.AutoBlock)
			}
			if !strings.Contains(err.Error(), "POLICY_AUTO_BLOCK") || !strings.Contains(err.Error(), `"on" or "off"`) {
				t.Errorf("error %q should name the setting and its values", err)
			}
		})
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
