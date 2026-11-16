package policy

import (
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/libs/events"
)

// newTestPolicy is a policy that may auto-block: switched on, with an
// allowlist.
func newTestPolicy() *Policy {
	p := DefaultPolicy()
	p.AutoBlock = true
	_ = p.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")
	_ = p.Allowlist.AddIP("192.168.1.1")
	return p
}

var evilDomain = &events.Target{Type: events.TargetDomain, Value: "evil.example"}

// feedMatch is a single-signal domain IoC detection, the shape the engine
// emits for a feed hit on a DNS query.
func feedMatch(conf int, sev string) events.DetectionEvent {
	return events.DetectionEvent{
		Confidence:  conf,
		Severity:    sev,
		ClientIP:    "192.168.1.100",
		SignalClass: events.SignalIoC,
		Signals: []events.Signal{{Class: events.SignalIoC, Confidence: conf,
			Indicator: "evil.example", IndicatorType: events.IndicatorDomain, Source: "threatfox"}},
		Target: evilDomain,
	}
}

// composite builds a critical multi-signal detection.
func composite(conf int, target *events.Target, signals ...events.Signal) events.DetectionEvent {
	return events.DetectionEvent{
		Confidence:  conf,
		Severity:    events.SeverityCritical,
		ClientIP:    "192.168.1.100",
		SignalClass: events.SignalComposite,
		Signals:     signals,
		Target:      target,
	}
}

// sig is one contributing signal with its own confidence and indicator.
func sig(class string, conf int, indicatorType, indicator string) events.Signal {
	return events.Signal{Class: class, Confidence: conf, IndicatorType: indicatorType, Indicator: indicator}
}

func domainSig(class string, conf int, domain string) events.Signal {
	return sig(class, conf, events.IndicatorDomain, domain)
}

func mustLoad(t *testing.T) *Policy {
	t.Helper()
	p, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv: %v", err)
	}
	return p
}

func TestAutoBlock(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(feedMatch(95, events.SeverityCritical))
	if d.Action != "auto_block" {
		t.Fatalf("expected auto_block, got %q (%s)", d.Action, d.Reason)
	}
	if !strings.Contains(d.Reason, "target=evil.example") {
		t.Errorf("auto-block reason should name what is blocked, got %q", d.Reason)
	}
	if d.ActionType != events.ActionDNSSinkhole {
		t.Fatalf("expected dns_sinkhole, got %q", d.ActionType)
	}
	if d.TTLSeconds != 3600 {
		t.Fatalf("expected TTL 3600, got %d", d.TTLSeconds)
	}
}

func TestPending(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 60,
		Severity:   events.SeverityMedium,
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "pending" {
		t.Fatalf("expected pending, got %q", d.Action)
	}
}

func TestIgnoreBelowThresholds(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 30,
		Severity:   events.SeverityLow,
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "ignore" {
		t.Fatalf("expected ignore, got %q", d.Action)
	}
}

func TestAllowlistByMAC(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 99,
		Severity:   events.SeverityCritical,
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "ignore" {
		t.Fatalf("allowlisted MAC should always be ignored, got %q", d.Action)
	}
}

func TestAllowlistByIP(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 99,
		Severity:   events.SeverityCritical,
		ClientIP:   "192.168.1.1",
	})
	if d.Action != "ignore" {
		t.Fatalf("allowlisted IP should always be ignored, got %q", d.Action)
	}
}

func TestAllowlistCaseInsensitiveMAC(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 99,
		Severity:   events.SeverityCritical,
		ClientMAC:  "AA:BB:CC:DD:EE:FF",
	})
	if d.Action != "ignore" {
		t.Fatalf("MAC match should be case-insensitive, got %q", d.Action)
	}
}

func TestHighConfidenceLowSeverityNotAutoBlock(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 95,
		Severity:   events.SeverityLow,
		ClientIP:   "192.168.1.100",
	})
	if d.Action == "auto_block" {
		t.Fatal("low severity should not auto-block even with high confidence")
	}
}

func TestDefaultPolicyValues(t *testing.T) {
	p := DefaultPolicy()
	if p.AutoMinConfidence != 90 {
		t.Errorf("expected auto confidence 90, got %d", p.AutoMinConfidence)
	}
	if p.AutoMinSeverity != events.SeverityCritical {
		t.Errorf("expected auto severity critical, got %s", p.AutoMinSeverity)
	}
	if p.DefaultAction != events.ActionDNSSinkhole {
		t.Errorf("expected default action dns_sinkhole, got %s", p.DefaultAction)
	}
	if p.AutoMinSignals != 1 {
		t.Errorf("expected AutoMinSignals 1, got %d", p.AutoMinSignals)
	}
	if p.AutoBlock {
		t.Error("the default policy must not enforce without a human")
	}
}

// Step 117: composite-confidence gate for auto-block.

func TestAutoMinSignalsRequiresCorroboration(t *testing.T) {
	p := newTestPolicy()
	p.AutoMinSignals = 3

	// two classes, an attested feed match among them, under a 3-class bar
	two := composite(98, evilDomain, domainSig(events.SignalIoC, 95, "evil.example"),
		domainSig(events.SignalBeacon, 75, "evil.example"))
	d := p.Evaluate(two)
	if d.Action != "pending" || !strings.Contains(d.Reason, "needs 3 signals, has 2") {
		t.Fatalf("a 2-class composite under AutoMinSignals=3 should be pending and say why, got %q (%s)",
			d.Action, d.Reason)
	}

	// Labelling the same evidence as a single-signal event must not skip
	// the gate: the count comes from the signals, not the label.
	mislabelled := two
	mislabelled.SignalClass = events.SignalIoC
	if d := p.Evaluate(mislabelled); d.Action != "pending" {
		t.Fatalf("a mislabelled composite skipped the signal gate: %q (%s)", d.Action, d.Reason)
	}

	// two corroborating classes under a 2-class bar → auto-block
	p.AutoMinSignals = 2
	if d := p.Evaluate(two); d.Action != "auto_block" {
		t.Fatalf("two-signal composite with an attested feed match should auto-block, got %q (%s)",
			d.Action, d.Reason)
	}
}

func TestKnownBadIoCAutoBlocksEvenWithSignalGate(t *testing.T) {
	p := newTestPolicy()
	p.AutoMinSignals = 2

	// a single known-bad IoC feed match is not a composite — it must still
	// auto-block instantly.
	d := p.Evaluate(feedMatch(95, events.SeverityCritical))
	if d.Action != "auto_block" {
		t.Fatalf("known-bad IoC should auto-block regardless of signal gate, got %q", d.Action)
	}
}

// TestIPTargetNeverAutoBlocks: an IP-IoC hit used to be auto-blocked with
// blocked_domain "cdn.x (→203.0.113.7)", which then failed in the sinkhole.
// The policy must queue it for a human and say why.
func TestIPTargetNeverAutoBlocks(t *testing.T) {
	p := newTestPolicy()
	ev := feedMatch(95, events.SeverityCritical)
	ev.Signals[0].Indicator, ev.Signals[0].IndicatorType = "203.0.113.7", events.IndicatorIP
	ev.Target = &events.Target{Type: events.TargetIP, Value: "203.0.113.7"}

	d := p.Evaluate(ev)
	if d.Action != "pending" {
		t.Fatalf("an ip target must not auto-block, got %q", d.Action)
	}
	if !strings.Contains(d.Reason, "target is ip 203.0.113.7") ||
		!strings.Contains(d.Reason, "only a domain can be blocked automatically") {
		t.Errorf("reason should say plainly why, got %q", d.Reason)
	}
}

// TestNoTargetNeverAutoBlocks: an IDS rule hit names no destination; its
// rule text used to become the sinkhole domain.
func TestNoTargetNeverAutoBlocks(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence:  95,
		Severity:    events.SeverityCritical,
		ClientIP:    "192.168.1.100",
		Domain:      "looks-like-a.domain.example", // never a source of targets
		Summary:     "evil.example",                // nor is this
		SignalClass: events.SignalIDS,
		Signals: []events.Signal{{Class: events.SignalIDS, Confidence: 95,
			Indicator: "2031999", IndicatorType: events.IndicatorSID}},
	})
	if d.Action != "pending" {
		t.Fatalf("an event without a target must not auto-block, got %q", d.Action)
	}
	if !strings.Contains(d.Reason, "no enforceable target") {
		t.Errorf("reason should say there is nothing to block, got %q", d.Reason)
	}
}

// TestPendingExplainsMissingTarget: an action an operator approves with the
// sinkhole will fail if there is no domain; the queue should say so up front.
func TestPendingExplainsMissingTarget(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 60,
		Severity:   events.SeverityMedium,
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "pending" || !strings.Contains(d.Reason, "no enforceable target") {
		t.Fatalf("got %q (%s)", d.Action, d.Reason)
	}

	withTarget := feedMatch(60, events.SeverityMedium)
	if d := p.Evaluate(withTarget); strings.Contains(d.Reason, "target") {
		t.Errorf("a domain target needs no explanation, got %q", d.Reason)
	}
}

func TestLoadFromEnvAutoMinSignals(t *testing.T) {
	t.Setenv("POLICY_AUTO_MIN_SIGNALS", "2")
	if p := mustLoad(t); p.AutoMinSignals != 2 {
		t.Errorf("AutoMinSignals = %d, want 2", p.AutoMinSignals)
	}
}

func TestAllowlistRemoveMAC(t *testing.T) {
	var al Allowlist
	_ = al.AddMAC("aa:bb:cc:dd:ee:ff")
	al.RemoveMAC("aa:bb:cc:dd:ee:ff")
	if al.Contains("aa:bb:cc:dd:ee:ff", "") {
		t.Fatal("MAC should be removed")
	}
}

func TestAllowlistRemoveIP(t *testing.T) {
	var al Allowlist
	_ = al.AddIP("192.168.1.1")
	al.RemoveIP("192.168.1.1")
	if al.Contains("", "192.168.1.1") {
		t.Fatal("IP should be removed")
	}
}

func TestAllowlistMACs(t *testing.T) {
	var al Allowlist
	_ = al.AddMAC("aa:bb:cc:dd:ee:ff")
	_ = al.AddMAC("11:22:33:44:55:66")
	macs := al.MACs()
	if len(macs) != 2 {
		t.Fatalf("expected 2 MACs, got %d", len(macs))
	}
}

func TestAllowlistIPs(t *testing.T) {
	var al Allowlist
	_ = al.AddIP("10.0.0.1")
	ips := al.IPs()
	if len(ips) != 1 || ips[0] != "10.0.0.1" {
		t.Fatalf("expected [10.0.0.1], got %v", ips)
	}
}

func TestAllowlistContainsEmpty(t *testing.T) {
	var al Allowlist
	if al.Contains("", "") {
		t.Fatal("empty allowlist should not match")
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("POLICY_AUTO_CONFIDENCE", "85")
	t.Setenv("POLICY_AUTO_SEVERITY", "high")
	t.Setenv("POLICY_PENDING_CONFIDENCE", "40")
	t.Setenv("POLICY_PENDING_SEVERITY", "low")
	t.Setenv("POLICY_DEFAULT_TTL", "7200")
	t.Setenv("POLICY_DEFAULT_ACTION", "arp_isolate")
	t.Setenv("ALLOWLIST_MACS", "aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66")
	t.Setenv("ALLOWLIST_IPS", "10.0.0.1,10.0.0.2")

	p := mustLoad(t)

	if p.AutoMinConfidence != 85 {
		t.Errorf("auto confidence = %d, want 85", p.AutoMinConfidence)
	}
	if p.AutoMinSeverity != "high" {
		t.Errorf("auto severity = %q, want high", p.AutoMinSeverity)
	}
	if p.PendMinConfidence != 40 {
		t.Errorf("pending confidence = %d, want 40", p.PendMinConfidence)
	}
	if p.DefaultTTL != 7200 {
		t.Errorf("default TTL = %d, want 7200", p.DefaultTTL)
	}
	if p.DefaultAction != "arp_isolate" {
		t.Errorf("default action = %q, want arp_isolate", p.DefaultAction)
	}
	if len(p.Allowlist.MACs()) != 2 {
		t.Errorf("expected 2 allowlisted MACs, got %d", len(p.Allowlist.MACs()))
	}
	if len(p.Allowlist.IPs()) != 2 {
		t.Errorf("expected 2 allowlisted IPs, got %d", len(p.Allowlist.IPs()))
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{events.SeverityCritical, 4},
		{events.SeverityHigh, 3},
		{events.SeverityMedium, 2},
		{events.SeverityLow, 1},
		{"unknown", 0},
		{"", 0},
	}
	for _, tt := range tests {
		got := severityRank(tt.severity)
		if got != tt.want {
			t.Errorf("severityRank(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

// TestCorroboratedHeuristicsNeverAutoBlock pins down the step-124 fix.
//
// Composite confidence combines signals with a noisy-OR, so the strongest
// pair of heuristics the engine can produce — a beacon capped at 75 and a
// volumetric anomaly capped at 70 — combines to 1-(0.25*0.30) = 0.925 → 93,
// which maps to severity "critical". That cleared BOTH the 90/critical bar
// and AutoMinSignals=2, so two local heuristics could quarantine a device
// with no human in the loop. NTP, telemetry and update checks all look like
// beaconing, so this was a realistic way to cut a household device off.
func TestCorroboratedHeuristicsNeverAutoBlock(t *testing.T) {
	p := newTestPolicy()
	p.AutoMinSignals = 2

	// what combine([75,70]) actually produces, pointed at the beacon's
	// destination
	dest := &events.Target{Type: events.TargetDomain, Value: "updates.vendor.example"}
	heuristicsOnly := composite(93, dest,
		domainSig(events.SignalBeacon, 75, "updates.vendor.example"),
		sig(events.SignalVolumetric, 70, "", ""))

	d := p.Evaluate(heuristicsOnly)
	if d.Action != "pending" {
		t.Fatalf("beacon+volumetric must stay human-in-the-loop, got %q (reason: %s)",
			d.Action, d.Reason)
	}
	if !strings.Contains(d.Reason, "known-bad") {
		t.Errorf("pending reason should explain the known-bad gate, got %q", d.Reason)
	}

	// An IDS signature that names a rule, not the destination, attests
	// nothing about updates.vendor.example: still a human's call.
	withSignature := heuristicsOnly
	withSignature.Signals = append(append([]events.Signal(nil), heuristicsOnly.Signals...),
		sig(events.SignalIDS, 70, events.IndicatorSID, "2013028"))
	if d := p.Evaluate(withSignature); d.Action != "pending" ||
		!strings.Contains(d.Reason, "no known-bad signal names the target updates.vendor.example") {
		t.Fatalf("an IDS hit on a rule id must not unlock a block of the beacon's destination, got %q (%s)",
			d.Action, d.Reason)
	}

	// A signature that matched the destination itself, strongly, does.
	attested := heuristicsOnly
	attested.Signals = append(append([]events.Signal(nil), heuristicsOnly.Signals...),
		domainSig(events.SignalIDS, 95, "updates.vendor.example"))
	if d := p.Evaluate(attested); d.Action != "auto_block" {
		t.Fatalf("heuristics plus a strong signature on the destination should auto-block, got %q (%s)",
			d.Action, d.Reason)
	}
}

// TestUnlabelledEventNeverAutoBlocks covers a producer that forgets to set a
// signal class. "No label" must mean "no attested evidence", never a free
// pass through the gate.
func TestUnlabelledEventNeverAutoBlocks(t *testing.T) {
	p := newTestPolicy()
	d := p.Evaluate(events.DetectionEvent{
		Confidence: 100,
		Severity:   events.SeverityCritical,
		ClientIP:   "192.168.1.100",
	})
	if d.Action != "pending" {
		t.Fatalf("unlabelled event must not auto-block, got %q", d.Action)
	}
}

// TestKnownBadOptOutNoLongerWidens: POLICY_AUTO_REQUIRE_KNOWN_BAD=false used
// to let corroborated heuristics auto-block. The variable is now ignored.
func TestKnownBadOptOutNoLongerWidens(t *testing.T) {
	t.Setenv("POLICY_AUTO_REQUIRE_KNOWN_BAD", "false")
	t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)
	t.Setenv("ALLOWLIST_IPS", "192.168.1.1")
	p := mustLoad(t)
	d := p.Evaluate(composite(93, evilDomain,
		domainSig(events.SignalBeacon, 75, "evil.example"), sig(events.SignalVolumetric, 70, "", "")))
	if d.Action != "pending" {
		t.Fatalf("heuristics must not auto-block whatever the environment says, got %q", d.Action)
	}
}

// TestInvalidSeverityEnvDoesNotWidenPolicy covers the misconfiguration that
// silently WEAKENED the gate: an unrecognised severity ranks 0, which made
// `evRank >= severityRank(AutoMinSeverity)` trivially true and reduced
// auto-block to a bare confidence check. A typo must never widen enforcement.
func TestInvalidSeverityEnvDoesNotWidenPolicy(t *testing.T) {
	t.Setenv("POLICY_AUTO_SEVERITY", "CRITICAL_TYPO")
	t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)
	t.Setenv("POLICY_ALLOW_EMPTY_ALLOWLIST", "true")
	p := mustLoad(t)
	if p.AutoMinSeverity != events.SeverityCritical {
		t.Fatalf("invalid severity should fall back to critical, got %q", p.AutoMinSeverity)
	}

	// A medium-severity event with high confidence must not auto-block.
	d := p.Evaluate(events.DetectionEvent{
		Confidence:  99,
		Severity:    events.SeverityMedium,
		ClientIP:    "192.168.1.100",
		SignalClass: events.SignalIoC,
	})
	if d.Action == "auto_block" {
		t.Fatalf("medium severity must not auto-block under a critical bar, got %q", d.Action)
	}
}

func TestLoadFromEnvRejectsInvalidValues(t *testing.T) {
	t.Setenv("POLICY_AUTO_CONFIDENCE", "9000")
	t.Setenv("POLICY_PENDING_SEVERITY", "")
	t.Setenv("POLICY_DEFAULT_ACTION", "rm_minus_rf")
	t.Setenv("POLICY_DEFAULT_TTL", "-1")
	t.Setenv("POLICY_AUTO_MIN_SIGNALS", "0")

	p := mustLoad(t)
	if p.AutoMinConfidence != 90 {
		t.Errorf("AutoMinConfidence = %d, want 90", p.AutoMinConfidence)
	}
	if p.DefaultAction != events.ActionDNSSinkhole {
		t.Errorf("DefaultAction = %q, want dns_sinkhole", p.DefaultAction)
	}
	if p.DefaultTTL != 3600 {
		t.Errorf("DefaultTTL = %d, want 3600", p.DefaultTTL)
	}
	if p.AutoMinSignals != 1 {
		t.Errorf("AutoMinSignals = %d, want 1", p.AutoMinSignals)
	}
}

// TestAllowlistNormalization is the regression test for the gap that left the
// router unprotected: the detection pipeline emits lowercase colon-separated
// MACs, but operators copy whatever their router UI shows.
func TestAllowlistNormalization(t *testing.T) {
	var al Allowlist
	if err := al.AddMAC("AA-BB-CC-DD-EE-FF"); err != nil {
		t.Fatalf("hyphen MAC should be accepted: %v", err)
	}
	if err := al.AddMAC("001122334455"); err != nil {
		t.Fatalf("bare hex MAC should be accepted: %v", err)
	}

	for _, spelling := range []string{
		"aa:bb:cc:dd:ee:ff",
		"AA:BB:CC:DD:EE:FF",
		"aa-bb-cc-dd-ee-ff",
		"AABBCCDDEEFF",
	} {
		if !al.Contains(spelling, "") {
			t.Errorf("MAC spelling %q should match the allowlisted device", spelling)
		}
	}
	if !al.Contains("00:11:22:33:44:55", "") {
		t.Error("bare-hex entry should match canonical form")
	}

	if err := al.AddMAC("not-a-mac"); err == nil {
		t.Error("invalid MAC should be rejected at load time, not silently ignored")
	}
}

func TestAllowlistIPNormalizationAndCIDR(t *testing.T) {
	var al Allowlist
	if err := al.AddIP("2001:DB8::1"); err != nil {
		t.Fatalf("IPv6 should be accepted: %v", err)
	}
	if err := al.AddIP("192.168.1.0/29"); err != nil {
		t.Fatalf("CIDR should be accepted: %v", err)
	}

	if !al.Contains("", "2001:db8::1") {
		t.Error("IPv6 case should not affect matching")
	}
	if !al.Contains("", "192.168.1.1") {
		t.Error("address inside an allowlisted CIDR should match")
	}
	if !al.Contains("", "192.168.1.7") {
		t.Error("last address of /29 should match")
	}
	if al.Contains("", "192.168.1.8") {
		t.Error("address outside the CIDR must not match")
	}
	if al.Contains("", "::ffff:10.0.0.1") {
		t.Error("unrelated address must not match")
	}

	if err := al.AddIP("192.168.1.300"); err == nil {
		t.Error("invalid IP should be rejected")
	}
	if err := al.AddIP("192.168.1.0/99"); err == nil {
		t.Error("invalid CIDR should be rejected")
	}
}

func TestAllowlistIPv4In6Equivalence(t *testing.T) {
	var al Allowlist
	if err := al.AddIP("::ffff:192.168.1.1"); err != nil {
		t.Fatalf("IPv4-in-IPv6 should be accepted: %v", err)
	}
	if !al.Contains("", "192.168.1.1") {
		t.Error("IPv4-in-IPv6 entry should match the plain IPv4 form")
	}
}

func TestAllowlistLen(t *testing.T) {
	var al Allowlist
	if al.Len() != 0 {
		t.Fatalf("empty allowlist Len() = %d, want 0", al.Len())
	}
	_ = al.AddMAC("aa:bb:cc:dd:ee:ff")
	_ = al.AddIP("10.0.0.1")
	_ = al.AddIP("10.1.0.0/24")
	if al.Len() != 3 {
		t.Errorf("Len() = %d, want 3", al.Len())
	}
}
