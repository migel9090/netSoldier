package main

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// auditEvent is a contract-valid composite in the shape the v2 engine
// builds: one signal per class, each with its own confidence and indicator.
func auditEvent(id, client string, conf int, target string, signals ...events.Signal) events.DetectionEvent {
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            "DET-audit-" + id,
		Timestamp:     time.Now().UTC(),
		Summary:       fmt.Sprintf("%d corroborating signals for %s", len(signals), client),
		Domain:        target,
		ClientIP:      client,
		Severity:      events.SeverityCritical,
		Confidence:    conf,
		Source:        "composite",
		SignalClass:   events.SignalComposite,
		Signals:       signals,
		Target:        &events.Target{Type: events.TargetDomain, Value: target},
	}
}

// TestAuditCompositesNeverReachAdGuard replays the auditors' two live runs
// through the real policy (proxmox-soc posture), the real HTTP path and the
// real sinkhole driver. Both used to end as household-wide AdGuard rules for
// domains no feed had listed.
func TestAuditCompositesNeverReachAdGuard(t *testing.T) {
	ag := newMiniAdGuard(t)
	pol := policy.DefaultPolicy()
	pol.AutoBlock = true
	pol.AutoMinSignals = 2
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	env := sinkHarness(t, ag, harnessOpts{pol: pol})

	beacon := func(dst string) events.Signal {
		return events.Signal{Class: events.SignalBeacon, Confidence: 75, Indicator: dst,
			IndicatorType: events.IndicatorDomain, Source: "rita"}
	}
	volumetric := events.Signal{Class: events.SignalVolumetric, Confidence: 70, Source: "iforest"}

	cases := []struct {
		name string
		ev   events.DetectionEvent
		rule string
	}{
		{"ET INFO signature + beacon + volumetric", auditEvent("1", "192.168.1.50", 93, "time.cloudflare.com",
			beacon("time.cloudflare.com"),
			events.Signal{Class: events.SignalIDS, Confidence: 0, Indicator: "2013028",
				IndicatorType: events.IndicatorSID, Source: "et-open"},
			volumetric),
			"no known-bad signal names the target time.cloudflare.com"},
		{"weak feed hit + beacon", auditEvent("2", "192.168.1.51", 90, "telemetry.vendor.example",
			beacon("telemetry.vendor.example"),
			events.Signal{Class: events.SignalIoC, Confidence: 60, Indicator: "c2.real-threat.example",
				IndicatorType: events.IndicatorDomain, Source: "threatfox"}),
			"no known-bad signal names the target telemetry.vendor.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := env.evaluate(tc.ev)
			if got.Decision.Action != "pending" || got.Action == nil || got.Action.State != events.StatePending {
				t.Fatalf("got %+v, want a pending action", got)
			}
			if got.Action.AutoApproved || !strings.Contains(got.Action.PolicyRule, tc.rule) {
				t.Errorf("policy_rule %q should say %q", got.Action.PolicyRule, tc.rule)
			}
		})
	}
	if rules, writes := ag.current(); len(rules) != 0 || writes != 0 {
		t.Fatalf("nothing may reach AdGuard: rules=%v writes=%d", rules, writes)
	}
}

// TestDefaultActionNeverChangesAutoBlock: with POLICY_DEFAULT_ACTION=
// arp_isolate a single feed match isolated a device at layer 2 with no human.
func TestDefaultActionNeverChangesAutoBlock(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.AutoBlock = true
	pol.DefaultAction = events.ActionARPIsolate
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	byType := map[string]*recordingDriver{
		events.ActionDNSSinkhole: {}, events.ActionARPIsolate: {}, events.ActionSwitchACL: {},
	}
	drvs := map[string]drivers.Driver{}
	for k, v := range byType {
		drvs[k] = v
	}
	env := newHarness(t, harnessOpts{pol: pol, drivers: drvs})

	auto := env.evaluate(criticalIoCEvent())
	if auto.Decision.Action != "auto_block" || auto.Action == nil || auto.Action.ActionType != events.ActionDNSSinkhole {
		t.Fatalf("auto-block must enforce through the DNS sinkhole, got %+v", auto)
	}
	if byType[events.ActionDNSSinkhole].applied.Load() != 1 || byType[events.ActionARPIsolate].applied.Load() != 0 {
		t.Fatal("only the sinkhole driver may run without a human")
	}

	held := env.evaluate(withDomainTarget(testEvent(60, events.SeverityMedium), "maybe.example"))
	if held.Action == nil || held.Action.State != events.StatePending || held.Action.ActionType != events.ActionARPIsolate {
		t.Fatalf("the default action is what a human approves, got %+v", held.Action)
	}
}

// TestPendingOnlyModeCountsEveryWithheldAutoBlock: started with a rejected
// allowlist entry, the service must make each auto-block it holds back
// visible — once per detection, not once per delivery.
func TestPendingOnlyModeCountsEveryWithheldAutoBlock(t *testing.T) {
	pol := policy.DefaultPolicy()
	pol.AutoBlock = true // switched on, and still held by the rejected entry
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	pol.RejectedEntries = []string{`ALLOWLIST_MACS entry "aa:bb:cc:dd:ee:fg"`}
	drv := &recordingDriver{}
	env := newHarness(t, harnessOpts{pol: pol, driver: drv})
	label := map[string]string{"reason": policy.WithheldInvalidProtection}
	before := metricValue(t, "killswitch_auto_block_withheld_total", label)

	ev := criticalIoCEvent()
	got := env.evaluate(ev)
	if got.Decision.Action != "pending" || got.Decision.Withheld != policy.WithheldInvalidProtection ||
		got.Action == nil || got.Action.State != events.StatePending {
		t.Fatalf("got %+v, want a withheld pending action", got)
	}
	if !strings.Contains(got.Action.PolicyRule, "protection entry was rejected at start-up") {
		t.Errorf("policy_rule should say why: %q", got.Action.PolicyRule)
	}
	if again := env.evaluate(ev); !again.Duplicate {
		t.Fatalf("repeat delivery: %+v", again)
	}
	env.evaluate(testEvent(60, events.SeverityMedium)) // would not have auto-blocked anyway
	env.evaluate(criticalIoCEvent())

	if got := metricValue(t, "killswitch_auto_block_withheld_total", label); got != before+2 {
		t.Fatalf("withheld counter moved %v → %v, want +2", before, got)
	}
	if drv.applied.Load() != 0 {
		t.Fatal("nothing may be enforced in pending-only mode")
	}
}

// TestAllowlistAloneQueuesForAHuman: an operator who only lists the devices
// never to touch has not asked for automation. The allowlist used to switch
// it on; now a detection that meets every other auto-block condition is
// queued, counted and explained as POLICY_AUTO_BLOCK=off — and GET /policy
// says the switch is off rather than that something is wrong.
func TestAllowlistAloneQueuesForAHuman(t *testing.T) {
	pol := policy.DefaultPolicy()
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	drv := &recordingDriver{}
	env := newHarness(t, harnessOpts{pol: pol, driver: drv})
	label := map[string]string{"reason": policy.WithheldAutoBlockOff}
	before := metricValue(t, "killswitch_auto_block_withheld_total", label)

	got := env.evaluate(criticalIoCEvent())
	if got.Decision.Action != "pending" || got.Decision.Withheld != policy.WithheldAutoBlockOff ||
		got.Action == nil || got.Action.State != events.StatePending || got.Action.AutoApproved {
		t.Fatalf("got %+v, want a pending action withheld by %s", got, policy.WithheldAutoBlockOff)
	}
	if !strings.Contains(got.Action.PolicyRule, "auto-block disabled: POLICY_AUTO_BLOCK=off") {
		t.Errorf("policy_rule should say why: %q", got.Action.PolicyRule)
	}
	if n := metricValue(t, "killswitch_auto_block_withheld_total", label); n != before+1 {
		t.Errorf("withheld counter moved %v → %v, want +1", before, n)
	}
	if drv.applied.Load() != 0 {
		t.Fatal("nothing may be enforced without a human while auto-block is off")
	}

	var view map[string]any
	if status := env.get("/policy", &view); status != 200 {
		t.Fatalf("GET /policy: %d", status)
	}
	if view["auto_block"] != policy.AutoBlockOff || view["auto_block_allowed"] != false ||
		view["auto_block_disabled_reason"] != "auto-block disabled: POLICY_AUTO_BLOCK=off" {
		t.Errorf("GET /policy: auto_block=%v allowed=%v reason=%v", view["auto_block"],
			view["auto_block_allowed"], view["auto_block_disabled_reason"])
	}

	view = nil
	on := newHarness(t, harnessOpts{}) // switched on, allowlist 192.168.1.1
	if status := on.get("/policy", &view); status != 200 || view["auto_block"] != policy.AutoBlockOn ||
		view["auto_block_allowed"] != true || view["auto_block_disabled_reason"] != "" {
		t.Errorf("GET /policy once switched on: %d %v", status, view)
	}
}
