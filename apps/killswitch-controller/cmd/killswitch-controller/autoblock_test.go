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
	pol.AutoMinSignals = 2
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	sink := drivers.NewSinkholeDriver(ag.srv.URL, "u", "p")
	env := newEvalEnvWith(t, pol, func(string) (drivers.Driver, error) { return sink, nil })

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
			got := env.post(t, tc.ev)
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
	pol.DefaultAction = events.ActionARPIsolate
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	byType := map[string]*recordingDriver{
		events.ActionDNSSinkhole: {}, events.ActionARPIsolate: {}, events.ActionSwitchACL: {},
	}
	env := newEvalEnvWith(t, pol, func(at string) (drivers.Driver, error) { return byType[at], nil })

	auto := env.post(t, criticalIoCEvent())
	if auto.Decision.Action != "auto_block" || auto.Action == nil || auto.Action.ActionType != events.ActionDNSSinkhole {
		t.Fatalf("auto-block must enforce through the DNS sinkhole, got %+v", auto)
	}
	if byType[events.ActionDNSSinkhole].applied.Load() != 1 || byType[events.ActionARPIsolate].applied.Load() != 0 {
		t.Fatal("only the sinkhole driver may run without a human")
	}

	held := env.post(t, withDomainTarget(testEvent(60, events.SeverityMedium), "maybe.example"))
	if held.Action == nil || held.Action.State != events.StatePending || held.Action.ActionType != events.ActionARPIsolate {
		t.Fatalf("the default action is what a human approves, got %+v", held.Action)
	}
}

// TestPendingOnlyModeCountsEveryWithheldAutoBlock: started with a rejected
// allowlist entry, the service must make each auto-block it holds back
// visible — once per detection, not once per delivery.
func TestPendingOnlyModeCountsEveryWithheldAutoBlock(t *testing.T) {
	pol := policy.DefaultPolicy()
	if err := pol.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	pol.RejectedEntries = []string{`ALLOWLIST_MACS entry "aa:bb:cc:dd:ee:fg"`}
	drv := &recordingDriver{}
	env := newEvalEnvWith(t, pol, func(string) (drivers.Driver, error) { return drv, nil })
	label := map[string]string{"reason": policy.WithheldInvalidProtection}
	before := metricValue(t, "killswitch_auto_block_withheld_total", label)

	ev := criticalIoCEvent()
	got := env.post(t, ev)
	if got.Decision.Action != "pending" || got.Decision.Withheld != policy.WithheldInvalidProtection ||
		got.Action == nil || got.Action.State != events.StatePending {
		t.Fatalf("got %+v, want a withheld pending action", got)
	}
	if !strings.Contains(got.Action.PolicyRule, "protection entry was rejected at start-up") {
		t.Errorf("policy_rule should say why: %q", got.Action.PolicyRule)
	}
	if again := env.post(t, ev); !again.Duplicate {
		t.Fatalf("repeat delivery: %+v", again)
	}
	env.post(t, testEvent(60, events.SeverityMedium)) // would not have auto-blocked anyway
	env.post(t, criticalIoCEvent())

	if got := metricValue(t, "killswitch_auto_block_withheld_total", label); got != before+2 {
		t.Fatalf("withheld counter moved %v → %v, want +2", before, got)
	}
	if drv.applied.Load() != 0 {
		t.Fatal("nothing may be enforced in pending-only mode")
	}
}
