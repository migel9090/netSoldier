package policy

import (
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// ---- the invariant, over generated events --------------------------------

// attestedByOracle is the auto-block precondition written out from the
// specification, independently of events.AttestedSignal: the target is a
// domain, and one known-bad signal names exactly that domain and clears the
// bar on its own.
func attestedByOracle(ev events.DetectionEvent, bar int) bool {
	if ev.Target == nil || ev.Target.Type != events.TargetDomain {
		return false
	}
	target, ok := events.CanonicalDomain(ev.Target.Value)
	if !ok {
		return false
	}
	for _, s := range ev.Signals {
		if s.Class != events.SignalIoC && s.Class != events.SignalIDS {
			continue
		}
		if s.Confidence < bar || s.IndicatorType != events.IndicatorDomain {
			continue
		}
		if ind, ok := events.CanonicalDomain(s.Indicator); ok && ind == target {
			return true
		}
	}
	return false
}

// specAutoBlock is the whole rule (a)–(e).
func specAutoBlock(p *Policy, ev events.DetectionEvent) bool {
	if p.Allowlist.Contains(ev.ClientMAC, ev.ClientIP) || p.Infrastructure.Contains(ev.ClientMAC, ev.ClientIP) {
		return false
	}
	bar := severityRank(p.AutoMinSeverity)
	if bar == 0 || ev.Confidence < p.AutoMinConfidence || severityRank(ev.Severity) < bar {
		return false
	}
	if !attestedByOracle(ev, p.AutoMinConfidence) {
		return false
	}
	classes := map[string]bool{}
	for _, s := range ev.Signals {
		classes[s.Class] = true
	}
	if p.AutoMinSignals > 1 && len(classes) > 1 && len(classes) < p.AutoMinSignals {
		return false
	}
	if !p.AutoBlock || len(p.RejectedEntries) > 0 || (p.Allowlist.Len() == 0 && !p.AllowEmptyAllowlist) {
		return false
	}
	return true
}

var (
	genDomains = []string{"evil.example", "Evil.Example.", "sub.evil.example", "time.cloudflare.com",
		"telemetry.vendor.example", "raw.githubusercontent.com", "c2.real-threat.example", "", "not a domain"}
	genIPs        = []string{"203.0.113.7", "::ffff:203.0.113.7", "192.168.1.1", "192.168.001.001"}
	genOther      = []string{"2013028", "2031999", "e7d705a3286e19ea42f587b344ee6865", ""}
	genClasses    = []string{events.SignalIoC, events.SignalIDS, events.SignalTLS, events.SignalBeacon, events.SignalVolumetric, events.SignalComposite, "", "IOC", "dga"}
	genIndTypes   = []string{events.IndicatorDomain, events.IndicatorIP, events.IndicatorSID, events.IndicatorJA3, events.IndicatorURL, "", "Domain"}
	genSeverities = []string{events.SeverityCritical, events.SeverityHigh, events.SeverityMedium, events.SeverityLow, "", "CRITICAL"}
	genActions    = []string{events.ActionDNSSinkhole, events.ActionARPIsolate, events.ActionSwitchACL}
	genClientIPs  = []string{"192.168.1.100", "192.168.1.1", "192.168.1.53", "10.0.0.5", ""}
	genClientMACs = []string{"", "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "02:00:00:00:00:01"}
)

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

// highish skews confidences towards the auto-block bar, where the
// interesting decisions are.
func highish(r *rand.Rand) int {
	if r.IntN(2) == 0 {
		return 80 + r.IntN(21)
	}
	return r.IntN(101)
}

func genPolicy(r *rand.Rand) *Policy {
	p := DefaultPolicy()
	p.AutoMinConfidence = highish(r)
	p.AutoMinSeverity = pick(r, genSeverities[:4])
	p.PendMinConfidence = r.IntN(101)
	p.PendMinSeverity = pick(r, genSeverities[:4])
	p.AutoMinSignals = 1 + r.IntN(4)
	p.DefaultAction = pick(r, genActions)
	if r.IntN(4) > 0 {
		_ = p.Allowlist.AddIP("192.168.1.1")
		_ = p.Allowlist.AddMAC("aa:bb:cc:dd:ee:ff")
	}
	p.AllowEmptyAllowlist = r.IntN(2) == 0
	p.AutoBlock = r.IntN(6) > 0
	if r.IntN(6) == 0 {
		p.RejectedEntries = []string{`ALLOWLIST_MACS entry "aa:bb:cc:dd:ee:fg"`}
	}
	if r.IntN(3) == 0 {
		_ = p.Infrastructure.AddIP("192.168.1.53")
	}
	return p
}

func genIndicator(r *rand.Rand, typ string) string {
	switch typ {
	case events.IndicatorDomain, "Domain":
		return pick(r, genDomains)
	case events.IndicatorIP:
		return pick(r, genIPs)
	default:
		if r.IntN(4) == 0 {
			return pick(r, genDomains) // a domain under the wrong type
		}
		return pick(r, genOther)
	}
}

// genEvent mixes fully random events with near misses: an event that meets
// the rule, then perturbed. Random events alone almost never land on the
// boundary, which is where a wrong rule would show.
func genEvent(r *rand.Rand) events.DetectionEvent {
	if r.IntN(2) == 0 {
		return perturb(r, nearMiss(r))
	}
	return randomEvent(r)
}

func nearMiss(r *rand.Rand) events.DetectionEvent {
	target := pick(r, genDomains[:7])
	ev := events.DetectionEvent{
		Confidence:  90 + r.IntN(11),
		Severity:    events.SeverityCritical,
		ClientIP:    "192.168.1.100",
		SignalClass: events.SignalComposite,
		Target:      &events.Target{Type: events.TargetDomain, Value: target},
		Signals: []events.Signal{{Class: pick(r, genClasses[:2]), Confidence: 90 + r.IntN(11),
			IndicatorType: events.IndicatorDomain, Indicator: target}},
	}
	for n := r.IntN(3); n > 0; n-- {
		typ := pick(r, genIndTypes)
		ev.Signals = append(ev.Signals, events.Signal{Class: pick(r, genClasses[2:5]),
			Confidence: highish(r), IndicatorType: typ, Indicator: genIndicator(r, typ)})
	}
	return ev
}

func perturb(r *rand.Rand, ev events.DetectionEvent) events.DetectionEvent {
	for n := r.IntN(3); n > 0; n-- {
		s := &ev.Signals[r.IntN(len(ev.Signals))]
		switch r.IntN(9) {
		case 0:
			s.Class = pick(r, genClasses)
		case 1:
			s.Confidence = r.IntN(101)
		case 2:
			s.IndicatorType = pick(r, genIndTypes)
		case 3:
			s.Indicator = genIndicator(r, s.IndicatorType)
		case 4:
			ev.Target = &events.Target{Type: pick(r, []string{events.TargetDomain, events.TargetIP, "mac"}),
				Value: pick(r, append(append([]string{}, genDomains...), genIPs...))}
		case 5:
			ev.Target = nil
		case 6:
			ev.Severity = pick(r, genSeverities)
		case 7:
			ev.Confidence = r.IntN(101)
		case 8:
			ev.ClientIP, ev.ClientMAC = pick(r, genClientIPs), pick(r, genClientMACs)
		}
	}
	return ev
}

func randomEvent(r *rand.Rand) events.DetectionEvent {
	ev := events.DetectionEvent{
		Confidence: highish(r),
		Severity:   pick(r, genSeverities),
		ClientIP:   pick(r, genClientIPs),
		ClientMAC:  pick(r, genClientMACs),
	}
	for n := r.IntN(5); n > 0; n-- {
		typ := pick(r, genIndTypes)
		ev.Signals = append(ev.Signals, events.Signal{
			Class: pick(r, genClasses), Confidence: highish(r),
			IndicatorType: typ, Indicator: genIndicator(r, typ),
		})
	}
	switch r.IntN(6) {
	case 0: // no target
	case 1:
		ev.Target = &events.Target{Type: events.TargetIP, Value: pick(r, genIPs)}
	case 2:
		ev.Target = &events.Target{Type: pick(r, []string{"mac", "Domain", ""}), Value: pick(r, genDomains)}
	case 3, 4:
		// point the target at one signal's indicator: the shape that must
		// auto-block only when that signal is known-bad and strong enough
		if len(ev.Signals) > 0 {
			s := pick(r, ev.Signals)
			ev.Target = &events.Target{Type: events.TargetDomain, Value: s.Indicator}
			break
		}
		fallthrough
	default:
		ev.Target = &events.Target{Type: events.TargetDomain, Value: pick(r, genDomains)}
	}
	ev.SignalClass = pick(r, []string{events.SignalComposite, events.SignalIoC, ""})
	return ev
}

// checkInvariant evaluates one generated (policy, event) pair.
func checkInvariant(t *testing.T, p *Policy, ev events.DetectionEvent) string {
	t.Helper()
	d := p.Evaluate(ev)
	if d.Action == "auto_block" {
		if !attestedByOracle(ev, p.AutoMinConfidence) {
			t.Fatalf("auto-blocked without a known-bad signal attesting the domain target at %d:\n"+
				"event=%+v\npolicy=%+v\ndecision=%+v", p.AutoMinConfidence, ev, p, d)
		}
		if d.ActionType != events.ActionDNSSinkhole {
			t.Fatalf("automatic action type %q, want dns_sinkhole (default action %q)", d.ActionType, p.DefaultAction)
		}
		if d.Withheld != "" {
			t.Fatalf("an auto_block decision cannot be withheld: %+v", d)
		}
	}
	if got, want := d.Action == "auto_block", specAutoBlock(p, ev); got != want {
		t.Fatalf("auto_block=%v, specification says %v:\nevent=%+v\npolicy=%+v\ndecision=%+v",
			got, want, ev, p, d)
	}
	if d.Withheld != "" && d.Action != "pending" {
		t.Fatalf("a withheld auto-block must be pending: %+v", d)
	}
	return d.Action
}

// TestNoAutoBlockWithoutAttestedDomainTarget is the property behind KS-2:
// across random signal mixes, confidences, severities, targets and policy
// settings, nothing is auto-blocked unless a known-bad signal names the
// domain target and clears the bar on its own — and everything that meets
// the whole rule is.
func TestNoAutoBlockWithoutAttestedDomainTarget(t *testing.T) {
	n := 200_000
	if testing.Short() {
		n = 20_000
	}
	r := rand.New(rand.NewPCG(0x4b53, 0x2d32))
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		counts[checkInvariant(t, genPolicy(r), genEvent(r))]++
	}
	// The generator has to reach every outcome, or the property is vacuous.
	for _, outcome := range []string{"auto_block", "pending", "ignore"} {
		if counts[outcome] < n/200 {
			t.Fatalf("generator produced only %d %s decisions out of %d: %v", counts[outcome], outcome, n, counts)
		}
	}
	t.Logf("decisions over %d generated events: %v", n, counts)
}

// FuzzNoAutoBlockWithoutAttestedDomainTarget lets `go test -fuzz` search
// for a counterexample; the plain test run checks the seeds.
func FuzzNoAutoBlockWithoutAttestedDomainTarget(f *testing.F) {
	for _, seed := range []uint64{1, 2, 3, 0x4b53} {
		f.Add(seed, seed^0x9e3779b97f4a7c15)
	}
	f.Fuzz(func(t *testing.T, a, b uint64) {
		r := rand.New(rand.NewPCG(a, b))
		for i := 0; i < 50; i++ {
			checkInvariant(t, genPolicy(r), genEvent(r))
		}
	})
}

// ---- the auditors' scenarios, in the v2 shape ------------------------------

// auditPolicy is the shipped proxmox-soc posture with automation on:
// corroboration required, the router allowlisted.
func auditPolicy(t *testing.T) *Policy {
	t.Helper()
	p := DefaultPolicy()
	p.AutoBlock = true
	p.AutoMinSignals = 2
	if err := p.Allowlist.AddIP("192.168.1.1"); err != nil {
		t.Fatal(err)
	}
	return p
}

func auditComposite(client string, conf int, target *events.Target, signals ...events.Signal) events.DetectionEvent {
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            "DET-audit-1",
		Timestamp:     time.Now().UTC(),
		Summary:       "corroborating signals for " + client,
		ClientIP:      client,
		Severity:      events.SeverityCritical,
		Confidence:    conf,
		Source:        "composite",
		SignalClass:   events.SignalComposite,
		Signals:       signals,
		Target:        target,
	}
}

func domainTarget(d string) *events.Target {
	return &events.Target{Type: events.TargetDomain, Value: d}
}

func wantPending(t *testing.T, p *Policy, ev events.DetectionEvent, reason string) {
	t.Helper()
	if err := ev.Validate(); err != nil {
		t.Fatalf("scenario is not a contract-valid event: %v", err)
	}
	d := p.Evaluate(ev)
	if d.Action != "pending" {
		t.Fatalf("got %q, want pending (reason: %s)", d.Action, d.Reason)
	}
	if !strings.Contains(d.Reason, reason) {
		t.Errorf("policy_rule %q should say %q", d.Reason, reason)
	}
}

// TestInfoSignaturePlusHeuristicsDoesNotBlockBeaconDestination is the
// auditor's live run: an "ET INFO" Suricata alert (confidence 0, a rule id
// for an indicator), a beacon to time.cloudflare.com (75) and a volumetric
// anomaly (70) combine to 93/critical. The only domain anywhere is the
// beacon's destination, which no feed listed; it was auto-blocked.
func TestInfoSignaturePlusHeuristicsDoesNotBlockBeaconDestination(t *testing.T) {
	p := auditPolicy(t)
	for _, idsConfidence := range []int{0, 100} { // whatever the engine scores Suricata at
		ev := auditComposite("192.168.1.50", 93, domainTarget("time.cloudflare.com"),
			events.Signal{Class: events.SignalBeacon, Confidence: 75, Indicator: "time.cloudflare.com",
				IndicatorType: events.IndicatorDomain, Source: "rita"},
			events.Signal{Class: events.SignalIDS, Confidence: idsConfidence, Indicator: "2013028",
				IndicatorType: events.IndicatorSID, Source: "et-open"},
			events.Signal{Class: events.SignalVolumetric, Confidence: 70, Source: "iforest"},
		)
		ev.Domain = "time.cloudflare.com"
		wantPending(t, p, ev, "no known-bad signal names the target time.cloudflare.com")
	}
}

// TestWeakFeedHitDoesNotBlockTelemetryDomain: a confidence-0 URLhaus host
// (how threat-intel-sync exports feeds without a score) plus a beacon to
// telemetry.vendor.example and a volumetric anomaly. Whichever domain the
// engine names as the target, nothing vouches for it strongly enough.
func TestWeakFeedHitDoesNotBlockTelemetryDomain(t *testing.T) {
	p := auditPolicy(t)
	signals := []events.Signal{
		{Class: events.SignalIoC, Confidence: 0, Indicator: "raw.githubusercontent.com",
			IndicatorType: events.IndicatorDomain, Source: "urlhaus"},
		{Class: events.SignalBeacon, Confidence: 75, Indicator: "telemetry.vendor.example",
			IndicatorType: events.IndicatorDomain, Source: "rita"},
		{Class: events.SignalVolumetric, Confidence: 70, Source: "iforest"},
	}
	t.Run("target is the beacon destination", func(t *testing.T) {
		wantPending(t, p, auditComposite("192.168.1.50", 93, domainTarget("telemetry.vendor.example"), signals...),
			"no known-bad signal names the target telemetry.vendor.example")
	})
	t.Run("target is the weak feed hit", func(t *testing.T) {
		wantPending(t, p, auditComposite("192.168.1.50", 93, domainTarget("raw.githubusercontent.com"), signals...),
			"too weak on its own: ioc confidence 0 < 90")
	})
	t.Run("a real mid-confidence IoC after a beacon", func(t *testing.T) {
		ev := auditComposite("192.168.1.53", 90, domainTarget("telemetry.vendor.example"),
			signals[1], events.Signal{Class: events.SignalIoC, Confidence: 60,
				Indicator: "c2.real-threat.example", IndicatorType: events.IndicatorDomain, Source: "threatfox"})
		wantPending(t, p, ev, "no known-bad signal names the target telemetry.vendor.example")
	})
}

// TestWeakIoCPlusBeaconIsPending: a 60 feed hit and a 75 beacon on the
// same domain combine to exactly 90/critical. The feed alone does not clear
// the bar, so corroboration by a heuristic must not let it.
func TestWeakIoCPlusBeaconIsPending(t *testing.T) {
	p := auditPolicy(t)
	ev := auditComposite("192.168.1.60", 90, domainTarget("evil.example"),
		domainSig(events.SignalIoC, 60, "evil.example"), domainSig(events.SignalBeacon, 75, "evil.example"))
	wantPending(t, p, ev, "the known-bad signal for evil.example is too weak on its own: ioc confidence 60 < 90")
}

// TestSameIndicatorFromTwoSensorsIsPending: AdGuard's feed match and a
// Suricata dataset rule on the same domain arrive as two classes at 70 each,
// combining to 91 and passing a two-signal gate — the effective bar fell
// from 90 to about 69. One indicator seen twice is still one weak claim.
func TestSameIndicatorFromTwoSensorsIsPending(t *testing.T) {
	p := auditPolicy(t)
	ioc := events.Signal{Class: events.SignalIoC, Confidence: 70, Indicator: "evil.example",
		IndicatorType: events.IndicatorDomain, Source: "threatfox"}
	ids := events.Signal{Class: events.SignalIDS, Confidence: 70, Indicator: "evil.example",
		IndicatorType: events.IndicatorDomain, Source: "suricata-dataset"}
	wantPending(t, p, auditComposite("192.168.1.61", 91, domainTarget("evil.example"), ioc, ids),
		"too weak on its own")

	ids.Confidence = 95
	if d := p.Evaluate(auditComposite("192.168.1.61", 99, domainTarget("evil.example"), ioc, ids)); d.Action != "auto_block" {
		t.Fatalf("one strong attestation of the target should auto-block, got %q (%s)", d.Action, d.Reason)
	}
}

// TestAutoBlockIsAlwaysSinkhole: POLICY_DEFAULT_ACTION=arp_isolate made a
// single feed match isolate a device at layer 2 with no human. The default
// is what a human approves; the automatic path is the DNS sinkhole.
func TestAutoBlockIsAlwaysSinkhole(t *testing.T) {
	for _, def := range genActions {
		t.Run(def, func(t *testing.T) {
			t.Setenv("POLICY_DEFAULT_ACTION", def)
			t.Setenv("POLICY_AUTO_BLOCK", AutoBlockOn)
			t.Setenv("ALLOWLIST_IPS", "192.168.1.1")
			p := mustLoad(t)

			auto := p.Evaluate(feedMatch(95, events.SeverityCritical))
			if auto.Action != "auto_block" || auto.ActionType != events.ActionDNSSinkhole {
				t.Fatalf("auto path: %q via %q, want auto_block via dns_sinkhole", auto.Action, auto.ActionType)
			}
			pending := p.Evaluate(feedMatch(60, events.SeverityMedium))
			if pending.Action != "pending" || pending.ActionType != def {
				t.Fatalf("pending path: %q via %q, want pending via %q", pending.Action, pending.ActionType, def)
			}
		})
	}
}

// TestPendingReasonNamesTheFailedCondition: every way an otherwise
// auto-block-grade event can fall short says which way in policy_rule.
func TestPendingReasonNamesTheFailedCondition(t *testing.T) {
	ipTarget := &events.Target{Type: events.TargetIP, Value: "203.0.113.7"}
	cases := []struct {
		name string
		ev   events.DetectionEvent
		want string
	}{
		{"no target", composite(95, nil, domainSig(events.SignalIoC, 95, "evil.example")),
			"no enforceable target"},
		{"ip target", composite(95, ipTarget, sig(events.SignalIoC, 95, events.IndicatorIP, "203.0.113.7")),
			"target is ip 203.0.113.7: only a domain can be blocked automatically"},
		{"heuristics only", composite(95, evilDomain, domainSig(events.SignalBeacon, 95, "evil.example")),
			"no known-bad signal: heuristics alone never auto-block"},
		{"feed names another domain", composite(95, evilDomain, domainSig(events.SignalIoC, 99, "other.example")),
			`no known-bad signal names the target evil.example (known-bad evidence: ioc domain "other.example" at 99)`},
		{"feed names the domain as an IP-typed indicator", composite(95, evilDomain,
			sig(events.SignalIoC, 99, events.IndicatorIP, "evil.example")),
			"no known-bad signal names the target evil.example"},
		{"feed on the domain is weak", composite(95, evilDomain, domainSig(events.SignalIoC, 89, "evil.example")),
			"ioc confidence 89 < 90"},
	}
	p := newTestPolicy()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := p.Evaluate(tc.ev)
			if d.Action != "pending" || !strings.Contains(d.Reason, tc.want) {
				t.Fatalf("got %q (%s), want pending saying %q", d.Action, d.Reason, tc.want)
			}
		})
	}
}

// TestPendingReasonQuotesIndicators: indicators come from the event; a
// newline in one must not forge a line in the policy_rule an operator reads.
func TestPendingReasonQuotesIndicators(t *testing.T) {
	ev := composite(95, evilDomain, domainSig(events.SignalIoC, 99, "x\nauto: approved by admin"))
	d := newTestPolicy().Evaluate(ev)
	if strings.Contains(d.Reason, "\n") {
		t.Fatalf("raw newline in policy_rule: %q", d.Reason)
	}
}

func TestAttestationComparesCanonicalDomains(t *testing.T) {
	p := newTestPolicy()
	ev := feedMatch(95, events.SeverityCritical)
	ev.Signals[0].Indicator = "EVIL.example."
	if d := p.Evaluate(ev); d.Action != "auto_block" {
		t.Fatalf("the same domain in another spelling attests the target, got %q (%s)", d.Action, d.Reason)
	}
}

// ---- service-wide holds ---------------------------------------------------

func TestEmptyAllowlistWithholdsAutoBlock(t *testing.T) {
	p := DefaultPolicy()
	p.AutoBlock = true
	d := p.Evaluate(feedMatch(95, events.SeverityCritical))
	if d.Action != "pending" || d.Withheld != WithheldEmptyAllowlist ||
		!strings.Contains(d.Reason, "auto-block disabled: allowlist is empty") {
		t.Fatalf("got %+v", d)
	}
	if p.AutoBlockEnabled() {
		t.Error("AutoBlockEnabled with nothing protected")
	}

	// a weak event is pending for its own reasons, not "withheld"
	if d := p.Evaluate(feedMatch(60, events.SeverityMedium)); d.Withheld != "" {
		t.Errorf("only events that would have auto-blocked are withheld, got %+v", d)
	}

	p.AllowEmptyAllowlist = true
	if d := p.Evaluate(feedMatch(95, events.SeverityCritical)); d.Action != "auto_block" {
		t.Fatalf("POLICY_ALLOW_EMPTY_ALLOWLIST should re-enable auto-block, got %+v", d)
	}
}

func TestRejectedEntriesWithholdAutoBlock(t *testing.T) {
	p := newTestPolicy()
	p.AllowEmptyAllowlist = true
	p.RejectedEntries = []string{`ALLOWLIST_MACS entry "aa:bb:cc:dd:ee:fg"`}
	d := p.Evaluate(feedMatch(95, events.SeverityCritical))
	if d.Action != "pending" || d.Withheld != WithheldInvalidProtection ||
		!strings.Contains(d.Reason, "1 protection entry was rejected at start-up") {
		t.Fatalf("got %+v", d)
	}
}

// TestNoUsableEnforcementWithholdsAutoBlock: with the DNS sinkhole not
// configured, a detection that met every condition was approved by the
// policy and then failed for want of a driver. It is queued for a human,
// and its policy_rule says why.
func TestNoUsableEnforcementWithholdsAutoBlock(t *testing.T) {
	p := newTestPolicy()
	missing := errors.New(`action type "dns_sinkhole" is not available: ADGUARD_USER/ADGUARD_PASSWORD not set`)
	p.AutoEnforcement = func() error { return missing }
	d := p.Evaluate(feedMatch(95, events.SeverityCritical))
	if d.Action != "pending" || d.Withheld != WithheldNoEnforcement ||
		!strings.Contains(d.Reason, "no usable enforcement is configured") || !strings.Contains(d.Reason, "ADGUARD_USER") {
		t.Fatalf("got %+v", d)
	}
	if p.AutoBlockEnabled() {
		t.Error("AutoBlockEnabled with nothing to enforce through")
	}
	if hold, label := p.AutoBlockHold(); label != WithheldNoEnforcement || !strings.Contains(hold, "no usable enforcement") {
		t.Errorf("AutoBlockHold = %q, %q", hold, label)
	}
	// Switched off, the switch is the reason: nothing would have used it.
	p.AutoBlock = false
	if _, label := p.AutoBlockHold(); label != WithheldAutoBlockOff {
		t.Errorf("auto-block off: held by %q", label)
	}
	// Usable again: auto-block.
	p.AutoBlock = true
	p.AutoEnforcement = func() error { return nil }
	if d := p.Evaluate(feedMatch(95, events.SeverityCritical)); d.Action != "auto_block" {
		t.Fatalf("with the sinkhole usable: %+v", d)
	}
}

func TestInfrastructureClientIsIgnored(t *testing.T) {
	p := newTestPolicy()
	_ = p.Infrastructure.AddIP("192.168.1.53")
	ev := feedMatch(99, events.SeverityCritical)
	ev.ClientIP = "192.168.1.53"
	if d := p.Evaluate(ev); d.Action != "ignore" || !strings.Contains(d.Reason, "protected infrastructure") {
		t.Fatalf("an event from the DNS server must never become an action, got %+v", d)
	}
	if p.Allowlist.Len() != 2 {
		t.Error("infrastructure must not count as operator allowlist entries")
	}
}

func TestUnknownAutoSeverityBarNeverAutoBlocks(t *testing.T) {
	p := newTestPolicy()
	p.AutoMinSeverity = "CRITICAL_TYPO"
	if d := p.Evaluate(feedMatch(100, events.SeverityLow)); d.Action == "auto_block" {
		t.Fatalf("an unknown severity bar must not rank 0: %+v", d)
	}
}
