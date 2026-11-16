package composite

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/eventmap"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/libs/events"
)

// The scenarios below are built from the real sensor parsers, so they carry
// exactly what the engine would forward.

func beaconAlert(t *testing.T, src, domain string) detection.Alert {
	t.Helper()
	row := json.RawMessage(`{"ts":1800000000,"src_ip":"` + src + `","dst_ip":"198.51.100.20","dst_domain":"` +
		domain + `","beacon_score":1.0,"connection_count":288,"confidence":75,"severity":"high","beacon_type":"","tags":["beacon"]}`)
	ev, err := ingest.MLBeacons{}.Parse(row)
	if err != nil {
		t.Fatal(err)
	}
	return ingest.ToAlert(ev, nil)
}

func anomalyAlert(t *testing.T, src string) detection.Alert {
	t.Helper()
	row := json.RawMessage(`{"ts":1800000100,"window_start":"2027-01-15 08:00:00","src_ip":"` + src +
		`","anomaly_score":0.95,"confidence":70,"severity":"high","conn_count":900,"bytes_out":1,"dst_fanout":3,"model_version":"v1","tags":["anomaly","upload-heavy"]}`)
	ev, err := ingest.MLAnomalies{}.Parse(row)
	if err != nil {
		t.Fatal(err)
	}
	return ingest.ToAlert(ev, nil)
}

func suricataAlert(t *testing.T, src, sig string, sev int) detection.Alert {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"ts": 1800000200, "flow_id": "7", "src_ip": src, "src_port": 50000,
		"dest_ip": "93.184.216.34", "dest_port": 80, "proto": "TCP", "alert_signature": sig,
		"alert_category": "x", "alert_severity": sev, "alert_signature_id": 2013028, "threat_intel": ""})
	ev, err := ingest.SuricataAlerts{}.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return ingest.ToAlert(ev, nil)
}

// feedHit mirrors what the AdGuard path builds for a domain-IoC match.
func feedHit(src, queried, indicator string, conf int) detection.Alert {
	return detection.Alert{
		ID: detection.NewID(), Timestamp: time.Now(), Summary: "DNS query for " + queried,
		Domain: queried, ClientIP: src, MatchedIoC: indicator, IoCType: events.IndicatorDomain,
		Severity: detection.SeverityForConfidence(conf), Source: "threatfox", Confidence: conf,
		SignalClass: detection.SignalIoC,
		Signals: []events.Signal{{Class: detection.SignalIoC, Confidence: conf,
			Indicator: indicator, IndicatorType: events.IndicatorDomain, Source: "threatfox"}},
		Target: &events.Target{Type: events.TargetDomain, Value: indicator},
	}
}

var idPattern = regexp.MustCompile(events.DetectionIDPattern)

// TestCompositeHasItsOwnID: composites used to be emitted with no id at all,
// so the action they drove had a blank detection_id in the audit trail.
func TestCompositeHasItsOwnID(t *testing.T) {
	c := New(time.Minute, nil)
	b := beaconAlert(t, "192.168.1.52", "telemetry.vendor.example")
	b.ID = detection.NewID()
	c.Observe(b)
	comp := c.Observe(anomalyAlert(t, "192.168.1.52"))
	if comp == nil {
		t.Fatal("expected a composite")
	}
	if !idPattern.MatchString(comp.ID) {
		t.Fatalf("composite id %q does not match %s", comp.ID, events.DetectionIDPattern)
	}
	if comp.ID == b.ID {
		t.Error("the composite must not reuse a contributing signal's id")
	}

	again := c.Observe(anomalyAlert(t, "192.168.1.52"))
	if again == nil || again.ID == comp.ID {
		t.Errorf("each composite emission is its own detection, got %v after %q", again, comp.ID)
	}
}

// TestCompositeSignalsCarryOwnConfidence: the event used to say which classes
// contributed but not how strongly each did, so a 93 built from heuristics
// looked the same as a 93 from a feed.
func TestCompositeSignalsCarryOwnConfidence(t *testing.T) {
	c := New(time.Minute, nil)
	c.Observe(feedHit("192.168.1.51", "x.weak-ioc.example", "weak-ioc.example", 60))
	comp := c.Observe(beaconAlert(t, "192.168.1.51", "telemetry.vendor.example"))
	if comp == nil {
		t.Fatal("expected a composite")
	}

	byClass := map[string]events.Signal{}
	for _, s := range comp.Signals {
		byClass[s.Class] = s
	}
	ioc, beacon := byClass[detection.SignalIoC], byClass[detection.SignalBeacon]
	if ioc.Confidence != 60 || ioc.Indicator != "weak-ioc.example" || ioc.IndicatorType != events.IndicatorDomain {
		t.Errorf("ioc signal = %+v, want its own confidence 60 and indicator", ioc)
	}
	if beacon.Confidence != 75 || beacon.Indicator != "telemetry.vendor.example" {
		t.Errorf("beacon signal = %+v, want its own confidence 75 and destination", beacon)
	}
	if comp.Confidence <= 75 {
		t.Errorf("combined confidence %d should exceed either signal", comp.Confidence)
	}
}

// TestCompositeTargetIsTheKnownBadIndicator is the weak-IoC-plus-beacon case:
// the target used to come from the highest-confidence signal, the beacon, so
// a feed hit on one name blocked the name the beacon pointed at.
func TestCompositeTargetIsTheKnownBadIndicator(t *testing.T) {
	c := New(time.Minute, nil)
	c.Observe(beaconAlert(t, "192.168.1.53", "telemetry.vendor.example"))
	comp := c.Observe(feedHit("192.168.1.53", "c2.real-threat.example", "real-threat.example", 60))
	if comp == nil {
		t.Fatal("expected a composite")
	}
	want := events.Target{Type: events.TargetDomain, Value: "real-threat.example"}
	if comp.Target == nil || *comp.Target != want {
		t.Fatalf("target = %+v, want the feed's indicator %+v, not the beacon's destination", comp.Target, want)
	}

	ev := eventmap.AlertToEvent(*comp)
	if err := ev.Validate(); err != nil {
		t.Fatalf("composite event invalid: %v", err)
	}
	if _, ok := ev.AttestedSignal(60); !ok {
		t.Error("the feed hit attests the target at its own confidence")
	}
	if _, ok := ev.AttestedSignal(90); ok {
		t.Error("a 60-confidence feed hit must not attest at 90 just because the composite reached 90+")
	}
}

// TestCompositeTargetFallsBackToHeuristicDestination is the informational
// IDS alert + beacon + anomaly case. The IDS signal attests a rule, not a
// destination, so the only concrete target is where the beacon went — and
// nothing known-bad vouches for it, which the policy can now see.
func TestCompositeTargetFallsBackToHeuristicDestination(t *testing.T) {
	c := New(15*time.Minute, nil)
	c.Observe(beaconAlert(t, "192.168.1.50", "time.cloudflare.com"))
	c.Observe(anomalyAlert(t, "192.168.1.50"))
	comp := c.Observe(suricataAlert(t, "192.168.1.50", "ET INFO Observed DNS Query to .cloud TLD", 3))
	if comp == nil {
		t.Fatal("expected a composite")
	}
	want := events.Target{Type: events.TargetDomain, Value: "time.cloudflare.com"}
	if comp.Target == nil || *comp.Target != want {
		t.Fatalf("target = %+v, want the beacon destination", comp.Target)
	}

	ev := eventmap.AlertToEvent(*comp)
	if err := ev.Validate(); err != nil {
		t.Fatalf("composite event invalid: %v", err)
	}
	if !ev.HasKnownBadSignal() {
		t.Error("the IDS hit is still a known-bad class")
	}
	if s, ok := ev.AttestedSignal(0); ok {
		t.Errorf("no known-bad signal names time.cloudflare.com, got %+v", s)
	}
	if ev.Domain != "time.cloudflare.com" {
		t.Errorf("domain = %q, want the observed beacon name", ev.Domain)
	}
}

func TestCompositeWithNothingConcreteHasNoTarget(t *testing.T) {
	c := New(15*time.Minute, nil)
	c.Observe(anomalyAlert(t, "192.168.1.54"))
	comp := c.Observe(suricataAlert(t, "192.168.1.54", "ET POLICY curl User-Agent Outbound", 1))
	if comp == nil {
		t.Fatal("expected a composite")
	}
	if comp.Target != nil {
		t.Fatalf("an IDS rule hit plus a volumetric anomaly name nothing to block, got target %+v", comp.Target)
	}
	ev := eventmap.AlertToEvent(*comp)
	if err := ev.Validate(); err != nil {
		t.Fatalf("composite event invalid: %v", err)
	}
	if ev.SignalClass != events.SignalComposite || len(ev.Signals) != 2 {
		t.Errorf("signal_class=%q signals=%+v", ev.SignalClass, ev.Signals)
	}
	if ev.Summary == "" {
		t.Error("summary must be set")
	}
}

// TestCompositeTargetPrefersStrongestKnownBad: among several known-bad
// signals with targets, the most confident one names the target.
func TestCompositeTargetPrefersStrongestKnownBad(t *testing.T) {
	strongIDS := suricataAlert(t, "192.168.1.55", "ET MALWARE x", 1)
	strongIDS.Confidence, strongIDS.Signals[0].Confidence = 95, 95
	strongIDS.Target = &events.Target{Type: events.TargetIP, Value: "93.184.216.34"}

	c := New(time.Minute, nil)
	c.Observe(feedHit("192.168.1.55", "a.evil.example", "evil.example", 70))
	comp := c.Observe(strongIDS)
	if comp == nil {
		t.Fatal("expected a composite")
	}
	if comp.Target == nil || comp.Target.Value != "93.184.216.34" {
		t.Errorf("target = %+v, want the 95-confidence signal's", comp.Target)
	}
}

func TestSignalOfSynthesizesForUnlabelledProducer(t *testing.T) {
	s := signalOf(signal{class: detection.SignalBeacon, confidence: 140,
		alert: detection.Alert{Source: "rita"}})
	if s.Class != detection.SignalBeacon || s.Confidence != 100 || s.Source != "rita" || s.Indicator != "" {
		t.Errorf("signalOf = %+v", s)
	}
}
