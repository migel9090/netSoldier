package composite

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/eventmap"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/tlsheur"
	"github.com/migel9090/netSoldier/libs/events"
)

// datasetHit is what Suricata's NETSOLDIER ThreatIntel DNS rule reports when
// the queried name is in its ioc-domains dataset, through the real parser.
func datasetHit(t *testing.T, client, domain string, conf int, m *iocmatch.Matcher) detection.Alert {
	t.Helper()
	ti, _ := json.Marshal(map[string]any{"domain": domain, "source": "threatfox", "severity": "medium",
		"confidence": conf, "threat": "AsyncRAT"})
	row, _ := json.Marshal(map[string]any{"ts": 1800000000, "flow_id": "9", "src_ip": client, "src_port": 5353,
		"dest_ip": "192.168.1.2", "dest_port": 53, "proto": "UDP",
		"alert_signature": "NETSOLDIER ThreatIntel DNS query to IoC domain",
		"alert_category":  "A Network Trojan was detected", "alert_severity": 1, "alert_signature_id": 9100001,
		"threat_intel": string(ti)})
	local, _ := ingest.ParseLocalNetworks(ingest.DefaultLocalCIDRs)
	ev, err := ingest.NewSuricataAlerts(local).Parse(row)
	if err != nil {
		t.Fatal(err)
	}
	return ingest.ToAlert(ev, m)
}

// TestSameIndicatorFromTwoSensorsIsOneSignal is the audit's case: one
// ThreatFox indicator at confidence 75, seen by AdGuard and by the Suricata
// dataset rule on the same query. Counted as an ioc plus an independent
// ids-signature, noisy-OR made it 94/critical; it is one piece of evidence
// and stays a single-signal 75, for a human to look at.
func TestSameIndicatorFromTwoSensorsIsOneSignal(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{Value: "c2.midconf.example", Type: "domain", Source: "threatfox", Confidence: 75}})
	adguard := feedHit("192.168.1.50", "c2.midconf.example", "c2.midconf.example", 75)
	suricata := datasetHit(t, "192.168.1.50", "c2.midconf.example", 75, m)

	c := New(15*time.Minute, nil)
	if comp := c.Observe(adguard); comp != nil {
		t.Fatalf("one signal made a composite: %+v", comp)
	}
	if comp := c.Observe(suricata); comp != nil {
		ev := eventmap.AlertToEvent(*comp)
		t.Fatalf("one indicator from two sensors became a %d/%s composite of %v", ev.Confidence, ev.Severity, ev.Signals)
	}
	for _, a := range []detection.Alert{adguard, suricata} {
		ev := eventmap.AlertToEvent(a)
		if ev.SignalClass != events.SignalIoC || ev.Confidence != 75 || len(ev.Signals) != 1 {
			t.Errorf("%s: class=%s conf=%d signals=%v, want a single-signal ioc 75", a.Source, ev.SignalClass, ev.Confidence, ev.Signals)
		}
	}
}

// TestSameIndicatorAcrossKnownBadClassesCollapses: the collapse is by
// indicator across the known-bad classes, whichever class each sensor gives
// it: a signature that names the feed's own indicator is that feed match
// again, and the stronger of the two is kept.
func TestSameIndicatorAcrossKnownBadClassesCollapses(t *testing.T) {
	feed := feedHit("192.168.1.50", "c2.midconf.example", "c2.midconf.example", 75)
	sig := feedHit("192.168.1.50", "c2.midconf.example", "c2.midconf.example", 60)
	sig.SignalClass, sig.Source = detection.SignalIDS, "et-open"
	sig.Signals[0].Class = detection.SignalIDS

	c := New(15*time.Minute, nil)
	c.Observe(sig)
	if comp := c.Observe(feed); comp != nil {
		t.Fatalf("one indicator attested by ioc and ids-signature became a composite at %d", comp.Confidence)
	}
}

// TestFeedHitPlusBeaconToSameDomainCorroborates: reputation and behaviour
// are independent evidence even when they name the same domain. A feed hit
// on a domain plus a device beaconing to that very domain is the case a
// two-signal auto-block gate (POLICY_AUTO_MIN_SIGNALS=2) exists for: a
// two-class composite whose known-bad signal still vouches for the target.
func TestFeedHitPlusBeaconToSameDomainCorroborates(t *testing.T) {
	const c2 = "c2.highconf.example"
	c := New(15*time.Minute, nil)
	c.Observe(feedHit("192.168.1.50", c2, c2, 95))
	comp := c.Observe(beaconAlert(t, "192.168.1.50", c2))
	if comp == nil {
		t.Fatal("a feed hit and a beacon to the same domain did not corroborate")
	}
	ev := eventmap.AlertToEvent(*comp)
	if classes := ev.ContributingClasses(); len(classes) != 2 || ev.SignalClass != events.SignalComposite {
		t.Fatalf("classes = %v (%s), want ioc and beacon", classes, ev.SignalClass)
	}
	if ev.Target == nil || *ev.Target != (events.Target{Type: events.TargetDomain, Value: c2}) {
		t.Fatalf("target = %+v, want the listed domain", ev.Target)
	}
	if s, ok := ev.AttestedSignal(90); !ok || s.Class != events.SignalIoC || s.Confidence != 95 {
		t.Errorf("AttestedSignal(90) = %+v, %v: the feed hit must still vouch for the target", s, ok)
	}
	if ev.Confidence != combine([]int{95, 75}) {
		t.Errorf("confidence = %d, want %d", ev.Confidence, combine([]int{95, 75}))
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("composite breaks the contract: %v", err)
	}
}

// TestHeuristicsSharingAnIndicatorStayDistinct: two heuristics naming one
// destination (a TLS finding on an SNI and a beacon to that name), or a TLS
// fingerprint heuristic and a feed hit on that fingerprint, keep counting as
// distinct classes.
func TestHeuristicsSharingAnIndicatorStayDistinct(t *testing.T) {
	const fp = "t13d3012h2_1d37bd780c83_882d495ac381"
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{Value: fp, Type: "tlsfp", Source: "misp", Confidence: 75}})
	var tlsAlert detection.Alert
	tlsheur.New(m, nil, tlsheur.DefaultLocalCIDRs, func(a detection.Alert) { tlsAlert = a }).
		Handle(ingest.SensorEvent{Kind: "tls-client", Timestamp: time.Unix(1800000000, 0), SrcIP: "192.168.1.50",
			DstIP: "203.0.113.5", Indicator: fp, IndicatorType: "tlsfp"})
	intel := ingest.ToAlert(ingest.SensorEvent{Sensor: "zeek", Kind: "intel-hit", Timestamp: time.Unix(1800000001, 0),
		SrcIP: "192.168.1.50", DstIP: "203.0.113.5", Indicator: fp, IndicatorType: "tlsfp", Source: "misp"}, m)

	c := New(15*time.Minute, nil)
	c.Observe(tlsAlert)
	if comp := c.Observe(intel); comp == nil || len(comp.Signals) != 2 {
		t.Fatalf("a TLS heuristic and a feed hit on its fingerprint: composite %+v, want two signals", comp)
	}

	sni := detection.Alert{ClientIP: "192.168.1.51", SignalClass: detection.SignalTLS, Confidence: 30,
		Signals: []events.Signal{{Class: detection.SignalTLS, Confidence: 30,
			Indicator: "telemetry.vendor.example", IndicatorType: events.IndicatorDomain}}}
	c2 := New(15*time.Minute, nil)
	c2.Observe(sni)
	if comp := c2.Observe(beaconAlert(t, "192.168.1.51", "telemetry.vendor.example")); comp == nil || len(comp.Signals) != 2 {
		t.Fatalf("two heuristics on one destination: composite %+v, want two signals", comp)
	}
}

// TestDifferentIndicatorsStillCorroborate: the collapse must not eat real
// corroboration — a feed match on one name and a beacon to another are two
// signals.
func TestDifferentIndicatorsStillCorroborate(t *testing.T) {
	c := New(15*time.Minute, nil)
	c.Observe(feedHit("192.168.1.50", "c2.midconf.example", "c2.midconf.example", 75))
	comp := c.Observe(beaconAlert(t, "192.168.1.50", "telemetry.vendor.example"))
	if comp == nil || len(comp.Signals) != 2 {
		t.Fatalf("composite = %+v, want two signals", comp)
	}
}

func TestIndicatorKeyCanonical(t *testing.T) {
	a := detection.Alert{Signals: []events.Signal{{Indicator: "Evil.Example.", IndicatorType: "domain"}}}
	b := detection.Alert{MatchedIoC: "evil.example", IoCType: "domain"}
	if indicatorKey(a) == "" || indicatorKey(a) != indicatorKey(b) {
		t.Errorf("keys %q / %q", indicatorKey(a), indicatorKey(b))
	}
	v6a := detection.Alert{MatchedIoC: "2001:DB8::1", IoCType: "ip"}
	v6b := detection.Alert{MatchedIoC: "2001:db8:0::1", IoCType: "ip"}
	if indicatorKey(v6a) != indicatorKey(v6b) {
		t.Errorf("one address, two keys: %q / %q", indicatorKey(v6a), indicatorKey(v6b))
	}
	if indicatorKey(detection.Alert{MatchedIoC: "x"}) != "" {
		t.Error("an untyped indicator must not be compared")
	}
}
