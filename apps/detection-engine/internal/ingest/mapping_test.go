package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
)

// These tests pin what each sensor kind puts in the v2 fields. In 1.x every
// mapper wrote its indicator — or, lacking one, the rule message — into
// Domain, and the killswitch sinkholed Domain.

func parseRow(t *testing.T, src Source, row string) SensorEvent {
	t.Helper()
	ev, err := src.Parse(json.RawMessage(row))
	if err != nil {
		t.Fatalf("%s: %v", src.Name(), err)
	}
	return ev
}

func onlySignal(t *testing.T, a detection.Alert) events.Signal {
	t.Helper()
	if len(a.Signals) != 1 {
		t.Fatalf("expected exactly one signal, got %+v", a.Signals)
	}
	return a.Signals[0]
}

// TestSuricataAlertNamesItsRuleNotADestination: the rule message used to be
// Domain and matched_ioc, so every IDS auto-block failed in the sinkhole.
func TestSuricataAlertNamesItsRuleNotADestination(t *testing.T) {
	ev := parseRow(t, SuricataAlerts{}, `{"ts":1789000000,"flow_id":"1","src_ip":"192.168.1.50","src_port":51544,
		"dest_ip":"203.0.113.7","dest_port":443,"proto":"TCP","alert_signature":"ET MALWARE Cobalt Strike Beacon Observed",
		"alert_category":"Malware C2","alert_severity":1,"alert_signature_id":2031999,"threat_intel":""}`)
	a := ToAlert(ev, nil)

	if a.Domain != "" {
		t.Errorf("domain = %q, want empty: an IDS alert observed no DNS name", a.Domain)
	}
	if a.Target != nil {
		t.Errorf("target = %+v, want none: a rule hit attests a rule, not a destination", a.Target)
	}
	s := onlySignal(t, a)
	if s.Class != detection.SignalIDS || s.Indicator != "2031999" || s.IndicatorType != events.IndicatorSID {
		t.Errorf("signal = %+v, want the rule SID", s)
	}
	if s.Confidence != 80 || a.Confidence != 80 {
		t.Errorf("a severity-1 malware signature scores 80, got %d/%d", s.Confidence, a.Confidence)
	}
	if a.MatchedIoC != "2031999" || a.IoCType != events.IndicatorSID {
		t.Errorf("matched = %q/%q", a.MatchedIoC, a.IoCType)
	}
	if !strings.Contains(a.Summary, "Cobalt Strike") || !strings.Contains(a.Summary, "203.0.113.7:443") {
		t.Errorf("summary %q should carry the rule and the flow", a.Summary)
	}
}

// TestZeekIntelAddressHitTargetsTheAddress: an IP from Zeek Intel was
// accepted as the AdGuard rule ||203.0.113.9^.
func TestZeekIntelAddressHitTargetsTheAddress(t *testing.T) {
	a := ToAlert(parseRow(t, ZeekIntel{}, `{"ts":1789000100,"uid":"C1","src_ip":"192.168.1.60","src_port":40000,
		"dst_ip":"203.0.113.9","dst_port":443,"indicator":"203.0.113.9","indicator_type":"Intel::ADDR",
		"seen_where":"Conn::IN_RESP","sources":["feodo"]}`), nil)

	if a.Domain != "" {
		t.Errorf("domain = %q, want empty for an address hit", a.Domain)
	}
	if a.Target == nil || *a.Target != (events.Target{Type: events.TargetIP, Value: "203.0.113.9"}) {
		t.Errorf("target = %+v, want ip 203.0.113.9", a.Target)
	}
	if s := onlySignal(t, a); s.Class != detection.SignalIoC || s.Indicator != "203.0.113.9" || s.IndicatorType != "ip" {
		t.Errorf("signal = %+v", s)
	}
}

func TestZeekIntelDomainHitTargetsTheDomain(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{Value: "evil.example", Type: "domain", Source: "threatfox", Confidence: 88}})
	a := ToAlert(parseRow(t, ZeekIntel{}, `{"ts":1789000101,"uid":"C2","src_ip":"192.168.1.60","src_port":1,
		"dst_ip":"192.168.1.2","dst_port":53,"indicator":"Evil.Example","indicator_type":"Intel::DOMAIN",
		"seen_where":"DNS::IN_REQUEST","sources":["threatfox"]}`), m)

	want := events.Target{Type: events.TargetDomain, Value: "evil.example"}
	if a.Domain != "evil.example" || a.Target == nil || *a.Target != want {
		t.Errorf("domain=%q target=%+v, want both evil.example", a.Domain, a.Target)
	}
	if s := onlySignal(t, a); s.Confidence != 88 || s.Indicator != "evil.example" {
		t.Errorf("signal = %+v, want the matcher's confidence and the canonical indicator", s)
	}
}

// TestZeekIntelFingerprintHitNamesNothingToBlock: a TLS fingerprint was
// written into Domain and offered to the sinkhole.
func TestZeekIntelFingerprintHitNamesNothingToBlock(t *testing.T) {
	a := ToAlert(parseRow(t, ZeekIntel{}, `{"ts":1789000102,"uid":"C3","src_ip":"192.168.1.60","src_port":1,
		"dst_ip":"198.51.100.9","dst_port":443,"indicator":"t13d3012h2_1d37bd780c83_882d495ac381",
		"indicator_type":"Intel::TLSFP","seen_where":"SSL::IN_TLSFP","sources":["misp"]}`), nil)
	if a.Domain != "" || a.Target != nil {
		t.Errorf("a fingerprint is neither a domain nor a target: domain=%q target=%+v", a.Domain, a.Target)
	}
	if s := onlySignal(t, a); s.Indicator != "t13d3012h2_1d37bd780c83_882d495ac381" || s.IndicatorType != "tlsfp" {
		t.Errorf("signal = %+v, want the fingerprint as the attested indicator", s)
	}
}

func TestBeaconTargetsItsObservedDestination(t *testing.T) {
	named := ToAlert(parseRow(t, MLBeacons{}, `{"ts":1800000000,"src_ip":"192.168.1.50","dst_ip":"198.51.100.20",
		"dst_domain":"Telemetry.Vendor.Example","beacon_score":1.0,"connection_count":288,"confidence":75,
		"severity":"high","beacon_type":"","tags":["beacon"]}`), nil)
	if named.Domain != "telemetry.vendor.example" ||
		named.Target == nil || *named.Target != (events.Target{Type: events.TargetDomain, Value: "telemetry.vendor.example"}) {
		t.Errorf("named beacon: domain=%q target=%+v", named.Domain, named.Target)
	}
	if s := onlySignal(t, named); s.Class != detection.SignalBeacon || s.Confidence != 75 || s.IndicatorType != "domain" {
		t.Errorf("signal = %+v", s)
	}

	bare := ToAlert(parseRow(t, MLBeacons{}, `{"ts":1800000000,"src_ip":"192.168.1.50","dst_ip":"198.51.100.20",
		"dst_domain":"","beacon_score":1.0,"connection_count":288,"confidence":75,"severity":"high",
		"beacon_type":"","tags":["beacon"]}`), nil)
	if bare.Domain != "" {
		t.Errorf("an address-only beacon observed no DNS name, got domain %q", bare.Domain)
	}
	if bare.Target == nil || *bare.Target != (events.Target{Type: events.TargetIP, Value: "198.51.100.20"}) {
		t.Errorf("address-only beacon target = %+v", bare.Target)
	}
	if bare.IoCType != "ip" {
		t.Errorf("ioc_type = %q, want ip (not the 1.x 'beacon')", bare.IoCType)
	}
}

// TestVolumetricAnomalyNamesNoIndicator: the anomaly's "domain" and
// "indicator" used to be the device's OWN address.
func TestVolumetricAnomalyNamesNoIndicator(t *testing.T) {
	a := ToAlert(parseRow(t, MLAnomalies{}, `{"ts":1800000100,"window_start":"2027-01-15 08:00:00",
		"src_ip":"192.168.1.50","anomaly_score":0.95,"confidence":70,"severity":"high","conn_count":900,
		"bytes_out":1,"dst_fanout":3,"model_version":"v1","tags":["anomaly","upload-heavy"]}`), nil)

	if a.Domain != "" || a.Target != nil || a.MatchedIoC != "" {
		t.Errorf("an anomaly is about the device itself: domain=%q target=%+v matched=%q",
			a.Domain, a.Target, a.MatchedIoC)
	}
	s := onlySignal(t, a)
	if s.Class != detection.SignalVolumetric || s.Confidence != 70 || s.Indicator != "" {
		t.Errorf("signal = %+v", s)
	}
	if !strings.Contains(a.Summary, "upload-heavy") {
		t.Errorf("summary %q should describe the anomaly", a.Summary)
	}
}

func TestUnknownKindStillDescribed(t *testing.T) {
	a := ToAlert(SensorEvent{Sensor: "x", Kind: "mystery", SrcIP: "192.168.1.5", Signature: "odd"}, nil)
	if a.Summary == "" || a.Target != nil {
		t.Errorf("unknown kind: %+v", a)
	}
}
