package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/eventmap"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
)

// pendingAlone mirrors the killswitch's default pending bar: confidence 50
// and severity medium.
func pendingAlone(a detection.Alert) bool {
	rank := map[string]int{events.SeverityLow: 0, events.SeverityMedium: 1, events.SeverityHigh: 2, events.SeverityCritical: 3}
	return a.Confidence >= 50 && rank[a.Severity] >= 1
}

func suricataRow(src, dst string, srcPort, dstPort int, sig, category string, sev int, ti string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"ts": 1800000000, "flow_id": "42", "src_ip": src, "src_port": srcPort, "dest_ip": dst,
		"dest_port": dstPort, "proto": "TCP", "alert_signature": sig, "alert_category": category,
		"alert_severity": sev, "alert_signature_id": 2033000, "threat_intel": ti,
	})
	return b
}

// TestSuricataServerToClientSignatureNamesTheLocalClient is the audit's
// case: a severity-1 "ET MALWARE ... Beacon Response" fires on the packet
// from the C2 server to the LAN device. It arrived with confidence 0, which
// the killswitch ignores, and with the internet host as the client.
func TestSuricataServerToClientSignatureNamesTheLocalClient(t *testing.T) {
	ev, err := NewSuricataAlerts(defaultLocal(t)).Parse(suricataRow("185.220.101.7", "192.168.1.50", 443, 51544,
		"ET MALWARE Cobalt Strike Beacon Response", "Malware Command and Control Activity Detected", 1, ""))
	if err != nil {
		t.Fatal(err)
	}
	if ev.SrcIP != "192.168.1.50" || ev.SrcPort != 51544 || ev.DstIP != "185.220.101.7" || ev.DstPort != 443 {
		t.Fatalf("oriented flow = %s:%d -> %s:%d, want the LAN device as the client and the C2 host as the remote side",
			ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort)
	}
	a := ToAlert(ev, nil)
	if a.ClientIP != "192.168.1.50" {
		t.Errorf("client_ip = %s, want the local side", a.ClientIP)
	}
	if a.Confidence != 80 || a.Severity != events.SeverityHigh || !pendingAlone(a) {
		t.Errorf("confidence=%d severity=%s: a malware/C2 rule must clear the pending bar on its own",
			a.Confidence, a.Severity)
	}
	if a.SignalClass != detection.SignalIDS || a.Target != nil {
		t.Errorf("class=%s target=%+v: a rule hit is a signature and names nothing to block", a.SignalClass, a.Target)
	}
	if !strings.Contains(a.Summary, "192.168.1.50:51544") || !strings.Contains(a.Summary, "185.220.101.7:443") {
		t.Errorf("summary %q should name both sides", a.Summary)
	}
}

// TestSuricataPolicyRuleStaysWeak: an informational or policy rule must not
// reach a human on its own — not even when its classtype gives it severity 1
// (policy-violation has priority 1 in classification.config).
func TestSuricataPolicyRuleStaysWeak(t *testing.T) {
	s := NewSuricataAlerts(defaultLocal(t))
	for _, sev := range []int{1, 3} {
		ev, err := s.Parse(suricataRow("192.168.1.50", "93.184.216.34", 51544, 80,
			"ET POLICY curl User-Agent Outbound", "Potential Corporate Privacy Violation", sev, ""))
		if err != nil {
			t.Fatal(err)
		}
		a := ToAlert(ev, nil)
		if a.Confidence > 20 || a.Severity != events.SeverityLow || pendingAlone(a) {
			t.Errorf("severity %d ET POLICY: confidence=%d severity=%s, want weak", sev, a.Confidence, a.Severity)
		}
		if a.ClientIP != "192.168.1.50" {
			t.Errorf("outbound rule: client = %s", a.ClientIP)
		}
	}
}

func TestSignatureScoringTable(t *testing.T) {
	cases := []struct {
		sig, category string
		sev, want     int
	}{
		{"ET MALWARE Win32/Agent Tesla CnC Checkin", "A Network Trojan was detected", 1, 80},
		{"ET MALWARE something", "Potentially Bad Traffic", 2, 70}, // the ruleset category wins
		{"ETPRO TROJAN x", "", 3, 60},
		{"ET EXPLOIT Apache log4j RCE Attempt", "Attempted Administrator Privilege Gain", 1, 65},
		{"ET WEB_SERVER x", "", 2, 55},
		{"ET HUNTING Suspicious x", "A Network Trojan was detected", 1, 45},
		{"ET COINMINER x", "", 3, 25},
		{"ET INFO Observed DNS Query to .cloud TLD", "Potentially Bad Traffic", 2, 15},
		{"ET POLICY x", "", 1, 20},
		{"ET SCAN Nmap", "", 3, 10},
		{"SURICATA STREAM ESTABLISHED packet out of window", "Generic Protocol Command Decode", 3, 10},
		{"NETSOLDIER local rule", "Malware Command and Control Activity Detected", 2, 70},
		{"GPL ATTACK_RESPONSE id check returned root", "Potentially Bad Traffic", 2, 35},
		{"Local rule", "misc activity", 1, 20},
		{"Local rule", "", 1, 50},
		{"Local rule", "Some Custom Category", 2, 35},
		{"Local rule", "", 4, 20},
	}
	for _, c := range cases {
		if got := signatureConfidence(c.sig, c.category, c.sev); got != c.want {
			t.Errorf("%q / %q / sev %d = %d, want %d", c.sig, c.category, c.sev, got, c.want)
		}
	}
	for family, scores := range signatureScores {
		if scores[0] >= 90 {
			t.Errorf("%s reaches the auto-block bar on a signature alone", family)
		}
	}
	if s := signatureScores[familyMalware]; s[2] < 50 {
		t.Error("a malware/C2 rule must clear the pending bar at every severity")
	}
	if s := signatureScores[familyInformational]; s[0] >= 50 {
		t.Error("an informational rule must never clear the pending bar")
	}
}

// TestSuricataDatasetHitIsAFeedMatch: the NETSOLDIER ThreatIntel rules fire
// because a feed indicator is in their dataset. That is the feed match
// itself, not an independent signature.
func TestSuricataDatasetHitIsAFeedMatch(t *testing.T) {
	ti := `{"domain":"C2.MidConf.Example","source":"threatfox","severity":"medium","confidence":75,"threat":"AsyncRAT"}`
	ev, err := NewSuricataAlerts(defaultLocal(t)).Parse(suricataRow("192.168.1.50", "192.168.1.2", 5353, 53,
		"NETSOLDIER ThreatIntel DNS query to IoC domain", "A Network Trojan was detected", 1, ti))
	if err != nil {
		t.Fatal(err)
	}
	a := ToAlert(ev, nil)
	if a.SignalClass != detection.SignalIoC || a.Confidence != 75 || a.Source != "threatfox" || a.Threat != "AsyncRAT" {
		t.Errorf("class=%s conf=%d source=%s threat=%s, want the feed's ioc at 75", a.SignalClass, a.Confidence, a.Source, a.Threat)
	}
	s := onlySignal(t, a)
	if s.Class != detection.SignalIoC || s.Indicator != "c2.midconf.example" || s.IndicatorType != events.IndicatorDomain {
		t.Errorf("signal = %+v, want the canonical indicator", s)
	}
	if a.Target == nil || *a.Target != (events.Target{Type: events.TargetDomain, Value: "c2.midconf.example"}) {
		t.Errorf("target = %+v", a.Target)
	}
	if a.ClientIP != "192.168.1.50" {
		t.Errorf("client = %s: a query to the local resolver is from the device", a.ClientIP)
	}
	if err := toEvent(a).Validate(); err != nil {
		t.Errorf("dataset hit breaks the contract: %v", err)
	}

	// The live matcher has the indicator at a lowered confidence: it wins,
	// like for a Zeek Intel hit.
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{Value: "c2.midconf.example", Type: "domain", Source: "threatfox", Confidence: 40}})
	if got := ToAlert(ev, m); got.Confidence != 40 {
		t.Errorf("matcher confidence not applied: %d", got.Confidence)
	}

	// An address dataset, a feed confidence out of range, no severity.
	ev, _ = NewSuricataAlerts(defaultLocal(t)).Parse(suricataRow("192.168.1.50", "203.0.113.9", 50000, 443,
		"NETSOLDIER ThreatIntel traffic to IoC IP", "A Network Trojan was detected", 1,
		`{"ip":"203.0.113.9","source":"feodo","confidence":250}`))
	a = ToAlert(ev, nil)
	if a.Confidence != 100 || a.Severity != events.SeverityCritical || a.Target == nil || a.Target.Value != "203.0.113.9" {
		t.Errorf("ip dataset hit: conf=%d sev=%s target=%+v", a.Confidence, a.Severity, a.Target)
	}

	// A context without the value still is a feed match, with nothing to
	// enforce.
	ev, _ = NewSuricataAlerts(defaultLocal(t)).Parse(suricataRow("192.168.1.50", "198.51.100.1", 50000, 443,
		"NETSOLDIER ThreatIntel TLS SNI matches IoC domain", "A Network Trojan was detected", 1,
		`{"source":"urlhaus","confidence":60}`))
	a = ToAlert(ev, nil)
	if a.SignalClass != detection.SignalIoC || a.Target != nil || a.Confidence != 60 {
		t.Errorf("valueless context: class=%s target=%+v conf=%d", a.SignalClass, a.Target, a.Confidence)
	}

	// A blob that is not a context is an ordinary rule hit.
	if ev, _ := NewSuricataAlerts(defaultLocal(t)).Parse(suricataRow("192.168.1.50", "198.51.100.1", 1, 2,
		"ET MALWARE x", "", 1, `not json`)); ev.Kind != "ids-alert" {
		t.Errorf("garbage context made kind %s", ev.Kind)
	}
}

func toEvent(a detection.Alert) events.DetectionEvent {
	if a.ID == "" {
		a.ID = detection.NewID()
	}
	return eventmap.AlertToEvent(a)
}

// TestSuricataNeitherSideLocalKeepsPacketSource: with LOCAL_NETWORKS not
// covering either address there is nothing to orient by.
func TestSuricataNeitherSideLocalKeepsPacketSource(t *testing.T) {
	ev, _ := NewSuricataAlerts(defaultLocal(t)).Parse(suricataRow("198.51.100.1", "203.0.113.9", 1, 2, "ET SCAN x", "", 3, ""))
	if ev.SrcIP != "198.51.100.1" {
		t.Errorf("src = %s", ev.SrcIP)
	}
}
