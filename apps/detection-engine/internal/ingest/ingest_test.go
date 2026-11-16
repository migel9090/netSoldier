package ingest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
)

func TestSuricataAlertParse(t *testing.T) {
	row := json.RawMessage(`{"ts":1789000000,"flow_id":"1234567890123456789","src_ip":"192.168.1.50",
		"src_port":51544,"dest_ip":"203.0.113.7","dest_port":443,"proto":"TCP",
		"alert_signature":"ET MALWARE Cobalt Strike Beacon","alert_category":"Malware Command and Control Activity Detected",
		"alert_severity":1,"alert_signature_id":2031999,"threat_intel":""}`)

	ev, err := NewSuricataAlerts(defaultLocal(t)).Parse(row)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Sensor != "suricata" || ev.Kind != "ids-alert" {
		t.Errorf("bad sensor/kind: %s/%s", ev.Sensor, ev.Kind)
	}
	if ev.FlowID != "1234567890123456789" {
		t.Errorf("uint64 flow_id mangled: %s", ev.FlowID)
	}
	if ev.SrcIP != "192.168.1.50" || ev.DstIP != "203.0.113.7" || ev.Source != "et-open" {
		t.Errorf("outbound alert: src=%s dst=%s source=%s", ev.SrcIP, ev.DstIP, ev.Source)
	}
}

func TestZeekIntelParseAndNormalize(t *testing.T) {
	row := json.RawMessage(`{"ts":1789000100,"uid":"CxUAB2kZ1","src_ip":"192.168.1.60","src_port":40000,
		"dst_ip":"198.51.100.9","dst_port":443,"indicator":"t13d3012h2_1d37bd780c83_882d495ac381",
		"indicator_type":"Intel::TLSFP","seen_where":"SSL::IN_TLSFP","sources":["misp"]}`)

	ev, err := ZeekIntel{}.Parse(row)
	if err != nil {
		t.Fatal(err)
	}
	if ev.IndicatorType != "tlsfp" {
		t.Errorf("intel type not normalized: %s", ev.IndicatorType)
	}
	if ev.Kind != "intel-hit" || ev.Source != "misp" {
		t.Errorf("bad kind/source: %s/%s", ev.Kind, ev.Source)
	}

	for in, want := range map[string]string{
		"Intel::DOMAIN": "domain", "Intel::ADDR": "ip", "Intel::SUBNET": "ip",
		"Intel::JA3": "ja3", "Intel::CERT_HASH": "cert-sha256", "Intel::URL": "url",
	} {
		if got := normalizeIntelType(in); got != want {
			t.Errorf("normalizeIntelType(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestToAlertEnrichesIntelHitFromMatcher(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{
		Value: "t13d3012h2_1d37bd780c83_882d495ac381", Type: "tlsfp",
		Source: "misp", Threat: "c2 beacon", Confidence: 92,
	}})

	ev := SensorEvent{
		Sensor: "zeek", Kind: "intel-hit", Timestamp: time.Unix(1789000100, 0),
		SrcIP: "192.168.1.60", Indicator: "t13d3012h2_1d37bd780c83_882d495ac381",
		IndicatorType: "tlsfp", Source: "zeek-intel",
	}
	a := ToAlert(ev, m)
	if a.Severity != "critical" || a.Confidence != 92 {
		t.Errorf("matcher enrichment missing: %+v", a)
	}
	if a.MitreID != "T1071" {
		t.Errorf("mitre = %s, want T1071 (c2 threat text)", a.MitreID)
	}
	if a.ClientIP != "192.168.1.60" {
		t.Errorf("client = %s", a.ClientIP)
	}
}

func TestToAlertIDSFallbacks(t *testing.T) {
	ev := SensorEvent{
		Sensor: "suricata", Kind: "ids-alert", Timestamp: time.Unix(1789000000, 0),
		SrcIP: "192.168.1.50", Signature: "ET SCAN Nmap", Severity: "low", Source: "et-open",
	}
	a := ToAlert(ev, nil)
	if a.Threat != "ET SCAN Nmap" || !strings.Contains(a.Summary, "ET SCAN Nmap") {
		t.Errorf("rule text belongs in threat and summary: %+v", a)
	}
	if a.MatchedIoC != "" || a.Domain != "" {
		t.Errorf("rule text must not become an indicator or a domain: %+v", a)
	}
	if a.MitreID == "" {
		t.Errorf("expected derived mitre, got none")
	}
	if a.ID != "" || a.Record != "" {
		t.Errorf("an event from no stored row: id %q record %q, want both empty", a.ID, a.Record)
	}
}

// TestAlertNamesItsRow: the same row read twice — in the overlap, or after a
// restart — names the same record, which the pipeline's ledger recognises.
// The id is left to the engine: ids are per process.
func TestAlertNamesItsRow(t *testing.T) {
	ev := SensorEvent{Kind: "intel-hit", SrcIP: "192.168.1.60", Origin: "zeek_intel", RowKey: "123456789"}
	a, b := ToAlert(ev, nil), ToAlert(ev, nil)
	if a.Record == "" || a.Record != b.Record || a.ID != "" {
		t.Fatalf("records %q / %q, id %q", a.Record, b.Record, a.ID)
	}
	ev.RowKey = "123456790"
	if ToAlert(ev, nil).Record == a.Record {
		t.Error("two rows share a record")
	}
	ev.Origin, ev.RowKey = "suricata_alerts", "123456789"
	if ToAlert(ev, nil).Record == a.Record {
		t.Error("the same hash in two tables shares a record")
	}
}

func defaultLocal(t *testing.T) LocalNetworks {
	t.Helper()
	l, bad := ParseLocalNetworks(DefaultLocalCIDRs)
	if len(bad) > 0 {
		t.Fatalf("default local networks do not parse: %v", bad)
	}
	return l
}

func TestLocalNetworks(t *testing.T) {
	l, bad := ParseLocalNetworks([]string{"192.168.0.0/16", " 2001:db8:1::/48 ", "", "not-a-cidr"})
	if len(bad) != 1 || bad[0] != "not-a-cidr" {
		t.Errorf("bad entries = %v", bad)
	}
	for ip, want := range map[string]bool{
		"192.168.1.50": true, "::ffff:192.168.1.50": true, "2001:db8:1::7": true,
		"127.0.0.1": true, "fe80::1": true, "169.254.1.1": true,
		"203.0.113.7": false, "2001:db8:2::7": false, "": false, "garbage": false,
	} {
		if got := l.Contains(ip); got != want {
			t.Errorf("Contains(%q) = %v, want %v", ip, got, want)
		}
	}
}
