package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
)

func TestSuricataAlertParse(t *testing.T) {
	row := json.RawMessage(`{"ts":1789000000,"flow_id":"1234567890123456789","src_ip":"192.168.1.50",
		"src_port":51544,"dest_ip":"203.0.113.7","dest_port":443,"proto":"TCP",
		"alert_signature":"ET MALWARE Cobalt Strike Beacon","alert_category":"Malware C2",
		"alert_severity":1,"alert_signature_id":2031999,
		"threat_intel":"{\"source\":\"threatfox\",\"severity\":\"critical\",\"confidence\":95,\"threat\":\"CobaltStrike\"}"}`)

	ev, key, err := SuricataAlerts{}.Parse(row)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Sensor != "suricata" || ev.Kind != "ids-alert" {
		t.Errorf("bad sensor/kind: %s/%s", ev.Sensor, ev.Kind)
	}
	// datajson enrichment overrides rule severity (high) with feed context
	if ev.Severity != "critical" || ev.Confidence != 95 || ev.Source != "threatfox" || ev.Threat != "CobaltStrike" {
		t.Errorf("threat_intel not applied: %+v", ev)
	}
	if ev.FlowID != "1234567890123456789" {
		t.Errorf("uint64 flow_id mangled: %s", ev.FlowID)
	}
	if want := "1234567890123456789/2031999/1789000000"; key != want {
		t.Errorf("key = %s, want %s", key, want)
	}
}

func TestSuricataSeverityWithoutIntel(t *testing.T) {
	for sev, want := range map[int]string{1: "high", 2: "medium", 3: "low"} {
		row := json.RawMessage(fmt.Sprintf(
			`{"ts":1789000000,"flow_id":"1","src_ip":"a","src_port":1,"dest_ip":"b","dest_port":2,
			  "proto":"TCP","alert_signature":"sig","alert_category":"cat","alert_severity":%d,
			  "alert_signature_id":7,"threat_intel":""}`, sev))
		ev, _, err := SuricataAlerts{}.Parse(row)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Severity != want {
			t.Errorf("severity %d -> %s, want %s", sev, ev.Severity, want)
		}
	}
}

func TestZeekIntelParseAndNormalize(t *testing.T) {
	row := json.RawMessage(`{"ts":1789000100,"uid":"CxUAB2kZ1","src_ip":"192.168.1.60","src_port":40000,
		"dst_ip":"198.51.100.9","dst_port":443,"indicator":"t13d3012h2_1d37bd780c83_882d495ac381",
		"indicator_type":"Intel::TLSFP","seen_where":"SSL::IN_TLSFP","sources":["misp"]}`)

	ev, key, err := ZeekIntel{}.Parse(row)
	if err != nil {
		t.Fatal(err)
	}
	if ev.IndicatorType != "tlsfp" {
		t.Errorf("intel type not normalized: %s", ev.IndicatorType)
	}
	if ev.Kind != "intel-hit" || ev.Source != "misp" {
		t.Errorf("bad kind/source: %s/%s", ev.Kind, ev.Source)
	}
	if !strings.HasPrefix(key, "CxUAB2kZ1/t13d") {
		t.Errorf("bad key: %s", key)
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
	if a.MatchedIoC != "ET SCAN Nmap" || a.Threat != "ET SCAN Nmap" {
		t.Errorf("signature fallback missing: %+v", a)
	}
	if a.MitreID == "" {
		t.Errorf("expected derived mitre, got none")
	}
}

func TestPollerCursorAndDedupe(t *testing.T) {
	// Two polls: the second repeats the last row of the first (same second)
	// plus one new row — the repeat must be deduplicated.
	responses := []string{
		`{"ts":1789000000,"uid":"A","src_ip":"1.1.1.1","src_port":1,"dst_ip":"2.2.2.2","dst_port":2,"indicator":"x.example","indicator_type":"Intel::DOMAIN","seen_where":"DNS","sources":[]}
{"ts":1789000005,"uid":"B","src_ip":"1.1.1.1","src_port":1,"dst_ip":"2.2.2.2","dst_port":2,"indicator":"y.example","indicator_type":"Intel::DOMAIN","seen_where":"DNS","sources":[]}`,
		`{"ts":1789000005,"uid":"B","src_ip":"1.1.1.1","src_port":1,"dst_ip":"2.2.2.2","dst_port":2,"indicator":"y.example","indicator_type":"Intel::DOMAIN","seen_where":"DNS","sources":[]}
{"ts":1789000010,"uid":"C","src_ip":"1.1.1.1","src_port":1,"dst_ip":"2.2.2.2","dst_port":2,"indicator":"z.example","indicator_type":"Intel::DOMAIN","seen_where":"DNS","sources":[]}`,
	}
	call := 0
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		queries = append(queries, string(body[:n]))
		if call < len(responses) {
			fmt.Fprintln(w, responses[call])
		}
		call++
	}))
	defer srv.Close()

	var got []SensorEvent
	p := NewPoller(NewCHClient(srv.URL, "netsoldier"), ZeekIntel{}, time.Hour, func(ev SensorEvent) {
		got = append(got, ev)
	})
	p.cursor = time.Unix(1789000000, 0).UTC()

	for i := 0; i < 2; i++ {
		if err := p.poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	if len(got) != 3 {
		t.Fatalf("expected 3 unique events, got %d: %+v", len(got), got)
	}
	if got[0].Indicator != "x.example" || got[1].Indicator != "y.example" || got[2].Indicator != "z.example" {
		t.Errorf("wrong events: %+v", got)
	}
	if p.cursor != time.Unix(1789000010, 0).UTC() {
		t.Errorf("cursor = %v, want 1789000010", p.cursor)
	}
	if !strings.Contains(queries[1], "toDateTime(1789000005)") {
		t.Errorf("second query should start at advanced cursor: %s", queries[1])
	}
}
