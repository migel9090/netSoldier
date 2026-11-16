package eventmap

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/composite"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/tlsheur"
	"github.com/migel9090/netSoldier/libs/events"
)

func TestAlertToEventCarriesContract(t *testing.T) {
	a := detection.Alert{
		ID:          "DET-abc-42",
		Timestamp:   time.Unix(1_700_000_000, 0).UTC(),
		Summary:     "DNS query for a.evil.example matches threatfox domain indicator evil.example",
		Domain:      "a.evil.example",
		MatchedIoC:  "evil.example",
		IoCType:     "domain",
		ClientIP:    "192.168.1.5",
		ClientMAC:   "aa:bb:cc:dd:ee:ff",
		ClientName:  "laptop",
		Severity:    "critical",
		Confidence:  95,
		Source:      "threatfox",
		Threat:      "cobalt-strike",
		MitreID:     "T1071",
		Tags:        []string{"c2"},
		SignalClass: detection.SignalIoC,
		Signals: []events.Signal{{Class: detection.SignalIoC, Confidence: 95,
			Indicator: "evil.example", IndicatorType: "domain", Source: "threatfox"}},
		Target: &events.Target{Type: events.TargetDomain, Value: "evil.example"},
	}
	ev := AlertToEvent(a)

	if ev.SchemaVersion != events.DetectionSchemaVersion {
		t.Errorf("schema version = %q", ev.SchemaVersion)
	}
	if ev.ID != "DET-abc-42" || ev.Confidence != 95 || ev.ClientMAC != "aa:bb:cc:dd:ee:ff" ||
		ev.ClientName != "laptop" || ev.Summary != a.Summary {
		t.Errorf("core fields not mapped: %+v", ev)
	}
	if ev.Target == nil || *ev.Target != *a.Target || len(ev.Signals) != 1 || ev.Signals[0] != a.Signals[0] {
		t.Errorf("evidence not mapped: target=%+v signals=%+v", ev.Target, ev.Signals)
	}
	if err := ev.Validate(); err != nil {
		t.Fatalf("mapped event must validate: %v", err)
	}
}

func TestAlertToEventCanonicalisesIdentity(t *testing.T) {
	ev := AlertToEvent(detection.Alert{ClientIP: "::ffff:192.168.1.5", ClientMAC: "AA:BB:CC:DD:EE:FF"})
	if ev.ClientIP != "192.168.1.5" || ev.ClientMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("identity not canonical: ip=%q mac=%q", ev.ClientIP, ev.ClientMAC)
	}
}

// TestIoCTypeIsNotRewritten: 1.x coerced unknown ioc_types to "ip", which
// labelled a beacon's destination domain or an anomaly as an IP indicator.
func TestIoCTypeIsNotRewritten(t *testing.T) {
	for _, typ := range []string{"domain", "ip", "cidr", "sid", "cert-sha256", ""} {
		if ev := AlertToEvent(detection.Alert{IoCType: typ}); ev.IoCType != typ {
			t.Errorf("ioc_type %q was changed to %q", typ, ev.IoCType)
		}
	}
}

// TestIncompleteAlertGetsConservativeFallbacks: an alert from a producer that
// sets only the 1.x fields must not gain an indicator or a target it never
// stated — matched_ioc is display text, not evidence.
func TestIncompleteAlertGetsConservativeFallbacks(t *testing.T) {
	ev := AlertToEvent(detection.Alert{
		ID: "DET-abc-1", Timestamp: time.Now(), ClientIP: "192.168.1.9",
		Domain: "evil.example", MatchedIoC: "evil.example", IoCType: "domain",
		Severity: "critical", Confidence: 150, Source: "local", Threat: "c2",
		SignalClass: detection.SignalIoC,
	})
	if len(ev.Signals) != 1 || ev.Signals[0].Class != detection.SignalIoC ||
		ev.Signals[0].Indicator != "" || ev.Signals[0].Confidence != 100 {
		t.Fatalf("fallback signal = %+v, want class only, clamped confidence, no indicator", ev.Signals)
	}
	if ev.Target != nil {
		t.Fatalf("no target may be invented from domain/matched_ioc, got %+v", ev.Target)
	}
	if ev.Summary == "" {
		t.Error("a summary must be supplied")
	}
	if _, ok := ev.AttestedSignal(0); ok {
		t.Error("a fallback signal attests nothing")
	}
}

func TestSignalClassDerivedFromSignals(t *testing.T) {
	one := AlertToEvent(detection.Alert{Signals: []events.Signal{{Class: detection.SignalBeacon}}})
	if one.SignalClass != detection.SignalBeacon {
		t.Errorf("single signal class = %q", one.SignalClass)
	}
	two := AlertToEvent(detection.Alert{Signals: []events.Signal{
		{Class: detection.SignalBeacon}, {Class: detection.SignalIoC}}})
	if two.SignalClass != detection.SignalComposite {
		t.Errorf("two classes = %q, want composite", two.SignalClass)
	}
	if none := AlertToEvent(detection.Alert{}); none.SignalClass != "" || none.Validate() == nil {
		t.Errorf("an alert with no class at all must stay invalid, got %+v", none)
	}
}

func TestSeverityDerivedWhenMissing(t *testing.T) {
	ev := AlertToEvent(detection.Alert{Confidence: 95})
	if ev.Severity != events.SeverityCritical {
		t.Errorf("severity = %q, want critical (derived from confidence)", ev.Severity)
	}
}

// TestEveryProducerEmitsValidV2Events drives each real producer the way the
// engine is wired and checks what would go on the wire: every event
// validates, and `domain` never carries rule text, an address, a fingerprint
// or a decorated string — the values the 1.x engine put there and the
// killswitch then tried to sinkhole.
func TestEveryProducerEmitsValidV2Events(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{
		{Value: "evil-ioc.com", Type: "domain", Source: "threatfox", Confidence: 95},
		{Value: "203.0.113.7", Type: "ip", Source: "feodo", Confidence: 90},
		{Value: "t13d3012h2_1d37bd780c83_882d495ac381", Type: "tlsfp", Source: "misp", Confidence: 92},
	})

	var mu sync.Mutex
	var alerts []detection.Alert
	collect := func(a detection.Alert) {
		mu.Lock()
		alerts = append(alerts, a)
		mu.Unlock()
	}

	// AdGuard path: a domain hit and a DNS-answer IP hit.
	entryTime := time.Now().Add(time.Hour)
	ag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{
			{"question": map[string]string{"name": "a.evil-ioc.com", "type": "A"}, "client": "192.168.1.66", "time": entryTime},
			{"question": map[string]string{"name": "cdn.legit.example", "type": "A"}, "client": "192.168.1.66",
				"time": entryTime.Add(-time.Second), "answer": []map[string]any{{"value": "203.0.113.7", "type": "A", "ttl": 60}}},
		}})
	}))
	t.Cleanup(ag.Close)
	engine := detection.New(adguard.NewClient(ag.URL, "u", "p"), m, 10*time.Millisecond)
	engine.OnAlert = collect
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { engine.Run(ctx); close(done) }()
	deadline := time.Now().Add(time.Minute)
	for {
		mu.Lock()
		n := len(alerts)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	// Sensor paths.
	parse := func(src ingest.Source, row string) ingest.SensorEvent {
		ev, err := src.Parse(json.RawMessage(row))
		if err != nil {
			t.Fatalf("%s: %v", src.Name(), err)
		}
		return ev
	}
	sensor := []ingest.SensorEvent{
		parse(ingest.SuricataAlerts{}, `{"ts":1789000000,"flow_id":"1","src_ip":"192.168.1.50","src_port":51544,
			"dest_ip":"203.0.113.7","dest_port":443,"proto":"TCP","alert_signature":"ET MALWARE Cobalt Strike Beacon Observed",
			"alert_category":"Malware C2","alert_severity":1,"alert_signature_id":2031999,"threat_intel":""}`),
		parse(ingest.ZeekIntel{}, `{"ts":1789000100,"uid":"C1","src_ip":"192.168.1.60","src_port":40000,"dst_ip":"203.0.113.9",
			"dst_port":443,"indicator":"203.0.113.9","indicator_type":"Intel::ADDR","seen_where":"Conn::IN_RESP","sources":["feodo"]}`),
		parse(ingest.ZeekIntel{}, `{"ts":1789000101,"uid":"C2","src_ip":"192.168.1.60","src_port":40000,"dst_ip":"192.168.1.2",
			"dst_port":53,"indicator":"evil-ioc.com","indicator_type":"Intel::DOMAIN","seen_where":"DNS::IN_REQUEST","sources":["threatfox"]}`),
		parse(ingest.ZeekIntel{}, `{"ts":1789000102,"uid":"C3","src_ip":"192.168.1.60","src_port":40000,"dst_ip":"198.51.100.9",
			"dst_port":443,"indicator":"t13d3012h2_1d37bd780c83_882d495ac381","indicator_type":"Intel::TLSFP","seen_where":"SSL::IN_TLSFP","sources":["misp"]}`),
		parse(ingest.MLBeacons{}, `{"ts":1789000200,"src_ip":"192.168.1.50","dst_ip":"198.51.100.20","dst_domain":"",
			"beacon_score":1.0,"connection_count":288,"confidence":75,"severity":"high","beacon_type":"","tags":["beacon"]}`),
		parse(ingest.MLAnomalies{}, `{"ts":1789000300,"window_start":"2027-01-15 08:00:00","src_ip":"192.168.1.50",
			"anomaly_score":0.95,"confidence":70,"severity":"high","conn_count":900,"bytes_out":1,"dst_fanout":3,"model_version":"v1","tags":["anomaly"]}`),
	}
	for _, ev := range sensor {
		collect(ingest.ToAlert(ev, m))
	}

	// TLS heuristics: a fingerprint IoC, and TLS straight to an address.
	tls := tlsheur.New(m, nil, tlsheur.DefaultLocalCIDRs, collect)
	tls.Handle(ingest.SensorEvent{Kind: "tls-client", Timestamp: time.Unix(1789000400, 0), SrcIP: "192.168.1.10",
		DstIP: "203.0.113.5", SNI: "cdn.example", Indicator: "t13d3012h2_1d37bd780c83_882d495ac381", IndicatorType: "tlsfp"})
	tls.Handle(ingest.SensorEvent{Kind: "tls-client", Timestamp: time.Unix(1789000401, 0), SrcIP: "192.168.1.10",
		DstIP: "198.51.100.77", Indicator: "t13x", IndicatorType: "tlsfp"})

	// A composite of what the same device produced.
	corr := composite.New(time.Hour, nil)
	var comp *detection.Alert
	for _, a := range alerts {
		if a.ClientIP == "192.168.1.50" {
			if c := corr.Observe(a); c != nil {
				comp = c
			}
		}
	}
	if comp == nil {
		t.Fatal("expected a composite for 192.168.1.50")
	}
	alerts = append(alerts, *comp)

	if len(alerts) != 11 {
		t.Fatalf("expected 11 detections from the producers, got %d", len(alerts))
	}
	seen := map[string]bool{}
	for _, a := range alerts {
		if a.ID == "" {
			a.ID = detection.NewID() // what Engine.Ingest assigns
		}
		ev := AlertToEvent(a)
		if err := ev.Validate(); err != nil {
			t.Errorf("%s (%s): %v", ev.SignalClass, ev.Summary, err)
			continue
		}
		if seen[ev.ID] {
			t.Errorf("duplicate id %s", ev.ID)
		}
		seen[ev.ID] = true
		if ev.Domain != "" {
			if _, ok := events.CanonicalDomain(ev.Domain); !ok || net.ParseIP(ev.Domain) != nil ||
				strings.ContainsAny(ev.Domain, " (→_") {
				t.Errorf("domain %q is not an observed DNS name (%s)", ev.Domain, ev.Summary)
			}
		}
		if ev.Target != nil {
			switch ev.Target.Type {
			case events.TargetDomain:
				if strings.Contains(ev.Target.Value, "t13d") {
					t.Errorf("a fingerprint became a domain target: %+v", ev.Target)
				}
			case events.TargetIP:
				if ev.Target.Value == ev.ClientIP {
					t.Errorf("the device's own address became a target: %+v (%s)", ev.Target, ev.Summary)
				}
			}
		}
	}
}
