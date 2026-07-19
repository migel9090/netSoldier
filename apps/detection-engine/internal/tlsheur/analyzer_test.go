package tlsheur

import (
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
)

type fakeResolver map[string]string

func (f fakeResolver) Get(ip string) string { return f[ip] }

func tlsEvent(src, dst, sni, ja3, ja4 string) ingest.SensorEvent {
	return ingest.SensorEvent{
		Sensor: "zeek", Kind: "tls-client", Timestamp: time.Unix(1789000000, 0),
		SrcIP: src, DstIP: dst, SNI: sni, JA3: ja3,
		Indicator: ja4, IndicatorType: "ja4",
	}
}

func newTestAnalyzer(m *iocmatch.Matcher, r Resolver) (*Analyzer, *[]detection.Alert) {
	var alerts []detection.Alert
	a := New(m, r, DefaultLocalCIDRs, func(al detection.Alert) { alerts = append(alerts, al) })
	return a, &alerts
}

func TestJA4IoCMatch(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{
		Value: "t13d3012h2_1d37bd780c83_882d495ac381", Type: "ja4",
		Source: "misp", Threat: "c2", Confidence: 95,
	}})
	a, alerts := newTestAnalyzer(m, fakeResolver{})

	a.Handle(tlsEvent("192.168.1.10", "203.0.113.5", "cdn.example", "", "t13d3012h2_1d37bd780c83_882d495ac381"))

	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	got := (*alerts)[0]
	if got.Severity != "critical" || got.Source != "misp" || got.Confidence != 95 {
		t.Errorf("ioc metadata not carried: %+v", got)
	}
}

func TestSNIDNSMismatch(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{"203.0.113.5": "www.legit-cdn.com"})

	a.Handle(tlsEvent("192.168.1.10", "203.0.113.5", "evil.attacker.net", "", "t13x"))

	if len(*alerts) != 1 {
		t.Fatalf("expected mismatch alert, got %d", len(*alerts))
	}
	if (*alerts)[0].Threat != "sni-dns-mismatch" || (*alerts)[0].Severity != "low" {
		t.Errorf("unexpected alert: %+v", (*alerts)[0])
	}
}

func TestSNIDNSSameRegistrableDomainNoAlert(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{"203.0.113.5": "edge7.example.com"})

	// SNI www.example.com vs resolved edge7.example.com — same eTLD+1
	a.Handle(tlsEvent("192.168.1.10", "203.0.113.5", "www.example.com", "", "t13x"))

	if len(*alerts) != 0 {
		t.Fatalf("CDN-style multi-host must not alert: %+v", *alerts)
	}
}

func TestDNSLessTLS(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{})

	a.Handle(tlsEvent("192.168.1.10", "198.51.100.77", "", "", "t13x"))

	if len(*alerts) != 1 || (*alerts)[0].Threat != "dns-less-tls" {
		t.Fatalf("expected dns-less-tls alert: %+v", *alerts)
	}
}

func TestLocalDestinationIgnored(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{})

	a.Handle(tlsEvent("192.168.1.10", "192.168.1.20", "", "", "t13x"))
	a.Handle(tlsEvent("192.168.1.10", "127.0.0.1", "", "", "t13x"))

	if len(*alerts) != 0 {
		t.Fatalf("local destinations must not alert: %+v", *alerts)
	}
}

func TestSuppressionWindow(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{})

	ev := tlsEvent("192.168.1.10", "198.51.100.77", "", "", "t13x")
	a.Handle(ev)
	a.Handle(ev)
	a.Handle(ev)

	if len(*alerts) != 1 {
		t.Fatalf("repeat findings within window must be suppressed, got %d", len(*alerts))
	}
}

func TestNonTLSKindIgnored(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{})
	ev := tlsEvent("192.168.1.10", "198.51.100.77", "", "", "x")
	ev.Kind = "ids-alert"
	a.Handle(ev)
	if len(*alerts) != 0 {
		t.Fatalf("non tls-client events must be ignored")
	}
}
