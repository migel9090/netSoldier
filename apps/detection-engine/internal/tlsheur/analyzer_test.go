package tlsheur

import (
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
)

type fakeResolver map[string]string

func (f fakeResolver) Get(_, ip string) string { return f[ip] }

func tlsEvent(src, dst, sni, ja3, fp string) ingest.SensorEvent {
	return ingest.SensorEvent{
		Sensor: "zeek", Kind: "tls-client", Timestamp: time.Unix(1789000000, 0),
		SrcIP: src, DstIP: dst, SNI: sni, JA3: ja3,
		Indicator: fp, IndicatorType: "tlsfp",
	}
}

func newTestAnalyzer(m *iocmatch.Matcher, r Resolver) (*Analyzer, *[]detection.Alert) {
	var alerts []detection.Alert
	a := New(m, r, DefaultLocalCIDRs, func(al detection.Alert) { alerts = append(alerts, al) })
	return a, &alerts
}

func TestTLSFPIoCMatch(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{
		Value: "t13d3012h2_1d37bd780c83_882d495ac381", Type: "tlsfp",
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

// TestFingerprintMatchDoesNotBecomeADomain: the fingerprint and the
// destination are different things. 1.x put the SNI (or the address) in
// Domain and the fingerprint in matched_ioc with no way to tell which one a
// receiver should act on.
func TestFingerprintMatchDoesNotBecomeADomain(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{
		Value: "t13d3012h2_1d37bd780c83_882d495ac381", Type: "tlsfp",
		Source: "misp", Threat: "c2", Confidence: 95,
	}})
	a, alerts := newTestAnalyzer(m, fakeResolver{})
	a.Handle(tlsEvent("192.168.1.10", "203.0.113.5", "CDN.Example", "", "t13d3012h2_1d37bd780c83_882d495ac381"))

	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	got := (*alerts)[0]
	if got.Domain != "cdn.example" {
		t.Errorf("domain = %q, want the SNI name", got.Domain)
	}
	if got.MatchedIoC != "t13d3012h2_1d37bd780c83_882d495ac381" || got.IoCType != "tlsfp" {
		t.Errorf("matched = %q/%q, want the fingerprint", got.MatchedIoC, got.IoCType)
	}
	if got.Target == nil || *got.Target != (events.Target{Type: events.TargetDomain, Value: "cdn.example"}) {
		t.Errorf("target = %+v, want the observed destination", got.Target)
	}
	if len(got.Signals) != 1 || got.Signals[0].Class != detection.SignalTLS || got.Signals[0].Confidence != 95 ||
		got.Signals[0].Indicator != "t13d3012h2_1d37bd780c83_882d495ac381" {
		t.Errorf("signals = %+v", got.Signals)
	}
	if !strings.Contains(got.Summary, "t13d3012h2") || !strings.Contains(got.Summary, "misp") {
		t.Errorf("summary = %q", got.Summary)
	}
}

func TestJA3MatchCarriesJA3Indicator(t *testing.T) {
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{{Value: "E7D705A3286E19EA42F587B344EE6865", Type: "ja3", Source: "abuse", Confidence: 80}})
	a, alerts := newTestAnalyzer(m, fakeResolver{})
	a.Handle(tlsEvent("192.168.1.10", "203.0.113.5", "", "e7d705a3286e19ea42f587b344ee6865", "t13x"))
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	got := (*alerts)[0]
	if got.IoCType != "ja3" || got.MatchedIoC != "e7d705a3286e19ea42f587b344ee6865" || got.Domain != "" {
		t.Errorf("ja3 alert = %+v", got)
	}
	if got.Target == nil || *got.Target != (events.Target{Type: events.TargetIP, Value: "203.0.113.5"}) {
		t.Errorf("without an SNI the destination is the address, got %+v", got.Target)
	}
}

// TestDNSLessTLSTargetsTheAddress: 1.x wrote the bare destination IP into
// Domain, where the sinkhole would have accepted it as a rule.
func TestDNSLessTLSTargetsTheAddress(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{})
	a.Handle(tlsEvent("192.168.1.10", "198.51.100.77", "", "", "t13x"))

	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	got := (*alerts)[0]
	if got.Domain != "" {
		t.Errorf("domain = %q, want empty: no name was observed", got.Domain)
	}
	if got.Target == nil || *got.Target != (events.Target{Type: events.TargetIP, Value: "198.51.100.77"}) {
		t.Errorf("target = %+v", got.Target)
	}
	if got.MatchedIoC != "198.51.100.77" || got.IoCType != "ip" {
		t.Errorf("matched = %q/%q", got.MatchedIoC, got.IoCType)
	}
}

// TestSNIMismatchIndicatorIsNotDecorated: matched_ioc used to be
// "evil.attacker.net vs www.legit-cdn.com".
func TestSNIMismatchIndicatorIsNotDecorated(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{"203.0.113.5": "www.legit-cdn.com"})
	a.Handle(tlsEvent("192.168.1.10", "203.0.113.5", "evil.attacker.net", "", "t13x"))

	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	got := (*alerts)[0]
	if got.MatchedIoC != "evil.attacker.net" || got.IoCType != "domain" {
		t.Errorf("matched = %q/%q, want the SNI name", got.MatchedIoC, got.IoCType)
	}
	if !strings.Contains(got.Summary, "www.legit-cdn.com") {
		t.Errorf("the resolved name belongs in the summary, got %q", got.Summary)
	}
}

// TestLiteralAddressInSNI: clients do put addresses in SNI; that is not an
// observed DNS name.
func TestLiteralAddressInSNI(t *testing.T) {
	a, alerts := newTestAnalyzer(iocmatch.New(), fakeResolver{"203.0.113.5": "www.legit-cdn.com"})
	a.Handle(tlsEvent("192.168.1.10", "203.0.113.5", "203.0.113.5", "", "t13x"))
	if len(*alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(*alerts))
	}
	got := (*alerts)[0]
	if got.Domain != "" || got.MatchedIoC != "" || got.IoCType != "" || got.Signals[0].IndicatorType != "" {
		t.Errorf("an address in SNI is not a name: %+v", got)
	}
	if got.Target == nil || got.Target.Type != events.TargetIP {
		t.Errorf("target = %+v, want the address", got.Target)
	}
}
