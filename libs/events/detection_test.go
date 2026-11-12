package events

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

// validEvent is a complete, contract-valid single-signal domain IoC event.
func validEvent() DetectionEvent {
	return DetectionEvent{
		SchemaVersion: DetectionSchemaVersion,
		ID:            "DET-7f3a9c-42",
		Timestamp:     time.Date(2026, 11, 16, 12, 0, 0, 123e6, time.UTC),
		Summary:       "DNS query for a domain listed by ThreatFox",
		Domain:        "cdn.evil.example",
		MatchedIoC:    "evil.example",
		IoCType:       IndicatorDomain,
		ClientIP:      "192.168.1.77",
		ClientMAC:     "aa:bb:cc:dd:ee:ff",
		ClientName:    "kids-tablet",
		Severity:      SeverityHigh,
		Confidence:    75,
		Source:        "threatfox",
		Threat:        "Mozi",
		MitreID:       "T1071.004",
		MitreName:     "Application Layer Protocol: DNS",
		QueryType:     "A",
		SignalClass:   SignalIoC,
		Signals: []Signal{{
			Class: SignalIoC, Confidence: 75, Indicator: "evil.example",
			IndicatorType: IndicatorDomain, Source: "threatfox",
		}},
		Target: &Target{Type: TargetDomain, Value: "evil.example"},
	}
}

func TestDetectionSchemaVersion(t *testing.T) {
	if DetectionSchemaVersion != "2.0" {
		t.Fatalf("DetectionSchemaVersion = %q, want 2.0", DetectionSchemaVersion)
	}
	if major, ok := schemaMajor(DetectionSchemaVersion); !ok || major != detectionSchemaMajor {
		t.Fatalf("DetectionSchemaVersion %q does not carry major %d", DetectionSchemaVersion, detectionSchemaMajor)
	}
}

func TestDetectionSeverityConstants(t *testing.T) {
	seen := make(map[string]bool)
	for _, s := range severities {
		if s == "" {
			t.Error("severity constant must not be empty")
		}
		if seen[s] {
			t.Errorf("duplicate severity constant %q", s)
		}
		seen[s] = true
	}
	if len(severities) != 4 {
		t.Errorf("expected 4 severity levels, got %d", len(severities))
	}
}

func TestDetectionEventJSONRoundtrip(t *testing.T) {
	original := validEvent()
	original.Tags = []string{"c2", "botnet"}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded DetectionEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("timestamp: got %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	decoded.Timestamp = original.Timestamp
	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("round trip changed the event:\n got %+v\nwant %+v", decoded, original)
	}
	if err := decoded.Validate(); err != nil {
		t.Errorf("round-tripped event no longer validates: %v", err)
	}
}

// TestDetectionEventWireShape pins the JSON keys a v2 receiver relies on.
func TestDetectionEventWireShape(t *testing.T) {
	data, _ := json.Marshal(validEvent())
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"schema_version", "id", "timestamp", "summary", "domain", "matched_ioc",
		"ioc_type", "client_ip", "client_mac", "severity", "confidence",
		"source", "threat", "signal_class", "signals", "target",
	} {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON key %q missing", key)
		}
	}
	for _, gone := range []string{"signal_count"} {
		if _, ok := raw[gone]; ok {
			t.Errorf("1.x key %q is still on the wire", gone)
		}
	}
	sig := raw["signals"].([]any)[0].(map[string]any)
	for _, key := range []string{"class", "confidence", "indicator", "indicator_type", "source"} {
		if _, ok := sig[key]; !ok {
			t.Errorf("signals[0] key %q missing", key)
		}
	}
	target := raw["target"].(map[string]any)
	if target["type"] != "domain" || target["value"] != "evil.example" {
		t.Errorf("target = %v", target)
	}
}

func TestDetectionEventOmitemptyFields(t *testing.T) {
	ev := validEvent()
	ev.Domain, ev.MatchedIoC, ev.IoCType = "", "", ""
	ev.ClientMAC, ev.ClientName, ev.MitreID, ev.MitreName, ev.QueryType = "", "", "", "", ""
	ev.Target = nil

	data, _ := json.Marshal(ev)
	var raw map[string]any
	_ = json.Unmarshal(data, &raw)

	for _, key := range []string{
		"domain", "matched_ioc", "ioc_type", "client_mac", "client_name",
		"mitre_id", "mitre_name", "query_type", "tags", "target",
	} {
		if _, ok := raw[key]; ok {
			t.Errorf("omitempty field %q present with zero value", key)
		}
	}
}

func TestDetectionEventIgnoresUnknownFields(t *testing.T) {
	jsonWithExtra := `{
		"schema_version": "2.1",
		"id": "DET-abc-1",
		"timestamp": "2026-05-20T10:00:00Z",
		"summary": "x",
		"client_ip": "1.2.3.4",
		"severity": "critical",
		"confidence": 95,
		"source": "test",
		"threat": "emotet",
		"signal_class": "ioc",
		"signals": [{"class": "ioc", "confidence": 95, "future": 1}],
		"future_field": "should be silently ignored"
	}`
	var ev DetectionEvent
	if err := json.Unmarshal([]byte(jsonWithExtra), &ev); err != nil {
		t.Fatalf("unmarshal with unknown field should succeed: %v", err)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("a 2.1 event with unknown optional fields should validate: %v", err)
	}
}

func TestIsKnownBadSignal(t *testing.T) {
	tests := []struct {
		class string
		want  bool
	}{
		{SignalIoC, true},
		{SignalIDS, true},
		{SignalBeacon, false},
		{SignalVolumetric, false},
		{SignalTLS, false},
		{SignalComposite, false},
		{"", false},
		{"unknown-class", false},
	}
	for _, tt := range tests {
		if got := IsKnownBadSignal(tt.class); got != tt.want {
			t.Errorf("IsKnownBadSignal(%q) = %v, want %v", tt.class, got, tt.want)
		}
	}
}

func sig(class string, conf int) Signal { return Signal{Class: class, Confidence: conf} }

func TestKnownBadSignals(t *testing.T) {
	tests := []struct {
		name      string
		ev        DetectionEvent
		want      []string
		wantKnown bool
	}{
		{"single feed match", DetectionEvent{Signals: []Signal{sig(SignalIoC, 90)}}, []string{SignalIoC}, true},
		{"single IDS signature", DetectionEvent{Signals: []Signal{sig(SignalIDS, 90)}}, []string{SignalIDS}, true},
		{"lone beacon heuristic is not known-bad", DetectionEvent{Signals: []Signal{sig(SignalBeacon, 75)}}, nil, false},
		{
			// Two heuristics corroborate each other and clear the confidence
			// bar, but nothing external attests the destination is malicious.
			name: "composite of two heuristics is not known-bad",
			ev: DetectionEvent{SignalClass: SignalComposite, Signals: []Signal{
				sig(SignalBeacon, 75), sig(SignalVolumetric, 70)}},
			want: nil, wantKnown: false,
		},
		{
			name: "composite including a feed match is known-bad",
			ev: DetectionEvent{SignalClass: SignalComposite, Signals: []Signal{
				sig(SignalBeacon, 75), sig(SignalIoC, 60)}},
			want: []string{SignalIoC}, wantKnown: true,
		},
		{"no signals claims nothing", DetectionEvent{Confidence: 100, Severity: SeverityCritical}, nil, false},
		{
			// A label is not evidence: only Signals counts.
			name: "signal_class label alone claims nothing",
			ev:   DetectionEvent{SignalClass: SignalIoC, Signals: []Signal{sig(SignalBeacon, 75)}},
			want: nil, wantKnown: false,
		},
		{
			name: "duplicate known-bad classes are deduplicated",
			ev:   DetectionEvent{Signals: []Signal{sig(SignalIoC, 1), sig(SignalIoC, 2), sig(SignalIDS, 3)}},
			want: []string{SignalIoC, SignalIDS}, wantKnown: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ev.KnownBadSignals(); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("KnownBadSignals() = %v, want %v", got, tt.want)
			}
			if got := tt.ev.HasKnownBadSignal(); got != tt.wantKnown {
				t.Errorf("HasKnownBadSignal() = %v, want %v", got, tt.wantKnown)
			}
		})
	}
}

func TestContributingClasses(t *testing.T) {
	ev := DetectionEvent{Signals: []Signal{sig(SignalBeacon, 1), sig(SignalIoC, 2), sig(SignalBeacon, 3)}}
	if got := ev.ContributingClasses(); !reflect.DeepEqual(got, []string{SignalBeacon, SignalIoC}) {
		t.Errorf("ContributingClasses() = %v", got)
	}
}

func TestAttestedSignal(t *testing.T) {
	domainTarget := &Target{Type: TargetDomain, Value: "evil.example"}
	feedHit := func(conf int, indicator string) Signal {
		return Signal{Class: SignalIoC, Confidence: conf, Indicator: indicator,
			IndicatorType: IndicatorDomain, Source: "threatfox"}
	}

	tests := []struct {
		name    string
		ev      DetectionEvent
		min     int
		want    bool
		wantCon int
	}{
		{"feed vouches for the target", DetectionEvent{Target: domainTarget,
			Signals: []Signal{feedHit(90, "evil.example")}}, 90, true, 90},
		{"feed hit too weak on its own", DetectionEvent{Target: domainTarget,
			Signals: []Signal{feedHit(60, "evil.example")}}, 90, false, 0},
		{
			// The shape of the corroborated-heuristics problem: the feed
			// vouched for one name, the strongest heuristic points at another.
			name: "feed vouches for a different name than the target",
			ev: DetectionEvent{
				Target: &Target{Type: TargetDomain, Value: "time.cloudflare.com"},
				Signals: []Signal{
					feedHit(95, "weak-ioc.example"),
					{Class: SignalBeacon, Confidence: 75, Indicator: "time.cloudflare.com", IndicatorType: IndicatorDomain},
				},
			},
			min: 50, want: false,
		},
		{
			name: "a heuristic naming the target attests nothing",
			ev: DetectionEvent{Target: domainTarget, Signals: []Signal{
				{Class: SignalBeacon, Confidence: 99, Indicator: "evil.example", IndicatorType: IndicatorDomain}}},
			min: 0, want: false,
		},
		{
			name: "an IDS rule id is not the target",
			ev: DetectionEvent{Target: domainTarget, Signals: []Signal{
				{Class: SignalIDS, Confidence: 99, Indicator: "2031999", IndicatorType: IndicatorSID}}},
			min: 0, want: false,
		},
		{
			name: "same value, different type",
			ev: DetectionEvent{Target: &Target{Type: TargetIP, Value: "203.0.113.0"}, Signals: []Signal{
				{Class: SignalIoC, Confidence: 99, Indicator: "203.0.113.0", IndicatorType: IndicatorCIDR}}},
			min: 0, want: false,
		},
		{
			name: "canonical comparison of domains",
			ev: DetectionEvent{Target: domainTarget, Signals: []Signal{
				feedHit(91, "Evil.Example.")}},
			min: 90, want: true, wantCon: 91,
		},
		{
			name: "canonical comparison of addresses",
			ev: DetectionEvent{Target: &Target{Type: TargetIP, Value: "2001:db8::1"}, Signals: []Signal{
				{Class: SignalIoC, Confidence: 90, Indicator: "2001:DB8:0::1", IndicatorType: IndicatorIP}}},
			min: 90, want: true, wantCon: 90,
		},
		{
			name: "the most confident attesting signal wins",
			ev: DetectionEvent{Target: domainTarget, Signals: []Signal{
				feedHit(91, "evil.example"), feedHit(97, "evil.example"), feedHit(93, "evil.example")}},
			min: 90, want: true, wantCon: 97,
		},
		{"no target, nothing attested", DetectionEvent{Signals: []Signal{feedHit(99, "evil.example")}}, 0, false, 0},
		{
			name: "unknown target type is never attested",
			ev: DetectionEvent{Target: &Target{Type: "url", Value: "evil.example"}, Signals: []Signal{
				{Class: SignalIoC, Confidence: 99, Indicator: "evil.example", IndicatorType: "url"}}},
			min: 0, want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.ev.AttestedSignal(tt.min)
			if ok != tt.want {
				t.Fatalf("AttestedSignal(%d) ok = %v, want %v (signal %+v)", tt.min, ok, tt.want, got)
			}
			if ok && got.Confidence != tt.wantCon {
				t.Errorf("AttestedSignal confidence = %d, want %d", got.Confidence, tt.wantCon)
			}
		})
	}
}

func TestValidateAcceptsContractExample(t *testing.T) {
	if err := validEvent().Validate(); err != nil {
		t.Fatalf("the contract's own example must validate: %v", err)
	}

	composite := validEvent()
	composite.SignalClass = SignalComposite
	composite.Signals = append(composite.Signals, Signal{Class: SignalBeacon, Confidence: 75})
	if err := composite.Validate(); err != nil {
		t.Errorf("composite: %v", err)
	}

	noTarget := validEvent()
	noTarget.Target = nil
	noTarget.ClientIP = "2001:db8::77"
	if err := noTarget.Validate(); err != nil {
		t.Errorf("IPv6 client without a target: %v", err)
	}

	ipTarget := validEvent()
	ipTarget.Target = &Target{Type: TargetIP, Value: "203.0.113.7"}
	if err := ipTarget.Validate(); err != nil {
		t.Errorf("ip target: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DetectionEvent)
		want   string // substring of the problem
	}{
		{"1.x schema", func(e *DetectionEvent) { e.SchemaVersion = "1.0" }, "unsupported major"},
		{"future major", func(e *DetectionEvent) { e.SchemaVersion = "3.0" }, "unsupported major"},
		{"no schema version", func(e *DetectionEvent) { e.SchemaVersion = "" }, "schema_version"},
		{"garbage schema version", func(e *DetectionEvent) { e.SchemaVersion = "two" }, "schema_version"},
		{"empty id", func(e *DetectionEvent) { e.ID = "" }, "id"},
		{"1.x id restarting at DET-1", func(e *DetectionEvent) { e.ID = "DET-1" }, "id"},
		{"id with a dash in the prefix", func(e *DetectionEvent) { e.ID = "DET-host-name-1" }, "id"},
		{"zero timestamp", func(e *DetectionEvent) { e.Timestamp = time.Time{} }, "timestamp"},
		{"empty summary", func(e *DetectionEvent) { e.Summary = "  " }, "summary"},
		{"unknown severity", func(e *DetectionEvent) { e.Severity = "CRITICAL" }, "severity"},
		{"confidence above 100", func(e *DetectionEvent) { e.Confidence = 101 }, "confidence"},
		{"negative confidence", func(e *DetectionEvent) { e.Confidence = -1 }, "confidence"},
		{"no signals", func(e *DetectionEvent) { e.Signals = nil }, "signals"},
		{"unknown signal class", func(e *DetectionEvent) { e.Signals[0].Class = "dga"; e.SignalClass = "dga" }, "signals[0].class"},
		{"composite as a signal", func(e *DetectionEvent) { e.Signals[0].Class = SignalComposite; e.SignalClass = SignalComposite }, "signals[0].class"},
		{"signal confidence above 100", func(e *DetectionEvent) { e.Signals[0].Confidence = 150 }, "signals[0].confidence"},
		{"label disagrees with signals", func(e *DetectionEvent) { e.SignalClass = SignalBeacon }, "signal_class"},
		{"composite label on one class", func(e *DetectionEvent) { e.SignalClass = SignalComposite }, "signal_class"},
		{"client ip unparsable", func(e *DetectionEvent) { e.ClientIP = "192.168.1.300" }, "client_ip"},
		{"client ip missing", func(e *DetectionEvent) { e.ClientIP = "" }, "client_ip"},
		{"client ip with leading zeros", func(e *DetectionEvent) { e.ClientIP = "192.168.001.001" }, "client_ip"},
		{"client ip not canonical", func(e *DetectionEvent) { e.ClientIP = "2001:DB8::1" }, "canonical"},
		{"client ip mapped", func(e *DetectionEvent) { e.ClientIP = "::ffff:192.168.1.5" }, "canonical"},
		{"client ip zoned", func(e *DetectionEvent) { e.ClientIP = "fe80::1%eth0" }, "client_ip"},
		{"client mac upper-case", func(e *DetectionEvent) { e.ClientMAC = "AA:BB:CC:DD:EE:FF" }, "client_mac"},
		{"unknown target type", func(e *DetectionEvent) { e.Target = &Target{Type: "url", Value: "http://x"} }, "target type"},
		{"decorated domain target", func(e *DetectionEvent) {
			e.Target = &Target{Type: TargetDomain, Value: "cdn.x (→203.0.113.7)"}
		}, "target domain"},
		{"rule text as domain target", func(e *DetectionEvent) {
			e.Target = &Target{Type: TargetDomain, Value: "ET MALWARE Cobalt Strike Beacon Observed"}
		}, "target domain"},
		{"ip literal as domain target", func(e *DetectionEvent) {
			e.Target = &Target{Type: TargetDomain, Value: "203.0.113.9"}
		}, "target domain"},
		{"fingerprint as domain target", func(e *DetectionEvent) {
			e.Target = &Target{Type: TargetDomain, Value: "t13d3012h2_1d37bd780c83_882d495ac381"}
		}, "target domain"},
		{"domain target not canonical", func(e *DetectionEvent) {
			e.Target = &Target{Type: TargetDomain, Value: "Evil.Example"}
		}, "canonical"},
		{"ip target unparsable", func(e *DetectionEvent) {
			e.Target = &Target{Type: TargetIP, Value: "evil.example"}
		}, "target ip"},
		{"ip target not canonical", func(e *DetectionEvent) {
			e.Target = &Target{Type: TargetIP, Value: "2001:DB8::1"}
		}, "canonical"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := validEvent()
			tt.mutate(&ev)
			err := ev.Validate()
			if err == nil {
				t.Fatal("expected a validation error")
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("error should be a *ValidationError, got %T", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should mention %q", err, tt.want)
			}
		})
	}
}

// TestValidateReportsEveryProblem: a sender fixing a broken producer should
// learn everything that is wrong from one rejection.
func TestValidateReportsEveryProblem(t *testing.T) {
	err := DetectionEvent{SchemaVersion: DetectionSchemaVersion}.Validate()
	var verr *ValidationError
	if !errors.As(err, &verr) {
		t.Fatalf("got %v", err)
	}
	if len(verr.Problems) < 6 {
		t.Errorf("expected every missing field to be reported, got %v", verr.Problems)
	}
	if !strings.HasPrefix(err.Error(), "invalid detection event: ") {
		t.Errorf("error = %q", err)
	}
}

// TestValidateRejectsV1Event feeds the exact shape the 1.x engine produced
// for a DNS-answer IP match: decorated domain, restart-prone id, no summary,
// signals as bare class names.
func TestValidateRejectsV1Event(t *testing.T) {
	v1 := `{"schema_version":"1.0","id":"DET-3","timestamp":"2026-11-16T12:00:00Z",
		"domain":"cdn.x (→203.0.113.7)","matched_ioc":"203.0.113.7","ioc_type":"ip",
		"client_ip":"192.168.1.5","severity":"critical","confidence":90,"source":"feodo",
		"threat":"","signal_class":"ioc"}`
	var ev DetectionEvent
	if err := json.Unmarshal([]byte(v1), &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := ev.Validate(); err == nil {
		t.Fatal("a 1.x event must not validate as 2.x")
	}
}

func TestCanonicalIP(t *testing.T) {
	ok := map[string]string{
		"192.168.1.5":        "192.168.1.5",
		" 10.0.0.1 ":         "10.0.0.1",
		"2001:DB8:0::1":      "2001:db8::1",
		"::ffff:192.168.1.5": "192.168.1.5",
	}
	for in, want := range ok {
		if got, valid := CanonicalIP(in); !valid || got != want {
			t.Errorf("CanonicalIP(%q) = %q, %v; want %q", in, got, valid, want)
		}
	}
	for _, in := range []string{"", "192.168.001.001", "0xc0a80101", "192.168.1.1/32", "fe80::1%eth0", "evil.example"} {
		if got, valid := CanonicalIP(in); valid {
			t.Errorf("CanonicalIP(%q) = %q, should be refused", in, got)
		}
	}
}

func TestCanonicalDomain(t *testing.T) {
	ok := map[string]string{
		"evil.example":              "evil.example",
		"EVIL.Example.":             "evil.example",
		" a-b.c1.example ":          "a-b.c1.example",
		"xn--80ak6aa92e.com":        "xn--80ak6aa92e.com",
		"1-2.example":               "1-2.example",
		"123.example":               "123.example",
		"time.cloudflare.com":       "time.cloudflare.com",
		"c2.evil.test":              "c2.evil.test",
		"x.co.uk":                   "x.co.uk", // public suffixes are the sinkhole's call, not the contract's
		"raw.githubusercontent.com": "raw.githubusercontent.com",
	}
	for in, want := range ok {
		if got, valid := CanonicalDomain(in); !valid || got != want {
			t.Errorf("CanonicalDomain(%q) = %q, %v; want %q", in, got, valid, want)
		}
	}
	for _, in := range []string{
		"", ".", "no-dot", "-bad.example", "bad-.example", "a..b", "with space.example",
		"203.0.113.9", "192.168.001.001", "1.2.3.4.5", "2001:db8::1", "_dmarc.evil.example",
		"cdn.x (→203.0.113.7)", "evil.example^\n||*^", "ünïcode.example",
		strings.Repeat("a", 64) + ".example", strings.Repeat("a.", 127) + "example",
	} {
		if got, valid := CanonicalDomain(in); valid {
			t.Errorf("CanonicalDomain(%q) = %q, should be refused", in, got)
		}
	}
}

func TestDetectionIDHelpers(t *testing.T) {
	id := FormatDetectionID("7f3a9c", 42)
	if id != "DET-7f3a9c-42" {
		t.Errorf("FormatDetectionID = %q", id)
	}
	if !detectionIDRe.MatchString(id) {
		t.Errorf("formatted id %q does not match the pattern", id)
	}
	for _, p := range []string{"abc", "ABC123", "0"} {
		if !ValidIDPrefix(p) {
			t.Errorf("ValidIDPrefix(%q) should be true", p)
		}
	}
	for _, p := range []string{"", "host-name", "a.b", "pod_1", "ä"} {
		if ValidIDPrefix(p) {
			t.Errorf("ValidIDPrefix(%q) should be false", p)
		}
	}
}
