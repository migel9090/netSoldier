package events

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDetectionSchemaVersion(t *testing.T) {
	if DetectionSchemaVersion == "" {
		t.Fatal("DetectionSchemaVersion must not be empty")
	}
}

func TestDetectionSeverityConstants(t *testing.T) {
	severities := []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}
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
	original := DetectionEvent{
		SchemaVersion: DetectionSchemaVersion,
		ID:            "DET-42",
		Timestamp:     time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC),
		Domain:        "evil.example.com",
		MatchedIoC:    "evil.example.com",
		IoCType:       "domain",
		ClientIP:      "192.168.1.42",
		ClientMAC:     "aa:bb:cc:dd:ee:ff",
		ClientName:    "iot-sensor",
		Severity:      SeverityCritical,
		Confidence:    95,
		Source:        "threatfox",
		Threat:        "emotet",
		MitreID:       "T1071",
		MitreName:     "Application Layer Protocol",
		QueryType:     "A",
		Tags:          []string{"c2", "botnet"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded DetectionEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.SchemaVersion != original.SchemaVersion {
		t.Errorf("schema_version: got %q, want %q", decoded.SchemaVersion, original.SchemaVersion)
	}
	if decoded.ID != original.ID {
		t.Errorf("id: got %q, want %q", decoded.ID, original.ID)
	}
	if !decoded.Timestamp.Equal(original.Timestamp) {
		t.Errorf("timestamp: got %v, want %v", decoded.Timestamp, original.Timestamp)
	}
	if decoded.Domain != original.Domain {
		t.Errorf("domain: got %q, want %q", decoded.Domain, original.Domain)
	}
	if decoded.MatchedIoC != original.MatchedIoC {
		t.Errorf("matched_ioc: got %q, want %q", decoded.MatchedIoC, original.MatchedIoC)
	}
	if decoded.IoCType != original.IoCType {
		t.Errorf("ioc_type: got %q, want %q", decoded.IoCType, original.IoCType)
	}
	if decoded.ClientIP != original.ClientIP {
		t.Errorf("client_ip: got %q, want %q", decoded.ClientIP, original.ClientIP)
	}
	if decoded.ClientMAC != original.ClientMAC {
		t.Errorf("client_mac: got %q, want %q", decoded.ClientMAC, original.ClientMAC)
	}
	if decoded.ClientName != original.ClientName {
		t.Errorf("client_name: got %q, want %q", decoded.ClientName, original.ClientName)
	}
	if decoded.Severity != original.Severity {
		t.Errorf("severity: got %q, want %q", decoded.Severity, original.Severity)
	}
	if decoded.Confidence != original.Confidence {
		t.Errorf("confidence: got %d, want %d", decoded.Confidence, original.Confidence)
	}
	if decoded.Source != original.Source {
		t.Errorf("source: got %q, want %q", decoded.Source, original.Source)
	}
	if decoded.Threat != original.Threat {
		t.Errorf("threat: got %q, want %q", decoded.Threat, original.Threat)
	}
	if decoded.MitreID != original.MitreID {
		t.Errorf("mitre_id: got %q, want %q", decoded.MitreID, original.MitreID)
	}
	if decoded.QueryType != original.QueryType {
		t.Errorf("query_type: got %q, want %q", decoded.QueryType, original.QueryType)
	}
	if len(decoded.Tags) != len(original.Tags) {
		t.Fatalf("tags: got %d, want %d", len(decoded.Tags), len(original.Tags))
	}
	for i, tag := range decoded.Tags {
		if tag != original.Tags[i] {
			t.Errorf("tags[%d]: got %q, want %q", i, tag, original.Tags[i])
		}
	}
}

func TestDetectionEventRequiredJSONKeys(t *testing.T) {
	ev := DetectionEvent{
		SchemaVersion: "1.0",
		ID:            "DET-1",
		Timestamp:     time.Now(),
		Domain:        "evil.com",
		MatchedIoC:    "evil.com",
		IoCType:       "domain",
		ClientIP:      "1.2.3.4",
		ClientMAC:     "aa:bb:cc:dd:ee:ff",
		Severity:      SeverityHigh,
		Confidence:    80,
		Source:        "test",
		Threat:        "malware",
	}

	data, _ := json.Marshal(ev)
	var raw map[string]any
	json.Unmarshal(data, &raw)

	required := []string{
		"schema_version", "id", "timestamp", "domain", "matched_ioc",
		"ioc_type", "client_ip", "client_mac", "severity", "confidence",
		"source", "threat",
	}
	for _, key := range required {
		if _, ok := raw[key]; !ok {
			t.Errorf("required JSON key %q missing", key)
		}
	}
}

func TestDetectionEventOmitemptyFields(t *testing.T) {
	ev := DetectionEvent{
		SchemaVersion: "1.0",
		ID:            "DET-1",
		Domain:        "evil.com",
		ClientIP:      "1.2.3.4",
		Severity:      SeverityHigh,
	}

	data, _ := json.Marshal(ev)
	var raw map[string]any
	json.Unmarshal(data, &raw)

	omit := []string{"client_mac", "client_name", "mitre_id", "mitre_name", "query_type", "tags"}
	for _, key := range omit {
		if _, ok := raw[key]; ok {
			t.Errorf("omitempty field %q present with zero value", key)
		}
	}
}

func TestDetectionEventBackwardCompat(t *testing.T) {
	jsonWithExtra := `{
		"schema_version": "1.0",
		"id": "DET-1",
		"timestamp": "2026-05-20T10:00:00Z",
		"domain": "evil.com",
		"matched_ioc": "evil.com",
		"ioc_type": "domain",
		"client_ip": "1.2.3.4",
		"severity": "critical",
		"confidence": 95,
		"source": "test",
		"threat": "emotet",
		"future_field_v2": "should be silently ignored"
	}`

	var ev DetectionEvent
	if err := json.Unmarshal([]byte(jsonWithExtra), &ev); err != nil {
		t.Fatalf("unmarshal with unknown field should succeed: %v", err)
	}
	if ev.ID != "DET-1" {
		t.Errorf("id: got %q, want DET-1", ev.ID)
	}
	if ev.Severity != SeverityCritical {
		t.Errorf("severity: got %q, want critical", ev.Severity)
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

func TestKnownBadSignals(t *testing.T) {
	tests := []struct {
		name      string
		ev        DetectionEvent
		want      []string
		wantKnown bool
	}{
		{
			name:      "single feed match",
			ev:        DetectionEvent{SignalClass: SignalIoC},
			want:      []string{SignalIoC},
			wantKnown: true,
		},
		{
			name:      "single IDS signature",
			ev:        DetectionEvent{SignalClass: SignalIDS},
			want:      []string{SignalIDS},
			wantKnown: true,
		},
		{
			name:      "lone beacon heuristic is not known-bad",
			ev:        DetectionEvent{SignalClass: SignalBeacon},
			want:      nil,
			wantKnown: false,
		},
		{
			// The case that matters for auto-enforcement: two heuristics
			// corroborate each other and clear the confidence bar, but
			// nothing external attests the destination is malicious.
			name: "composite of two heuristics is not known-bad",
			ev: DetectionEvent{
				SignalClass: SignalComposite,
				Signals:     []string{SignalBeacon, SignalVolumetric},
				SignalCount: 2,
			},
			want:      nil,
			wantKnown: false,
		},
		{
			name: "composite including a feed match is known-bad",
			ev: DetectionEvent{
				SignalClass: SignalComposite,
				Signals:     []string{SignalBeacon, SignalIoC},
				SignalCount: 2,
			},
			want:      []string{SignalIoC},
			wantKnown: true,
		},
		{
			name:      "unlabelled event claims nothing",
			ev:        DetectionEvent{Confidence: 100, Severity: SeverityCritical},
			want:      nil,
			wantKnown: false,
		},
		{
			name: "duplicate known-bad classes are deduplicated",
			ev: DetectionEvent{
				SignalClass: SignalIoC,
				Signals:     []string{SignalIoC, SignalIDS},
			},
			want:      []string{SignalIoC, SignalIDS},
			wantKnown: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ev.KnownBadSignals()
			if len(got) != len(tt.want) {
				t.Fatalf("KnownBadSignals() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("KnownBadSignals()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
			if gotKnown := tt.ev.HasKnownBadSignal(); gotKnown != tt.wantKnown {
				t.Errorf("HasKnownBadSignal() = %v, want %v", gotKnown, tt.wantKnown)
			}
		})
	}
}

func TestSignalClassSerializes(t *testing.T) {
	ev := DetectionEvent{SignalClass: SignalBeacon}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"signal_class":"beacon"`) {
		t.Errorf("signal_class missing from wire format: %s", b)
	}

	var empty DetectionEvent
	b, err = json.Marshal(empty)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "signal_class") {
		t.Errorf("empty signal_class should be omitted: %s", b)
	}
}
