package eventmap

import (
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/libs/events"
)

func TestAlertToEventCarriesContract(t *testing.T) {
	a := detection.Alert{
		ID:         "DET-42",
		Timestamp:  time.Unix(1_700_000_000, 0).UTC(),
		Domain:     "evil.example",
		MatchedIoC: "evil.example",
		IoCType:    "domain",
		ClientIP:   "192.168.1.5",
		ClientMAC:  "aa:bb:cc:dd:ee:ff",
		Severity:   "critical",
		Confidence: 95,
		Source:     "threatfox",
		Threat:     "cobalt-strike",
		MitreID:    "T1071",
		Tags:       []string{"c2"},
	}
	ev := AlertToEvent(a)

	if ev.SchemaVersion != events.DetectionSchemaVersion {
		t.Errorf("schema version = %q", ev.SchemaVersion)
	}
	if ev.ID != "DET-42" || ev.Confidence != 95 || ev.ClientMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("core fields not mapped: %+v", ev)
	}
	if ev.IoCType != "domain" {
		t.Errorf("ioc_type = %q, want domain", ev.IoCType)
	}
}

func TestInvalidIoCTypeNormalizedToIP(t *testing.T) {
	// beacon/volumetric signals carry descriptive types outside the schema
	// enum; they must be coerced so the killswitch/schema stay valid.
	for _, badType := range []string{"beacon", "flow-window", ""} {
		ev := AlertToEvent(detection.Alert{IoCType: badType, Confidence: 60})
		if ev.IoCType != "ip" {
			t.Errorf("ioc_type %q normalized to %q, want ip", badType, ev.IoCType)
		}
	}
}

func TestValidIoCTypesPreserved(t *testing.T) {
	for _, ok := range []string{"domain", "ip", "url", "ja3", "tlsfp", "md5", "sha256"} {
		ev := AlertToEvent(detection.Alert{IoCType: ok})
		if ev.IoCType != ok {
			t.Errorf("valid ioc_type %q was changed to %q", ok, ev.IoCType)
		}
	}
}

func TestSeverityDerivedWhenMissing(t *testing.T) {
	ev := AlertToEvent(detection.Alert{Confidence: 95})
	if ev.Severity != events.SeverityCritical {
		t.Errorf("severity = %q, want critical (derived from confidence)", ev.Severity)
	}
}

func TestCompositeFieldsMapped(t *testing.T) {
	a := detection.Alert{
		Confidence:  93,
		Signals:     []string{"beacon", "volumetric"},
		SignalCount: 2,
	}
	ev := AlertToEvent(a)
	if ev.SignalCount != 2 || len(ev.Signals) != 2 {
		t.Errorf("composite fields not mapped: signals=%v count=%d", ev.Signals, ev.SignalCount)
	}
}
