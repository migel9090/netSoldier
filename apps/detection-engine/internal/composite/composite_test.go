package composite

import (
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
)

func TestCombineNoisyOR(t *testing.T) {
	tests := []struct {
		name string
		in   []int
		want int
	}{
		{"single passes through", []int{90}, 90},
		{"two mid reinforce", []int{60, 60}, 84},
		{"beacon plus volumetric escalate", []int{75, 70}, 93},
		{"three weak stay bounded", []int{30, 30, 30}, 66},
		{"empty", []int{}, 0},
		{"clamps over 100", []int{150}, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := combine(tt.in); got != tt.want {
				t.Errorf("combine(%v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}

func TestCombineIsMonotonic(t *testing.T) {
	// adding a signal never lowers combined confidence
	base := combine([]int{60})
	more := combine([]int{60, 40})
	if more < base {
		t.Errorf("adding a signal lowered confidence: %d < %d", more, base)
	}
}

func mkAlert(client, class string, conf int) detection.Alert {
	return detection.Alert{
		ClientIP:    client,
		SignalClass: class,
		Confidence:  conf,
		MatchedIoC:  "x",
		Domain:      "evil.example",
	}
}

func TestSingleSignalNoComposite(t *testing.T) {
	c := New(time.Minute, nil)
	if got := c.Observe(mkAlert("192.168.1.5", detection.SignalBeacon, 75)); got != nil {
		t.Fatalf("single signal should not produce a composite, got %+v", got)
	}
	// a repeat of the same class is still one class -> no composite
	if got := c.Observe(mkAlert("192.168.1.5", detection.SignalBeacon, 75)); got != nil {
		t.Fatalf("same-class repeat should not corroborate, got %+v", got)
	}
}

func TestTwoClassesEscalate(t *testing.T) {
	var emitted *detection.Alert
	c := New(time.Minute, func(a detection.Alert) { emitted = &a })

	c.Observe(mkAlert("192.168.1.5", detection.SignalBeacon, 75))
	got := c.Observe(mkAlert("192.168.1.5", detection.SignalVolumetric, 70))

	if got == nil {
		t.Fatal("two distinct classes should produce a composite")
	}
	if got.Confidence != 93 {
		t.Errorf("composite confidence = %d, want 93", got.Confidence)
	}
	if got.SignalCount != 2 {
		t.Errorf("signal count = %d, want 2", got.SignalCount)
	}
	if got.Severity != detection.SeverityCritical {
		t.Errorf("severity = %q, want critical", got.Severity)
	}
	if got.SignalClass != detection.SignalComposite {
		t.Errorf("signal class = %q, want composite", got.SignalClass)
	}
	if emitted == nil || emitted.Confidence != got.Confidence {
		t.Error("Emit callback not invoked with the composite")
	}
}

func TestDifferentClientsDoNotCorroborate(t *testing.T) {
	c := New(time.Minute, nil)
	c.Observe(mkAlert("192.168.1.5", detection.SignalBeacon, 75))
	if got := c.Observe(mkAlert("192.168.1.9", detection.SignalVolumetric, 70)); got != nil {
		t.Fatalf("signals from different clients must not combine, got %+v", got)
	}
}

func TestExpiredSignalsDoNotCorroborate(t *testing.T) {
	now := time.Now()
	c := New(10*time.Minute, nil)
	c.now = func() time.Time { return now }
	c.Observe(mkAlert("192.168.1.5", detection.SignalBeacon, 75))

	// advance past the window before the second signal
	c.now = func() time.Time { return now.Add(11 * time.Minute) }
	if got := c.Observe(mkAlert("192.168.1.5", detection.SignalVolumetric, 70)); got != nil {
		t.Fatalf("stale signal should have expired, got composite %+v", got)
	}
}

func TestKnownBadStaysHighAlone(t *testing.T) {
	// a lone critical IoC (conf 95) does not need corroboration; it just
	// won't produce a *composite* — it flows through as the single alert.
	c := New(time.Minute, nil)
	if got := c.Observe(mkAlert("192.168.1.5", detection.SignalIoC, 95)); got != nil {
		t.Fatalf("single IoC should not be turned into a composite, got %+v", got)
	}
}

func TestAnchorIsHighestConfidenceSignal(t *testing.T) {
	c := New(time.Minute, nil)
	c.Observe(mkAlert("192.168.1.5", detection.SignalTLS, 30))
	strong := mkAlert("192.168.1.5", detection.SignalIoC, 85)
	strong.Threat = "cobalt-strike"
	got := c.Observe(strong)
	if got == nil {
		t.Fatal("expected composite")
	}
	if got.Threat != "cobalt-strike" {
		t.Errorf("anchor threat = %q, want cobalt-strike (the stronger signal)", got.Threat)
	}
}

// TestWeakRepeatDoesNotExtendStrongSignal: a steady trickle of weak signals
// used to refresh the stored strong signal's timestamp, so the 15-minute
// window stopped bounding how stale the confidence driving enforcement could
// be. A signal's recency must describe when that observation was made.
func TestWeakRepeatDoesNotExtendStrongSignal(t *testing.T) {
	now := time.Now()
	var emitted []detection.Alert
	c := New(10*time.Minute, func(a detection.Alert) { emitted = append(emitted, a) })
	c.now = func() time.Time { return now }

	// A strong beacon at t=0.
	c.Observe(detection.Alert{
		ClientMAC: "aa:bb:cc:dd:ee:ff", ClientIP: "192.168.1.10",
		SignalClass: detection.SignalBeacon, Confidence: 75,
	})

	// Weak beacon repeats every few minutes for half an hour.
	for i := 1; i <= 6; i++ {
		now = now.Add(5 * time.Minute)
		c.Observe(detection.Alert{
			ClientMAC: "aa:bb:cc:dd:ee:ff", ClientIP: "192.168.1.10",
			SignalClass: detection.SignalBeacon, Confidence: 10,
		})
	}

	// A second class arrives 30 minutes after the strong beacon. The strong
	// observation is long past the window, so it must not corroborate.
	c.Observe(detection.Alert{
		ClientMAC: "aa:bb:cc:dd:ee:ff", ClientIP: "192.168.1.10",
		SignalClass: detection.SignalVolumetric, Confidence: 70,
	})

	for _, a := range emitted {
		if a.Confidence >= 90 {
			t.Fatalf("a 30-minute-old signal must not corroborate into %d confidence "+
				"inside a 10-minute window", a.Confidence)
		}
	}
}

// TestCorrelationKeyedByMAC: keying on IP alone merged signals from two
// different devices when a DHCP lease moved inside the window.
func TestCorrelationKeyedByMAC(t *testing.T) {
	var emitted []detection.Alert
	c := New(15*time.Minute, func(a detection.Alert) { emitted = append(emitted, a) })

	// Device A, then device B reusing the same IP after a lease change.
	c.Observe(detection.Alert{
		ClientMAC: "aa:bb:cc:dd:ee:01", ClientIP: "192.168.1.50",
		SignalClass: detection.SignalBeacon, Confidence: 75,
	})
	c.Observe(detection.Alert{
		ClientMAC: "aa:bb:cc:dd:ee:02", ClientIP: "192.168.1.50",
		SignalClass: detection.SignalVolumetric, Confidence: 70,
	})

	if len(emitted) != 0 {
		t.Fatalf("signals from two different MACs must not combine, got %d composite(s) "+
			"(confidence %d)", len(emitted), emitted[0].Confidence)
	}
}

func TestCompositeCarriesTriggerIdentity(t *testing.T) {
	var emitted []detection.Alert
	c := New(15*time.Minute, func(a detection.Alert) { emitted = append(emitted, a) })

	c.Observe(detection.Alert{
		ClientMAC: "aa:bb:cc:dd:ee:01", ClientIP: "192.168.1.50",
		SignalClass: detection.SignalIoC, Confidence: 90, Domain: "evil.example",
		MatchedIoC: "evil.example",
	})
	c.Observe(detection.Alert{
		ClientMAC: "aa:bb:cc:dd:ee:01", ClientIP: "192.168.1.50", ClientName: "laptop",
		SignalClass: detection.SignalBeacon, Confidence: 70,
	})

	if len(emitted) != 1 {
		t.Fatalf("expected one composite, got %d", len(emitted))
	}
	comp := emitted[0]
	if comp.ClientMAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("ClientMAC = %q, want the triggering device", comp.ClientMAC)
	}
	if comp.ClientIP != "192.168.1.50" {
		t.Errorf("ClientIP = %q", comp.ClientIP)
	}
	if comp.SignalCount != 2 {
		t.Errorf("SignalCount = %d, want 2", comp.SignalCount)
	}
	// The composite must advertise its contributing classes so the policy can
	// tell known-bad from heuristic.
	if len(comp.Signals) != 2 {
		t.Errorf("Signals = %v, want two classes", comp.Signals)
	}
}

// TestHeuristicPairConfidence documents the exact number the killswitch gate
// has to defend against: two capped heuristics reach critical severity.
func TestHeuristicPairConfidence(t *testing.T) {
	if got := combine([]int{75, 70}); got != 93 {
		t.Fatalf("combine([75,70]) = %d, want 93 — the policy's known-bad gate is "+
			"calibrated against this value", got)
	}
	if got := detection.SeverityForConfidence(93); got != detection.SeverityCritical {
		t.Fatalf("SeverityForConfidence(93) = %q, want critical", got)
	}
}

func TestCorrelationKeyFallsBackToIP(t *testing.T) {
	if got := correlationKey(detection.Alert{ClientIP: "10.0.0.1"}); got != "ip:10.0.0.1" {
		t.Errorf("key without MAC = %q", got)
	}
	if got := correlationKey(detection.Alert{ClientMAC: "AA:BB:CC:DD:EE:FF"}); got != "mac:aa:bb:cc:dd:ee:ff" {
		t.Errorf("MAC key should be lowercased, got %q", got)
	}
	if got := correlationKey(detection.Alert{}); got != "" {
		t.Errorf("an alert with no identity should not correlate, got %q", got)
	}
}
