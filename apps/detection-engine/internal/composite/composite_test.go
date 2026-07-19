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
