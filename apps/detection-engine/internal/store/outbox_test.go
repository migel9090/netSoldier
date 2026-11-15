package store

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

func event(id uint64, indicator, sev string, conf int) events.DetectionEvent {
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            events.FormatDetectionID("t", id),
		Timestamp:     time.Now().UTC(), Summary: "s",
		Domain: indicator, MatchedIoC: indicator, IoCType: events.IndicatorDomain,
		ClientIP: "192.168.1.66", Severity: sev, Confidence: conf, Source: "test",
		SignalClass: events.SignalIoC,
		Signals:     []events.Signal{{Class: events.SignalIoC, Confidence: conf, Indicator: indicator}},
		Target:      &events.Target{Type: events.TargetDomain, Value: indicator},
	}
}

func outbox(t *testing.T, window time.Duration, max int) *Outbox {
	t.Helper()
	ob, err := memStore(t).Outbox(window, max)
	if err != nil {
		t.Fatal(err)
	}
	return ob
}

func mustEnqueue(t *testing.T, ob *Outbox, ev events.DetectionEvent, want string) {
	t.Helper()
	got, err := ob.Enqueue(ev)
	if err != nil || got != want {
		t.Fatalf("Enqueue(%s) = %s, %v; want %s", ev.ID, got, err, want)
	}
}

// TestRepeatsAreAggregated: 250 hits on one listed name from one device in
// one poll were 250 queued events, and the queue was 64 deep. Within the
// window they are one event.
func TestRepeatsAreAggregated(t *testing.T) {
	ob := outbox(t, time.Minute, 0)
	now := time.Now()
	ob.now = func() time.Time { return now }

	mustEnqueue(t, ob, event(1, "junk.example", events.SeverityLow, 10), Queued)
	for i := uint64(2); i <= 250; i++ {
		mustEnqueue(t, ob, event(i, "junk.example", events.SeverityLow, 10), Aggregated)
	}
	if ob.Pending() != 1 {
		t.Fatalf("pending = %d, want the repeats folded into one", ob.Pending())
	}
	e, _, _ := ob.Next(now)
	if e.Repeats != 249 {
		t.Errorf("repeats = %d, want 249", e.Repeats)
	}

	// Delivered, and the device keeps going: still one detection while the
	// window lasts...
	_ = ob.Delivered(e.Seq)
	mustEnqueue(t, ob, event(300, "junk.example", events.SeverityLow, 10), Aggregated)
	// ...and a new one after it.
	ob.now = func() time.Time { return now.Add(2 * time.Minute) }
	mustEnqueue(t, ob, event(301, "junk.example", events.SeverityLow, 10), Queued)
}

// TestNewInformationIsNotAggregated: a repeat that is more severe, more
// confident, about another device, another indicator, another class or a
// different composite is a new detection.
func TestNewInformationIsNotAggregated(t *testing.T) {
	ob := outbox(t, time.Hour, 0)
	base := event(1, "c2.example", events.SeverityHigh, 75)
	mustEnqueue(t, ob, base, Queued)

	n := uint64(10)
	variant := func(f func(*events.DetectionEvent)) events.DetectionEvent {
		n++
		ev := base
		ev.ID = events.FormatDetectionID("t", n)
		f(&ev)
		return ev
	}
	mustEnqueue(t, ob, variant(func(e *events.DetectionEvent) {}), Aggregated)
	mustEnqueue(t, ob, variant(func(e *events.DetectionEvent) { e.Confidence = 60 }), Aggregated)
	// In order: each case shares the key of the ones before it, and is
	// compared with the strongest of them.
	cases := []struct {
		name string
		ev   events.DetectionEvent
	}{
		{"more confident", variant(func(e *events.DetectionEvent) { e.Confidence = 85 })},
		{"more severe", variant(func(e *events.DetectionEvent) { e.Severity, e.Confidence = events.SeverityCritical, 95 })},
		{"other device", variant(func(e *events.DetectionEvent) { e.ClientIP = "192.168.1.67" })},
		{"other MAC", variant(func(e *events.DetectionEvent) { e.ClientMAC = "aa:bb:cc:dd:ee:01" })},
		{"other indicator", variant(func(e *events.DetectionEvent) { e.MatchedIoC = "c3.example" })},
		{"other target", variant(func(e *events.DetectionEvent) {
			e.Target = &events.Target{Type: events.TargetIP, Value: "203.0.113.7"}
		})},
		{"other class", variant(func(e *events.DetectionEvent) { e.SignalClass = events.SignalTLS })},
	}
	for _, c := range cases {
		if got, err := ob.Enqueue(c.ev); err != nil || got != Queued {
			t.Errorf("%s: %s, %v; want queued", c.name, got, err)
		}
	}
	// Weaker than the critical one now on record: a repeat.
	mustEnqueue(t, ob, variant(func(e *events.DetectionEvent) {}), Aggregated)
}

// TestCompositeThatGainsAClassIsNew: beacon+volumetric and then
// beacon+volumetric+ioc share the anchor indicator; the second carries a
// known-bad signal and must reach the killswitch.
func TestCompositeThatGainsAClassIsNew(t *testing.T) {
	comp := func(id uint64, classes ...string) events.DetectionEvent {
		ev := event(id, "telemetry.example", events.SeverityCritical, 93)
		ev.SignalClass = events.SignalComposite
		ev.Signals = nil
		for _, c := range classes {
			ev.Signals = append(ev.Signals, events.Signal{Class: c, Confidence: 70})
		}
		return ev
	}
	ob := outbox(t, time.Hour, 0)
	mustEnqueue(t, ob, comp(1, events.SignalBeacon, events.SignalVolumetric), Queued)
	mustEnqueue(t, ob, comp(2, events.SignalVolumetric, events.SignalBeacon), Aggregated)
	mustEnqueue(t, ob, comp(3, events.SignalBeacon, events.SignalVolumetric, events.SignalIoC), Queued)
}

func TestNextOrdersBySeverityThenAgeAndHonoursBackoff(t *testing.T) {
	ob := outbox(t, 0, 0)
	for i, sev := range []string{events.SeverityLow, events.SeverityHigh, events.SeverityCritical, events.SeverityHigh} {
		mustEnqueue(t, ob, event(uint64(i), fmt.Sprintf("i%d.example", i), sev, 50), Queued)
	}
	now := time.Now()
	e, ok, err := ob.Next(now)
	if err != nil || !ok || e.EventID != "DET-t-2" || e.Severity != events.SeverityCritical {
		t.Fatalf("first = %+v %v %v, want the critical one", e, ok, err)
	}
	// It fails and backs off: the next high one goes first meanwhile.
	if err := ob.Retry(e.Seq, now.Add(time.Minute), "503"); err != nil {
		t.Fatal(err)
	}
	if e, _, _ := ob.Next(now); e.EventID != "DET-t-1" {
		t.Errorf("during back-off next = %s, want DET-t-1", e.EventID)
	}
	if e, _, _ := ob.Next(now.Add(2 * time.Minute)); e.EventID != "DET-t-2" || e.Attempts != 1 {
		t.Errorf("after back-off next = %s (attempts %d), want DET-t-2 again", e.EventID, e.Attempts)
	}
}

func TestDeliveredAndRejectedLeaveTheBacklog(t *testing.T) {
	ob := outbox(t, time.Minute, 0)
	now := time.Now()
	ob.now = func() time.Time { return now }
	mustEnqueue(t, ob, event(1, "a.example", events.SeverityHigh, 75), Queued)
	mustEnqueue(t, ob, event(2, "b.example", events.SeverityHigh, 75), Queued)

	oldest, ok, err := ob.OldestPending()
	if err != nil || !ok || oldest.UnixMilli() != now.UnixMilli() {
		t.Errorf("OldestPending = %v %v %v", oldest, ok, err)
	}
	e1, _, _ := ob.Next(now)
	_ = ob.Delivered(e1.Seq)
	_ = ob.Delivered(e1.Seq) // twice: no double count
	e2, _, _ := ob.Next(now)
	_ = ob.Reject(e2.Seq, "422 invalid")
	if ob.Pending() != 0 {
		t.Fatalf("pending = %d", ob.Pending())
	}
	if _, ok, _ := ob.OldestPending(); ok {
		t.Error("OldestPending reports an event with nothing pending")
	}
	if _, ok, _ := ob.Next(now); ok {
		t.Error("Next returned a finished event")
	}

	// Finished rows stay for the window (they absorb repeats), then go.
	if n, _ := ob.Purge(); n != 0 {
		t.Errorf("purged %d rows still inside the window", n)
	}
	ob.now = func() time.Time { return now.Add(2 * time.Minute) }
	if n, _ := ob.Purge(); n != 2 {
		t.Errorf("purged %d rows past the window, want 2", n)
	}
}

// TestFullOutboxDropsTheLeastSevere: the outbox is bounded, and what gives
// way is the least severe, oldest event — never a critical one for noise.
func TestFullOutboxDropsTheLeastSevere(t *testing.T) {
	ob := outbox(t, time.Hour, 3)
	mustEnqueue(t, ob, event(1, "crit.example", events.SeverityCritical, 95), Queued)
	mustEnqueue(t, ob, event(2, "low1.example", events.SeverityLow, 10), Queued)
	mustEnqueue(t, ob, event(3, "low2.example", events.SeverityLow, 10), Queued)

	mustEnqueue(t, ob, event(4, "high.example", events.SeverityHigh, 75), Queued) // evicts low1
	if ob.Pending() != 3 {
		t.Fatalf("pending = %d, cap 3", ob.Pending())
	}
	var got []string
	for {
		e, ok, _ := ob.Next(time.Now())
		if !ok {
			break
		}
		got = append(got, e.EventID)
		_ = ob.Delivered(e.Seq)
	}
	if fmt.Sprint(got) != "[DET-t-1 DET-t-4 DET-t-3]" {
		t.Errorf("kept %v, want critical, high and the newer low", got)
	}

	// Full of criticals: a low one is the one that is dropped.
	ob2 := outbox(t, time.Hour, 1)
	mustEnqueue(t, ob2, event(1, "crit.example", events.SeverityCritical, 95), Queued)
	mustEnqueue(t, ob2, event(2, "low.example", events.SeverityLow, 10), Dropped)
	if e, _, _ := ob2.Next(time.Now()); e.EventID != "DET-t-1" {
		t.Errorf("the critical event was displaced by %s", e.EventID)
	}
}

func TestDuplicateEventIDIsQueuedOnce(t *testing.T) {
	ob := outbox(t, time.Nanosecond, 0)
	ev := event(1, "a.example", events.SeverityHigh, 75)
	mustEnqueue(t, ob, ev, Queued)
	time.Sleep(time.Millisecond) // past the window: aggregation cannot catch it
	mustEnqueue(t, ob, ev, Aggregated)
	if ob.Pending() != 1 {
		t.Errorf("pending = %d", ob.Pending())
	}
}

// TestBacklogSurvivesRestart: queued events used to live in a channel.
func TestBacklogSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "de.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ob, _ := st.Outbox(0, 0)
	mustEnqueue(t, ob, event(1, "a.example", events.SeverityLow, 10), Queued)
	mustEnqueue(t, ob, event(2, "b.example", events.SeverityCritical, 95), Queued)
	st.Close()

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	ob2, err := st2.Outbox(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ob2.Pending() != 2 {
		t.Fatalf("pending after restart = %d, want 2", ob2.Pending())
	}
	if e, _, _ := ob2.Next(time.Now()); e.EventID != "DET-t-2" {
		t.Errorf("after restart the critical event is not first: %s", e.EventID)
	}
}
