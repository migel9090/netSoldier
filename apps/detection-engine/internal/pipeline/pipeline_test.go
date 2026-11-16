package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/composite"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/feedback"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/webhook"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type memAlerts struct {
	mu     sync.Mutex
	alerts []detection.Alert
}

func (m *memAlerts) Add(a detection.Alert) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.alerts = append(m.alerts, a)
	return nil
}

type harness struct {
	alerts    *memAlerts
	store     *feedback.Store
	forwarded []detection.Alert
	p         *Pipeline
}

func newHarness() *harness {
	h := &harness{alerts: &memAlerts{}, store: feedback.New(nil)}
	h.p = &Pipeline{
		Alerts:    h.alerts,
		Suppress:  h.store,
		Correlate: composite.New(15*time.Minute, nil),
		Forward:   func(a detection.Alert) { h.forwarded = append(h.forwarded, a) },
	}
	return h
}

func beacon(client string) detection.Alert {
	return detection.Alert{ID: detection.NewID(), ClientIP: client, MatchedIoC: "telemetry.vendor.example",
		Domain: "telemetry.vendor.example", Confidence: 75, Severity: "high", SignalClass: detection.SignalBeacon,
		Signals: []events.Signal{{Class: detection.SignalBeacon, Confidence: 75, Indicator: "telemetry.vendor.example"}}}
}

func c2Lookup(client string) detection.Alert {
	return detection.Alert{ID: detection.NewID(), ClientIP: client, MatchedIoC: "c2.real-threat.example",
		Domain: "c2.real-threat.example", Confidence: 60, Severity: "medium", SignalClass: detection.SignalIoC,
		Signals: []events.Signal{{Class: detection.SignalIoC, Confidence: 60, Indicator: "c2.real-threat.example"}}}
}

func carries(a detection.Alert, indicator string) bool {
	for _, s := range a.Signals {
		if s.Indicator == indicator {
			return true
		}
	}
	return a.MatchedIoC == indicator
}

// TestBeaconVerdictDoesNotSwallowLaterC2Lookup is the audit's scenario: an
// analyst marks a device's beacon to a vendor host benign; minutes later
// the same device looks up a feed-listed C2 name. The composite took the
// beacon's indicator, matched the verdict, was dropped — and took the C2
// detection with it: nothing reached the killswitch.
func TestBeaconVerdictDoesNotSwallowLaterC2Lookup(t *testing.T) {
	h := newHarness()
	h.p.Handle(beacon("192.168.1.50"))
	if err := h.store.Record(feedback.Verdict{MatchedIoC: "telemetry.vendor.example", ClientIP: "192.168.1.50",
		SignalClass: detection.SignalBeacon, Verdict: feedback.VerdictFalsePositive, Analyst: "a"}); err != nil {
		t.Fatal(err)
	}
	n := len(h.forwarded)
	h.p.Handle(c2Lookup("192.168.1.50"))

	got := h.forwarded[n:]
	if len(got) != 1 || !carries(got[0], "c2.real-threat.example") {
		t.Fatalf("forwarded for the C2 lookup: %+v, want one detection carrying it", got)
	}
}

// TestSuppressedCompositeForwardsTrigger: a verdict on a composite says the
// combination is benign; the detection that formed it is still judged, and
// delivered, on its own merits.
func TestSuppressedCompositeForwardsTrigger(t *testing.T) {
	h := newHarness()
	h.p.Handle(beacon("192.168.1.50"))
	// The analyst marked an earlier composite (anchored on the beacon) benign.
	if err := h.store.Record(feedback.Verdict{MatchedIoC: "telemetry.vendor.example", ClientIP: "192.168.1.50",
		SignalClass: detection.SignalComposite, Verdict: feedback.VerdictFalsePositive, Analyst: "a"}); err != nil {
		t.Fatal(err)
	}
	trigger := c2Lookup("192.168.1.50")
	n := len(h.forwarded)
	h.p.Handle(trigger)

	got := h.forwarded[n:]
	if len(got) != 1 || got[0].ID != trigger.ID {
		t.Fatalf("forwarded %+v, want the trigger itself", got)
	}
	// Both were recorded: the composite is in the history even though it
	// was not delivered.
	var sawComposite bool
	for _, a := range h.alerts.alerts {
		sawComposite = sawComposite || a.SignalClass == detection.SignalComposite
	}
	if !sawComposite {
		t.Error("a suppressed composite must still be recorded")
	}
}

func TestCompositeSupersedesTrigger(t *testing.T) {
	h := newHarness()
	h.p.Handle(beacon("192.168.1.50"))
	h.p.Handle(c2Lookup("192.168.1.50"))
	if len(h.forwarded) != 2 || h.forwarded[1].SignalClass != detection.SignalComposite {
		t.Fatalf("forwarded %+v, want the beacon then the composite", h.forwarded)
	}
	if len(h.alerts.alerts) != 3 {
		t.Errorf("recorded %d alerts, want beacon, C2 lookup and composite", len(h.alerts.alerts))
	}
}

// TestSuppressedTriggerIsRecordedNotForwarded: suppression decides what
// reaches the killswitch, not what the analyst can see.
func TestSuppressedTriggerIsRecordedNotForwarded(t *testing.T) {
	h := newHarness()
	_ = h.store.Record(feedback.Verdict{MatchedIoC: "c2.real-threat.example", SignalClass: detection.SignalIoC,
		Verdict: feedback.VerdictFalsePositive, Analyst: "a"})
	h.p.Handle(c2Lookup("192.168.1.50"))
	if len(h.forwarded) != 0 || len(h.alerts.alerts) != 1 {
		t.Errorf("forwarded %d, recorded %d; want 0 and 1", len(h.forwarded), len(h.alerts.alerts))
	}
}

// TestRecordedAlertsSaySuppressed: a detection silenced by a verdict was
// recorded exactly like a new one, so the analyst who marked it benign kept
// seeing "new alerts" for it. Recorded under a verdict, it now says so; one
// that is not, and a composite that is not, do not.
func TestRecordedAlertsSaySuppressed(t *testing.T) {
	recorded := func(h *harness, id string) detection.Alert {
		t.Helper()
		for _, a := range h.alerts.alerts {
			if a.ID == id {
				return a
			}
		}
		t.Fatalf("alert %s was not recorded", id)
		return detection.Alert{}
	}

	t.Run("no verdict", func(t *testing.T) {
		h := newHarness()
		a := c2Lookup("192.168.1.50")
		h.p.Handle(a)
		if recorded(h, a.ID).Suppressed {
			t.Error("an alert no verdict applies to is marked suppressed")
		}
	})

	t.Run("verdict on the detection", func(t *testing.T) {
		h := newHarness()
		_ = h.store.Record(feedback.Verdict{MatchedIoC: "c2.real-threat.example", SignalClass: detection.SignalIoC,
			Verdict: feedback.VerdictFalsePositive, Analyst: "a"})
		a := c2Lookup("192.168.1.50")
		h.p.Handle(a)
		if !recorded(h, a.ID).Suppressed || len(h.forwarded) != 0 {
			t.Errorf("recorded %+v, forwarded %d; want it kept, marked suppressed, not delivered",
				recorded(h, a.ID), len(h.forwarded))
		}
	})

	t.Run("verdict on the composite", func(t *testing.T) {
		h := newHarness()
		h.p.Handle(beacon("192.168.1.50"))
		_ = h.store.Record(feedback.Verdict{MatchedIoC: "telemetry.vendor.example", ClientIP: "192.168.1.50",
			SignalClass: detection.SignalComposite, Verdict: feedback.VerdictFalsePositive, Analyst: "a"})
		trigger := c2Lookup("192.168.1.50")
		h.p.Handle(trigger)

		var comps []detection.Alert
		for _, a := range h.alerts.alerts {
			if a.SignalClass == detection.SignalComposite {
				comps = append(comps, a)
			}
		}
		if len(comps) != 1 || !comps[0].Suppressed {
			t.Errorf("composites recorded: %+v, want one marked suppressed", comps)
		}
		if recorded(h, trigger.ID).Suppressed {
			t.Error("the trigger is judged on its own and no verdict applies to it")
		}
		if got := h.forwarded[len(h.forwarded)-1]; got.ID != trigger.ID || got.Suppressed {
			t.Errorf("delivered %+v, want the trigger, unmarked", got)
		}
	})
}

func TestNothingConfigured(t *testing.T) {
	p := &Pipeline{Alerts: &memAlerts{}}
	p.Handle(c2Lookup("192.168.1.50")) // no suppressor, correlator or receiver: must not panic
}

type failingAlerts struct{}

func (failingAlerts) Add(detection.Alert) error { return fmt.Errorf("disk full") }

func TestStoreFailureDoesNotStopDelivery(t *testing.T) {
	var forwarded int
	p := &Pipeline{Alerts: failingAlerts{}, Forward: func(detection.Alert) { forwarded++ }}
	p.Handle(c2Lookup("192.168.1.50"))
	if forwarded != 1 {
		t.Error("a detection that could not be recorded locally must still be delivered")
	}
}

func TestForwarderRefusesInvalidEvents(t *testing.T) {
	st, _ := store.OpenMemory()
	defer st.Close()
	ob, _ := st.Outbox(0, 0)
	notified := 0
	f := &Forwarder{Outbox: ob, Notify: func() { notified++ }}

	before := testutil.ToFloat64(invalidEvents)
	f.Forward(detection.Alert{ID: "not-an-id", ClientIP: "192.168.1.5", SignalClass: detection.SignalIoC})
	if testutil.ToFloat64(invalidEvents) != before+1 || ob.Pending() != 0 {
		t.Error("an invalid event was queued or not counted")
	}

	a := c2Lookup("192.168.1.50")
	a.Timestamp, a.Summary = time.Now(), "s"
	f.Forward(a)
	a.ID = detection.NewID()
	f.Forward(a) // a repeat: aggregated, nothing to wake the dispatcher for
	if ob.Pending() != 1 || notified != 1 {
		t.Errorf("pending=%d notified=%d, want 1/1", ob.Pending(), notified)
	}
}

// fakeQueryLog behaves like AdGuard Home's /control/querylog: newest-first,
// truncated to ?limit=N.
type fakeQueryLog struct {
	mu      sync.Mutex
	entries []map[string]any // oldest first
}

func (f *fakeQueryLog) add(host, client string, ts time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, map[string]any{
		"question": map[string]string{"host": host, "type": "A"}, "client": client, "time": ts,
	})
}

func (f *fakeQueryLog) handler(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]any
	for i := len(f.entries) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, f.entries[i])
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
}

// TestFloodDoesNotMaskCriticalDetection is the audit's flood: a device
// makes its real C2 lookup, then 250 lookups under a low-confidence listed
// domain, all in one poll interval. Walking the querylog newest-first, the
// junk filled the 64-slot queue and the critical detection was the one
// dropped (critical delivered 0 times, junk 65 times). Now the junk is one
// aggregated detection and nothing is lost; and when the receiver is
// briefly unavailable during the flood, the critical one goes first once it
// is back.
func TestFloodDoesNotMaskCriticalDetection(t *testing.T) {
	for _, receiverDown := range []bool{false, true} {
		t.Run(fmt.Sprintf("receiver_down_during_flood=%v", receiverDown), func(t *testing.T) {
			order, recorded := floodScenario(t, receiverDown)
			counts := map[string]int{}
			for _, ev := range order {
				counts[ev.MatchedIoC]++
			}
			t.Logf("delivered: critical C2 detection=%d, junk detections=%d (of 250 hits), first=%s",
				counts["c2.real-threat.example"], counts["old-urlhaus-host.example"], order[0].MatchedIoC)
			if counts["c2.real-threat.example"] != 1 {
				t.Fatalf("the critical detection was delivered %d times, want 1", counts["c2.real-threat.example"])
			}
			if counts["old-urlhaus-host.example"] != 1 {
				t.Errorf("250 repeats of one listed domain were delivered %d times, want 1 aggregated",
					counts["old-urlhaus-host.example"])
			}
			if receiverDown && order[0].MatchedIoC != "c2.real-threat.example" {
				t.Errorf("first delivery after the outage = %s (%s), want the critical detection",
					order[0].MatchedIoC, order[0].Severity)
			}
			if recorded != 251 {
				t.Errorf("history holds %d alerts, want every one of the 251 detections", recorded)
			}
		})
	}
}

// floodScenario runs the real engine, pipeline, outbox and dispatcher
// against a fake querylog and a receiver, and returns what the receiver
// accepted, in order, plus how many alerts were recorded.
func floodScenario(t *testing.T, receiverDown bool) ([]events.DetectionEvent, int) {
	var mu sync.Mutex
	var order []events.DetectionEvent
	refusing := receiverDown
	rx := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		refuse := refusing
		mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusServiceUnavailable) // killswitch restarting
			return
		}
		var ev events.DetectionEvent
		_ = json.Unmarshal(b, &ev)
		time.Sleep(2 * time.Millisecond) // healthy in-cluster killswitch
		mu.Lock()
		order = append(order, ev)
		mu.Unlock()
	}))
	defer rx.Close()

	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	ob, _ := st.Outbox(0, 0)
	d := webhook.NewDispatcher(ob, webhook.NewSender(rx.URL, "s", "t"))

	f := &fakeQueryLog{}
	ag := httptest.NewServer(http.HandlerFunc(f.handler))
	defer ag.Close()
	m := iocmatch.New()
	m.Add([]iocmatch.IoC{
		{Value: "c2.real-threat.example", Type: "domain", Source: "threatfox", Confidence: 100},
		{Value: "old-urlhaus-host.example", Type: "domain", Source: "urlhaus", Confidence: 0},
	})
	engine := detection.New(adguard.NewClient(ag.URL, "u", "p"), m, 20*time.Millisecond)
	fw := &Forwarder{Outbox: ob, Notify: d.Notify}
	alerts := st.Alerts(0, 0)
	engine.OnAlert = (&Pipeline{Alerts: alerts, Suppress: feedback.New(nil),
		Correlate: composite.New(15*time.Minute, nil), Forward: fw.Forward}).Handle

	base := time.Now().Add(time.Second)
	f.add("c2.real-threat.example", "192.168.1.66", base)
	for i := 0; i < 250; i++ {
		f.add(fmt.Sprintf("n%d.old-urlhaus-host.example", i), "192.168.1.66", base.Add(time.Duration(i+1)*time.Millisecond))
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	engineDone := make(chan struct{})
	go func() { defer close(engineDone); engine.Run(ctx) }()

	deadline := time.Now().Add(time.Minute)
	recorded := 0
	for time.Now().Before(deadline) {
		all, _ := alerts.Recent(store.MaxListLimit)
		recorded = len(all)
		mu.Lock()
		if recorded == 251 {
			refusing = false // the killswitch is back
		}
		delivered := len(order)
		mu.Unlock()
		if recorded == 251 && ob.Pending() == 0 && delivered >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	<-engineDone

	mu.Lock()
	defer mu.Unlock()
	if len(order) == 0 {
		t.Fatal("nothing was delivered")
	}
	return append([]events.DetectionEvent(nil), order...), recorded
}
