package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func testEvent(n int, severity string) events.DetectionEvent {
	ind := fmt.Sprintf("c2-%d.example", n)
	conf := map[string]int{events.SeverityCritical: 95, events.SeverityHigh: 75,
		events.SeverityMedium: 55, events.SeverityLow: 20}[severity]
	return events.DetectionEvent{
		SchemaVersion: events.DetectionSchemaVersion,
		ID:            events.FormatDetectionID("test", uint64(n)),
		Timestamp:     time.Now().UTC(),
		Summary:       "DNS query for " + ind,
		Domain:        ind, MatchedIoC: ind, IoCType: events.IndicatorDomain,
		ClientIP: "192.168.1.50", Severity: severity, Confidence: conf, Source: "test",
		SignalClass: events.SignalIoC,
		Signals: []events.Signal{{Class: events.SignalIoC, Confidence: conf,
			Indicator: ind, IndicatorType: events.IndicatorDomain}},
		Target: &events.Target{Type: events.TargetDomain, Value: ind},
	}
}

func newOutbox(t *testing.T) *store.Outbox {
	t.Helper()
	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ob, err := st.Outbox(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	return ob
}

func enqueue(t *testing.T, ob *store.Outbox, ev events.DetectionEvent) {
	t.Helper()
	if res, err := ob.Enqueue(ev); err != nil || res != store.Queued {
		t.Fatalf("enqueue %s = %s, %v", ev.ID, res, err)
	}
}

// fastDispatcher keeps the production schedule's shape at millisecond scale.
func fastDispatcher(q Queue, s *Sender) *Dispatcher {
	d := NewDispatcher(q, s)
	d.base, d.retryCap, d.pauseCap, d.idle = 5*time.Millisecond, 40*time.Millisecond, 40*time.Millisecond, 5*time.Millisecond
	return d
}

// runUntil runs d until cond holds (or fails the test after 10 s).
func runUntil(t *testing.T, d *Dispatcher, cond func() bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached within 10s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// receiver records event ids in arrival order and answers with status().
type receiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	ids    []string
	status atomic.Int32
	calls  atomic.Int32
	delay  time.Duration
}

func newReceiver(t *testing.T) *receiver {
	rx := &receiver{}
	rx.status.Store(http.StatusOK)
	rx.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rx.calls.Add(1)
		time.Sleep(rx.delay)
		code := int(rx.status.Load())
		if code == http.StatusOK {
			body, _ := io.ReadAll(r.Body)
			var ev events.DetectionEvent
			_ = json.Unmarshal(body, &ev)
			rx.mu.Lock()
			rx.ids = append(rx.ids, ev.ID)
			rx.mu.Unlock()
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(rx.srv.Close)
	return rx
}

func (rx *receiver) got() []string {
	rx.mu.Lock()
	defer rx.mu.Unlock()
	return append([]string(nil), rx.ids...)
}

// TestBurstIsNotDropped: one poll can emit hundreds of detections. A 64-slot
// non-blocking queue delivered 64 of a 300 burst and dropped the rest.
func TestBurstIsNotDropped(t *testing.T) {
	rx := newReceiver(t)
	rx.delay = time.Millisecond
	ob := newOutbox(t)
	d := fastDispatcher(ob, NewSender(rx.srv.URL, "s", "t"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	const burst = 300
	for i := 0; i < burst; i++ {
		enqueue(t, ob, testEvent(i, events.SeverityMedium))
		d.Notify()
	}
	deadline := time.Now().Add(20 * time.Second)
	for len(rx.got()) < burst && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if n := len(rx.got()); n != burst {
		t.Fatalf("delivered %d of a %d burst", n, burst)
	}
	if ob.Pending() != 0 {
		t.Errorf("backlog = %d after delivering everything", ob.Pending())
	}
}

// TestOutageDoesNotDiscard: the receiver used to get four attempts over
// about seven seconds, after which the event was discarded for good. Here
// the receiver stays down through many more attempts than that and every
// event still arrives once it is back.
func TestOutageDoesNotDiscard(t *testing.T) {
	rx := newReceiver(t)
	rx.status.Store(http.StatusServiceUnavailable)
	ob := newOutbox(t)
	for i := 0; i < 10; i++ {
		enqueue(t, ob, testEvent(i, events.SeverityHigh))
	}
	d := fastDispatcher(ob, NewSender(rx.srv.URL, "s", "t"))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	for rx.calls.Load() < 12 { // well past the old give-up point
		time.Sleep(5 * time.Millisecond)
	}
	if ob.Pending() != 10 {
		t.Fatalf("pending during the outage = %d, want all 10 kept", ob.Pending())
	}
	if age := testutil.ToFloat64(oldestAge); age <= 0 {
		t.Errorf("oldest_age_seconds = %v during an outage, want > 0", age)
	}
	rx.status.Store(http.StatusOK)
	deadline := time.Now().Add(10 * time.Second)
	for ob.Pending() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if n := len(rx.got()); n != 10 {
		t.Fatalf("delivered %d of 10 after the receiver came back", n)
	}
	if b := testutil.ToFloat64(backlogGauge); b != 0 {
		t.Errorf("backlog gauge = %v after delivery", b)
	}
	if age := testutil.ToFloat64(oldestAge); age != 0 {
		t.Errorf("oldest_age_seconds = %v with nothing pending", age)
	}
}

// TestHigherSeverityDeliveredFirst: a critical detection must not wait
// behind lesser ones queued before it.
func TestHigherSeverityDeliveredFirst(t *testing.T) {
	rx := newReceiver(t)
	ob := newOutbox(t)
	order := []string{events.SeverityLow, events.SeverityMedium, events.SeverityLow,
		events.SeverityCritical, events.SeverityHigh}
	for i, sev := range order {
		enqueue(t, ob, testEvent(i, sev))
	}
	d := fastDispatcher(ob, NewSender(rx.srv.URL, "", ""))
	runUntil(t, d, func() bool { return ob.Pending() == 0 })

	want := []string{"DET-test-3", "DET-test-4", "DET-test-1", "DET-test-0", "DET-test-2"}
	if got := rx.got(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("delivery order = %v, want %v (severity, then age)", got, want)
	}
}

// TestClientErrorIsNotRetried: a 4xx such as 422 (an event the receiver
// refuses as invalid) cannot be fixed by sending it again.
func TestClientErrorIsNotRetried(t *testing.T) {
	rx := newReceiver(t)
	rx.status.Store(http.StatusUnprocessableEntity)
	ob := newOutbox(t)
	enqueue(t, ob, testEvent(1, events.SeverityHigh))
	d := fastDispatcher(ob, NewSender(rx.srv.URL, "s", "t"))
	runUntil(t, d, func() bool { return ob.Pending() == 0 })
	time.Sleep(50 * time.Millisecond)
	if c := rx.calls.Load(); c != 1 {
		t.Errorf("a 422 was attempted %d times, want 1", c)
	}
}

// TestUnauthorizedIsKeptAndRetried: a refused token is a deployment bug.
// The event used to be discarded on the first 401; once the token is fixed
// it must still arrive.
func TestUnauthorizedIsKeptAndRetried(t *testing.T) {
	rx := newReceiver(t)
	rx.status.Store(http.StatusUnauthorized)
	ob := newOutbox(t)
	enqueue(t, ob, testEvent(1, events.SeverityCritical))
	d := fastDispatcher(ob, NewSender(rx.srv.URL, "s", "stale-token"))

	before := testutil.ToFloat64(deliveriesTotal.WithLabelValues(ResultUnauthorized))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	for rx.calls.Load() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	if ob.Pending() != 1 {
		t.Fatal("a 401 must not discard the detection")
	}
	rx.status.Store(http.StatusOK) // operator fixed WEBHOOK_TOKEN on the receiver side
	for ob.Pending() > 0 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if got := rx.got(); len(got) != 1 || got[0] != "DET-test-1" {
		t.Errorf("delivered %v", got)
	}
	if testutil.ToFloat64(deliveriesTotal.WithLabelValues(ResultUnauthorized)) <= before {
		t.Error("refused credentials must be counted as unauthorized")
	}
}

// TestShutdownKeepsTheBacklogForTheNextStart: SIGTERM used to drop whatever
// was queued or in back-off, with no metric and no log line (0 of 10
// accounted for). Now a shutdown flushes what it can within its bound and
// the rest is on disk; the next process delivers it.
func TestShutdownKeepsTheBacklogForTheNextStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "de.db")
	rx := newReceiver(t)
	rx.status.Store(http.StatusServiceUnavailable)

	// First process: receiver down, then SIGTERM.
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ob, err := st.Outbox(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		enqueue(t, ob, testEvent(i, events.SeverityHigh))
	}
	d := fastDispatcher(ob, NewSender(rx.srv.URL, "s", "t"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	for rx.calls.Load() < 3 {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	fctx, fcancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	delivered, left := d.Flush(fctx)
	fcancel()
	if delivered != 0 || left != 10 {
		t.Fatalf("flush against a down receiver: delivered=%d left=%d, want 0/10", delivered, left)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Second process: receiver back.
	rx.status.Store(http.StatusOK)
	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	ob2, err := st2.Outbox(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ob2.Pending() != 10 {
		t.Fatalf("after restart the outbox holds %d, want 10", ob2.Pending())
	}
	runUntil(t, fastDispatcher(ob2, NewSender(rx.srv.URL, "s", "t")), func() bool { return ob2.Pending() == 0 })
	if n := len(rx.got()); n != 10 {
		t.Fatalf("delivered %d of 10 after the restart", n)
	}
}

// TestFlushDeliversWhatItCan: a clean shutdown with a healthy receiver
// leaves nothing behind.
func TestFlushDeliversWhatItCan(t *testing.T) {
	rx := newReceiver(t)
	ob := newOutbox(t)
	for i := 0; i < 5; i++ {
		enqueue(t, ob, testEvent(i, events.SeverityLow))
	}
	// One of them was backing off: a flush tries it anyway.
	e, _, _ := ob.Next(time.Now())
	_ = ob.Retry(e.Seq, time.Now().Add(time.Hour), "earlier failure")

	d := fastDispatcher(ob, NewSender(rx.srv.URL, "", ""))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	delivered, left := d.Flush(ctx)
	if delivered != 5 || left != 0 {
		t.Fatalf("flush delivered=%d left=%d, want 5/0", delivered, left)
	}
}

// TestCancelledAttemptLeavesEventUntouched: an attempt cut short by
// shutdown is not the receiver's verdict and must not count against the
// event.
func TestCancelledAttemptLeavesEventUntouched(t *testing.T) {
	rx := newReceiver(t)
	rx.delay = 300 * time.Millisecond
	ob := newOutbox(t)
	enqueue(t, ob, testEvent(1, events.SeverityHigh))
	d := fastDispatcher(ob, NewSender(rx.srv.URL, "", ""))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); d.Run(ctx) }()
	for rx.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	e, ok, err := ob.Next(time.Now())
	if err != nil || !ok {
		t.Fatalf("event gone after a cancelled attempt: ok=%v err=%v", ok, err)
	}
	if e.Attempts != 0 {
		t.Errorf("attempts = %d, want 0 for an attempt cut short by shutdown", e.Attempts)
	}
}

func TestBackoff(t *testing.T) {
	for n, want := range map[int]time.Duration{
		0: time.Second, 1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second,
		5: 16 * time.Second, 6: 30 * time.Second, 50: 30 * time.Second,
	} {
		if got := backoff(retryBase, retryMax, n); got != want {
			t.Errorf("backoff(%d) = %v, want %v", n, got, want)
		}
	}
}
