// Package webhook delivers detection events to the killswitch (or any
// receiver of the events.DetectionEvent contract) from the durable outbox.
//
// Delivery is at-least-once: an event stays in the outbox until the receiver
// acknowledges it, across receiver outages and restarts of this service. The
// receiver is idempotent on the event id, so a redelivery after a lost
// acknowledgement creates nothing new.
package webhook

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// Per event: after the n-th failed attempt the event waits
	// retryBase·2^(n-1), at most retryMax. It is never given up on. The cap
	// is short on purpose: once the receiver is back, every event is due
	// again within retryMax and goes out in severity order, instead of a
	// critical one sitting out a long back-off behind newer, lesser ones.
	retryBase = time.Second
	retryMax  = 30 * time.Second
	// After any failed attempt the dispatcher itself pauses, doubling up to
	// pauseMax while failures continue, so a receiver that is down costs one
	// request per pause rather than one per queued event.
	pauseMax = 30 * time.Second
	// idlePoll is how often an idle dispatcher looks for events whose
	// back-off has ended.
	idlePoll = time.Second
)

var (
	backlogGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Subsystem: "outbox",
		Name:      "backlog",
		Help:      "Detections in the outbox not yet acknowledged by the receiver.",
	})
	// oldestPending is the unix-nano enqueue time of the oldest
	// undelivered event, 0 when there is none; the age is computed at
	// scrape time so it keeps growing while the dispatcher is backing off.
	oldestPending atomic.Int64
	oldestAge     = prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Subsystem: "outbox",
		Name:      "oldest_age_seconds",
		Help:      "Age of the oldest detection not yet acknowledged by the receiver (0 when none).",
	}, func() float64 {
		ns := oldestPending.Load()
		if ns == 0 {
			return 0
		}
		return time.Since(time.Unix(0, ns)).Seconds()
	})
)

func init() {
	prometheus.MustRegister(backlogGauge, oldestAge)
}

// Queue is the durable outbox the dispatcher drains (*store.Outbox).
type Queue interface {
	Next(now time.Time) (store.Entry, bool, error)
	Delivered(seq int64) error
	Retry(seq int64, next time.Time, reason string) error
	Reject(seq int64, reason string) error
	Pending() int
	OldestPending() (time.Time, bool, error)
}

// Dispatcher drains a Queue into a Sender, most severe first.
type Dispatcher struct {
	q    Queue
	s    *Sender
	now  func() time.Time
	wake chan struct{}
	// back-off schedule; tests shorten it
	base, retryCap, pauseCap, idle time.Duration

	failures int // consecutive failed attempts; only touched by the loop
}

// NewDispatcher returns a dispatcher; start it with Run.
func NewDispatcher(q Queue, s *Sender) *Dispatcher {
	return &Dispatcher{
		q: q, s: s, now: time.Now, wake: make(chan struct{}, 1),
		base: retryBase, retryCap: retryMax, pauseCap: pauseMax, idle: idlePoll,
	}
}

// Notify tells the dispatcher an event was queued. It never blocks.
func (d *Dispatcher) Notify() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run delivers until ctx is cancelled. An attempt cut short by the
// cancellation leaves its event pending, exactly as it was.
func (d *Dispatcher) Run(ctx context.Context) {
	d.refreshGauges()
	slog.Info("webhook dispatcher started", "url", d.s.URL(), "backlog", d.q.Pending())
	for ctx.Err() == nil {
		e, ok, err := d.q.Next(d.now())
		if err != nil {
			slog.Error("reading the outbox failed", "error", err)
			sleep(ctx, d.idle)
			continue
		}
		if !ok {
			d.refreshGauges()
			select {
			case <-ctx.Done():
			case <-d.wake:
			case <-time.After(d.idle):
			}
			continue
		}
		res := d.attempt(ctx, e)
		d.refreshGauges()
		if res == ResultFailure || res == ResultUnauthorized {
			sleep(ctx, d.pause())
		}
	}
}

// Flush delivers what it can before ctx ends, for a clean shutdown: every
// pending event once, most severe first, ignoring back-off, stopping at the
// first sign the receiver is not taking deliveries. Whatever is left stays
// on disk for the next start.
func (d *Dispatcher) Flush(ctx context.Context) (delivered, left int) {
	farFuture := d.now().Add(100 * 365 * 24 * time.Hour)
	for ctx.Err() == nil {
		e, ok, err := d.q.Next(farFuture)
		if err != nil || !ok {
			break
		}
		res := d.attempt(ctx, e)
		if res == ResultSuccess {
			delivered++
			continue
		}
		if res != ResultRejected {
			break
		}
	}
	d.refreshGauges()
	return delivered, d.q.Pending()
}

// attempt makes one delivery attempt for e and records the outcome.
func (d *Dispatcher) attempt(ctx context.Context, e store.Entry) string {
	res, err := d.s.Send(ctx, e.Body)
	if ctx.Err() != nil && res != ResultSuccess {
		// Shutdown or flush deadline, not the receiver's doing: the event
		// stays pending and the attempt is not counted against it.
		return ResultFailure
	}
	deliveriesTotal.WithLabelValues(res).Inc()

	switch res {
	case ResultSuccess:
		d.failures = 0
		if err := d.q.Delivered(e.Seq); err != nil {
			// The receiver has it; at worst it is sent again and the
			// receiver answers with its earlier decision.
			slog.Error("could not mark detection delivered", "id", e.EventID, "error", err)
		}
	case ResultRejected:
		d.failures = 0
		slog.Error("webhook receiver refused detection; it will not be retried",
			"id", e.EventID, "severity", e.Severity, "error", err)
		if err := d.q.Reject(e.Seq, err.Error()); err != nil {
			slog.Error("could not mark detection rejected", "id", e.EventID, "error", err)
		}
	default:
		d.failures++
		wait := backoff(d.base, d.retryCap, e.Attempts+1)
		if res == ResultUnauthorized {
			slog.Error("webhook rejected our credentials — enforcement is NOT running; "+
				"detections are kept and retried; check WEBHOOK_TOKEN against the receiver's API key",
				"url", d.s.URL(), "has_token", d.s.token != "", "id", e.EventID, "error", err)
		} else {
			slog.Warn("webhook delivery failed, will retry",
				"url", d.s.URL(), "id", e.EventID, "severity", e.Severity,
				"attempt", e.Attempts+1, "retry_in", wait, "backlog", d.q.Pending(), "error", err)
		}
		if err := d.q.Retry(e.Seq, d.now().Add(wait), err.Error()); err != nil {
			slog.Error("could not record delivery attempt", "id", e.EventID, "error", err)
		}
	}
	return res
}

func (d *Dispatcher) pause() time.Duration {
	return backoff(d.base, d.pauseCap, d.failures)
}

func (d *Dispatcher) refreshGauges() {
	backlogGauge.Set(float64(d.q.Pending()))
	t, ok, err := d.q.OldestPending()
	switch {
	case err != nil:
		// keep the last value rather than claim an empty outbox
	case !ok:
		oldestPending.Store(0)
	default:
		oldestPending.Store(t.UnixNano())
	}
}

// backoff is base·2^(n-1), capped.
func backoff(base, limit time.Duration, n int) time.Duration {
	if n <= 1 {
		return base
	}
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
