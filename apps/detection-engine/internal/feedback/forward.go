package feedback

import (
	"context"
	"log/slog"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// After the n-th failed copy of a verdict the forwarder waits
	// forwardBase·2^(n-1), at most forwardMax, and never gives up: the copy
	// is history, not what keeps the verdict in force, so there is no hurry,
	// only no loss.
	forwardBase = 2 * time.Second
	forwardMax  = 5 * time.Minute
	// forwardIdle is how often an idle forwarder looks for verdicts.
	forwardIdle = 5 * time.Second
	// forwardTimeout bounds one insert.
	forwardTimeout = 15 * time.Second
)

var forwardBacklog = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: "detection_engine",
	Name:      "feedback_forward_backlog",
	Help:      "Analyst verdicts recorded locally and not yet copied to ClickHouse.",
})

func init() {
	prometheus.MustRegister(forwardBacklog)
}

// Sink receives copies of verdicts (*CHSink).
type Sink interface {
	Write(ctx context.Context, v Verdict) error
}

// Outbox is the journal's copy queue (*store.Feedback).
type Outbox interface {
	NextUnforwarded(now time.Time) (store.FeedbackRow, bool, error)
	Forwarded(seq int64) error
	RetryForward(seq int64, next time.Time, reason string) error
	Unforwarded() (int, error)
}

// Forwarder copies journaled verdicts to ClickHouse in the order they were
// recorded, marking each copied only once ClickHouse accepted it and
// retrying with backoff for as long as it takes — the detection outbox's
// way, applied to verdicts. A verdict waiting here is already in force and
// already survives a restart.
type Forwarder struct {
	q    Outbox
	sink Sink
	now  func() time.Time
	wake chan struct{}
	// back-off schedule; tests shorten it
	base, retryCap, idle time.Duration
}

// NewForwarder returns a forwarder; start it with Run.
func NewForwarder(q Outbox, sink Sink) *Forwarder {
	return &Forwarder{q: q, sink: sink, now: time.Now, wake: make(chan struct{}, 1),
		base: forwardBase, retryCap: forwardMax, idle: forwardIdle}
}

// Notify tells the forwarder a verdict was recorded. It never blocks.
func (f *Forwarder) Notify() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// Run copies until ctx is cancelled. A copy cut short by the cancellation
// stays queued, its attempt not counted.
func (f *Forwarder) Run(ctx context.Context) {
	f.refreshBacklog()
	for ctx.Err() == nil {
		if f.step(ctx) {
			continue
		}
		f.refreshBacklog()
		select {
		case <-ctx.Done():
		case <-f.wake:
		case <-time.After(f.idle):
		}
	}
}

// step makes one copy attempt and reports whether another is due at once.
func (f *Forwarder) step(ctx context.Context) bool {
	r, ok, err := f.q.NextUnforwarded(f.now())
	if err != nil {
		slog.Error("reading the feedback journal failed", "error", err)
		return false
	}
	if !ok {
		return false
	}
	wctx, cancel := context.WithTimeout(ctx, forwardTimeout)
	err = f.sink.Write(wctx, verdictOf(r))
	cancel()
	switch {
	case err == nil:
		if err := f.q.Forwarded(r.Seq); err != nil {
			// ClickHouse has it; at worst it is copied again.
			slog.Error("could not mark a verdict copied", "seq", r.Seq, "error", err)
			return false
		}
		return true
	case ctx.Err() != nil:
		return false
	default:
		wait := backoff(f.base, f.retryCap, r.Attempts+1)
		slog.Warn("copying a verdict to ClickHouse failed, will retry; it is in force and on disk meanwhile",
			"seq", r.Seq, "attempt", r.Attempts+1, "retry_in", wait, "error", err)
		if err := f.q.RetryForward(r.Seq, f.now().Add(wait), err.Error()); err != nil {
			slog.Error("could not record a copy attempt", "seq", r.Seq, "error", err)
		}
		return false
	}
}

func (f *Forwarder) refreshBacklog() {
	if n, err := f.q.Unforwarded(); err == nil {
		forwardBacklog.Set(float64(n))
	}
}

// backoff is base·2^(n-1), capped.
func backoff(base, limit time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}
