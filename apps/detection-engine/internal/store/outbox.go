package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultAggregationWindow is how long a delivered (or queued) event
	// absorbs repeats of itself. One device retrying a listed name, or one
	// signature firing on every packet of a flow, is one detection; queueing
	// each repeat is how 250 junk hits pushed a critical one out.
	DefaultAggregationWindow = 10 * time.Minute
	// DefaultMaxPending bounds undelivered events (a few KiB each). Reaching
	// it takes a receiver that has been unreachable for a long time.
	DefaultMaxPending = 50000
)

// Outbox outcomes of Enqueue.
const (
	Queued     = "queued"
	Aggregated = "aggregated"
	Dropped    = "dropped"
)

const (
	statePending   = 0
	stateDelivered = 1
	stateRejected  = 2
)

var outboxEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Subsystem: "outbox",
	Name:      "events_total",
	Help:      "Detections offered to the outbox: queued, aggregated into an earlier one, or dropped from a full outbox.",
}, []string{"result"})

func init() {
	prometheus.MustRegister(outboxEvents)
	for _, r := range []string{Queued, Aggregated, Dropped} {
		outboxEvents.WithLabelValues(r)
	}
}

// Entry is one undelivered event.
type Entry struct {
	Seq        int64
	EventID    string
	Severity   string
	Body       []byte // the exact bytes to send, so redelivery keeps the event id
	Attempts   int
	Repeats    int
	EnqueuedAt time.Time
}

// Outbox is the durable queue of events owed to the receiver. Safe for
// concurrent use; it assumes it is the only writer of its table.
type Outbox struct {
	db         *sql.DB
	window     time.Duration
	maxPending int
	now        func() time.Time

	mu      sync.Mutex
	pending int
}

// Outbox opens the queue (defaults for values <= 0).
func (s *Store) Outbox(window time.Duration, maxPending int) (*Outbox, error) {
	if window <= 0 {
		window = DefaultAggregationWindow
	}
	if maxPending <= 0 {
		maxPending = DefaultMaxPending
	}
	o := &Outbox{db: s.db, window: window, maxPending: maxPending, now: time.Now}
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM outbox WHERE state = ?`, statePending).Scan(&o.pending); err != nil {
		return nil, fmt.Errorf("count outbox: %w", err)
	}
	return o, nil
}

// AggregationKey identifies "the same detection again": the same device
// (MAC when known, else address), the same signal class — for a composite,
// the same set of classes — the same indicator and the same target. A
// composite that gains a class, or a detection that would enforce something
// different, is new information and is never folded into an earlier one.
func AggregationKey(ev events.DetectionEvent) string {
	client := ev.ClientMAC
	if client == "" {
		client = ev.ClientIP
	}
	class := ev.SignalClass
	if class == events.SignalComposite {
		classes := ev.ContributingClasses()
		sort.Strings(classes)
		class += ":" + strings.Join(classes, "+")
	}
	target := ""
	if ev.Target != nil {
		target = ev.Target.Type + ":" + ev.Target.Value
	}
	return strings.Join([]string{client, class, ev.MatchedIoC, target}, "\x1f")
}

// Enqueue stores an event for delivery, unless an event with the same
// AggregationKey, at least as severe and as confident, was enqueued within
// the aggregation window — then it only counts as a repeat of that one.
//
// When the outbox is full the least severe, oldest pending event makes room;
// if every pending event is more severe than this one, this one is dropped.
func (o *Outbox) Enqueue(ev events.DetectionEvent) (string, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return "", fmt.Errorf("encode event: %w", err)
	}
	key := AggregationKey(ev)
	rank := severityRank(ev.Severity)
	now := o.now()

	o.mu.Lock()
	defer o.mu.Unlock()

	tx, err := o.db.Begin()
	if err != nil {
		storeErrors.WithLabelValues("outbox_enqueue").Inc()
		return "", err
	}
	defer tx.Rollback()

	// The same event id twice is the same event: already queued.
	var dup int
	switch err := tx.QueryRow(`SELECT 1 FROM outbox WHERE event_id = ?`, ev.ID).Scan(&dup); {
	case err == nil:
		outboxEvents.WithLabelValues(Aggregated).Inc()
		return Aggregated, nil
	case !errors.Is(err, sql.ErrNoRows):
		storeErrors.WithLabelValues("outbox_enqueue").Inc()
		return "", err
	}

	var seq int64
	var prevRank, prevConf int
	err = tx.QueryRow(`SELECT seq, sev_rank, confidence FROM outbox
		WHERE agg_key = ? AND enqueued_at >= ?
		ORDER BY sev_rank DESC, confidence DESC, seq DESC LIMIT 1`,
		key, unixMilli(now.Add(-o.window))).Scan(&seq, &prevRank, &prevConf)
	switch {
	case err == nil && rank <= prevRank && ev.Confidence <= prevConf:
		if _, err := tx.Exec(`UPDATE outbox SET repeats = repeats + 1 WHERE seq = ?`, seq); err != nil {
			storeErrors.WithLabelValues("outbox_enqueue").Inc()
			return "", err
		}
		if err := tx.Commit(); err != nil {
			storeErrors.WithLabelValues("outbox_enqueue").Inc()
			return "", err
		}
		outboxEvents.WithLabelValues(Aggregated).Inc()
		return Aggregated, nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		storeErrors.WithLabelValues("outbox_enqueue").Inc()
		return "", err
	}

	evicted := false
	if o.pending >= o.maxPending {
		var victim int64
		var victimRank int
		var victimID string
		if err := tx.QueryRow(`SELECT seq, sev_rank, event_id FROM outbox WHERE state = ?
			ORDER BY sev_rank ASC, seq ASC LIMIT 1`, statePending).Scan(&victim, &victimRank, &victimID); err != nil {
			storeErrors.WithLabelValues("outbox_enqueue").Inc()
			return "", err
		}
		if victimRank > rank {
			outboxEvents.WithLabelValues(Dropped).Inc()
			slog.Warn("outbox full: detection dropped, every queued one is more severe",
				"id", ev.ID, "severity", ev.Severity, "pending", o.pending)
			return Dropped, nil
		}
		if _, err := tx.Exec(`DELETE FROM outbox WHERE seq = ?`, victim); err != nil {
			storeErrors.WithLabelValues("outbox_enqueue").Inc()
			return "", err
		}
		evicted = true
		slog.Warn("outbox full: oldest least severe detection dropped to make room",
			"dropped_id", victimID, "for_id", ev.ID, "pending", o.pending)
	}

	if _, err := tx.Exec(`INSERT INTO outbox
		(event_id, agg_key, sev_rank, confidence, enqueued_at, next_attempt_at, body)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ev.ID, key, rank, ev.Confidence, unixMilli(now), unixMilli(now), body); err != nil {
		storeErrors.WithLabelValues("outbox_enqueue").Inc()
		return "", err
	}
	if err := tx.Commit(); err != nil {
		storeErrors.WithLabelValues("outbox_enqueue").Inc()
		return "", err
	}
	if evicted {
		o.pending--
		outboxEvents.WithLabelValues(Dropped).Inc()
	}
	o.pending++
	outboxEvents.WithLabelValues(Queued).Inc()
	return Queued, nil
}

// Next returns the pending event to deliver now: most severe first, oldest
// first within a severity, skipping events still backing off.
func (o *Outbox) Next(now time.Time) (Entry, bool, error) {
	var e Entry
	var rank int
	var enq int64
	err := o.db.QueryRow(`SELECT seq, event_id, sev_rank, attempts, repeats, enqueued_at, body
		FROM outbox WHERE state = ? AND next_attempt_at <= ?
		ORDER BY sev_rank DESC, seq ASC LIMIT 1`, statePending, unixMilli(now)).
		Scan(&e.Seq, &e.EventID, &rank, &e.Attempts, &e.Repeats, &enq, &e.Body)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, false, nil
	}
	if err != nil {
		storeErrors.WithLabelValues("outbox_read").Inc()
		return Entry{}, false, err
	}
	e.Severity, e.EnqueuedAt = rankSeverity(rank), fromMilli(enq)
	return e, true, nil
}

// Delivered marks an event acknowledged by the receiver. The row stays for
// the aggregation window so repeats are still recognised.
func (o *Outbox) Delivered(seq int64) error {
	return o.finish(seq, stateDelivered, "")
}

// Reject marks an event the receiver refused for good (it is invalid; no
// retry can change that).
func (o *Outbox) Reject(seq int64, reason string) error {
	return o.finish(seq, stateRejected, reason)
}

func (o *Outbox) finish(seq int64, state int, reason string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	res, err := o.db.Exec(`UPDATE outbox SET state = ?, last_error = ? WHERE seq = ? AND state = ?`,
		state, truncate(reason, 512), seq, statePending)
	if err != nil {
		storeErrors.WithLabelValues("outbox_update").Inc()
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		o.pending--
	}
	return nil
}

// Retry records a failed attempt and when to try again.
func (o *Outbox) Retry(seq int64, next time.Time, reason string) error {
	_, err := o.db.Exec(`UPDATE outbox SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?
		WHERE seq = ? AND state = ?`, unixMilli(next), truncate(reason, 512), seq, statePending)
	if err != nil {
		storeErrors.WithLabelValues("outbox_update").Inc()
	}
	return err
}

// Pending is the number of undelivered events.
func (o *Outbox) Pending() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.pending
}

// OldestPending is when the oldest undelivered event was enqueued.
func (o *Outbox) OldestPending() (time.Time, bool, error) {
	var ms sql.NullInt64
	if err := o.db.QueryRow(`SELECT MIN(enqueued_at) FROM outbox WHERE state = ?`, statePending).Scan(&ms); err != nil {
		storeErrors.WithLabelValues("outbox_read").Inc()
		return time.Time{}, false, err
	}
	if !ms.Valid {
		return time.Time{}, false, nil
	}
	return fromMilli(ms.Int64), true, nil
}

// Purge forgets delivered and rejected events once they can no longer
// absorb repeats.
func (o *Outbox) Purge() (int64, error) {
	res, err := o.db.Exec(`DELETE FROM outbox WHERE state != ? AND enqueued_at < ?`,
		statePending, unixMilli(o.now().Add(-o.window)))
	if err != nil {
		storeErrors.WithLabelValues("outbox_purge").Inc()
		return 0, err
	}
	return res.RowsAffected()
}

func rankSeverity(rank int) string {
	switch rank {
	case 3:
		return events.SeverityCritical
	case 2:
		return events.SeverityHigh
	case 1:
		return events.SeverityMedium
	default:
		return events.SeverityLow
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
