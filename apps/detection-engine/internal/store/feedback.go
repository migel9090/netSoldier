package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// Feedback is the journal of analyst verdicts, and the outbox of those not
// yet copied to ClickHouse.
//
// It is the record: the suppressions in force are what replaying it gives
// (package feedback does that at start-up). Verdicts used to live in memory
// and in ClickHouse only, so in the lite profile — no ClickHouse — every
// false-positive suppression silently disappeared at the next restart, while
// the API said it had been persisted. ClickHouse, when there is one, now
// receives a copy of each verdict for history, in the order they were
// recorded and retried until it accepts them, like the detection outbox
// (rows stay after they were copied, and are forgotten by age).
type Feedback struct {
	db      *sql.DB
	durable bool
}

// FeedbackRow is one verdict as the journal keeps it.
type FeedbackRow struct {
	Seq         int64
	RecordedAt  time.Time
	AlertID     string
	MatchedIoC  string
	ClientIP    string
	SignalClass string
	Verdict     string
	Reason      string
	Analyst     string
	// Attempts counts failed copies to ClickHouse.
	Attempts int
}

// Feedback returns the verdict journal.
func (s *Store) Feedback() *Feedback { return &Feedback{db: s.db, durable: s.durable} }

// Durable reports whether a recorded verdict survives a restart.
func (f *Feedback) Durable() bool { return f.durable }

const feedbackCols = `seq, recorded_at, alert_id, matched_ioc, client_ip, signal_class, verdict,
	reason, analyst, attempts`

func scanFeedback(sc interface{ Scan(...any) error }, extra ...any) (FeedbackRow, error) {
	var r FeedbackRow
	var at int64
	err := sc.Scan(append([]any{&r.Seq, &at, &r.AlertID, &r.MatchedIoC, &r.ClientIP, &r.SignalClass,
		&r.Verdict, &r.Reason, &r.Analyst, &r.Attempts}, extra...)...)
	r.RecordedAt = fromMilli(at)
	return r, err
}

func insertFeedback(x interface {
	Exec(string, ...any) (sql.Result, error)
}, r FeedbackRow, forwarded int) (int64, error) {
	res, err := x.Exec(`INSERT INTO feedback (recorded_at, alert_id, matched_ioc, client_ip,
		signal_class, verdict, reason, analyst, forwarded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		unixMilli(r.RecordedAt), r.AlertID, r.MatchedIoC, r.ClientIP, r.SignalClass, r.Verdict,
		r.Reason, r.Analyst, forwarded)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Append records a verdict and returns its sequence number. Once it has
// returned, the verdict is committed.
func (f *Feedback) Append(r FeedbackRow) (int64, error) {
	seq, err := insertFeedback(f.db, r, 0)
	if err != nil {
		storeErrors.WithLabelValues("feedback_append").Inc()
		return 0, fmt.Errorf("record verdict: %w", err)
	}
	return seq, nil
}

// Adopt records, in one transaction and in the order given, verdicts that
// ClickHouse already has: they are not copied there again.
func (f *Feedback) Adopt(rows []FeedbackRow) ([]int64, error) {
	tx, err := f.db.Begin()
	if err != nil {
		storeErrors.WithLabelValues("feedback_append").Inc()
		return nil, err
	}
	defer tx.Rollback()
	seqs := make([]int64, len(rows))
	for i, r := range rows {
		if seqs[i], err = insertFeedback(tx, r, 1); err != nil {
			storeErrors.WithLabelValues("feedback_append").Inc()
			return nil, fmt.Errorf("adopt verdict: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		storeErrors.WithLabelValues("feedback_append").Inc()
		return nil, err
	}
	return seqs, nil
}

// Fresh reports whether the journal has never held a verdict. Pruning does
// not make it fresh again: AUTOINCREMENT remembers the highest sequence
// number ever used.
func (f *Feedback) Fresh() (bool, error) {
	var n int64
	err := f.db.QueryRow(`SELECT seq FROM sqlite_sequence WHERE name = 'feedback'`).Scan(&n)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return true, nil
	case err != nil:
		storeErrors.WithLabelValues("feedback_read").Inc()
		return false, err
	}
	return n == 0, nil
}

// Replay calls fn for every verdict recorded at or after since, in the
// order they were recorded: by the server's time, then by sequence, so that
// two verdicts in the same millisecond keep the order they were made in.
func (f *Feedback) Replay(since time.Time, fn func(FeedbackRow) error) error {
	rows, err := f.db.Query(`SELECT `+feedbackCols+` FROM feedback WHERE recorded_at >= ?
		ORDER BY recorded_at, seq`, unixMilli(since))
	if err != nil {
		storeErrors.WithLabelValues("feedback_read").Inc()
		return err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanFeedback(rows)
		if err != nil {
			storeErrors.WithLabelValues("feedback_read").Inc()
			return err
		}
		if err := fn(r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// NextUnforwarded returns the oldest verdict not yet copied to ClickHouse,
// if its next attempt is due. Copies go strictly in order: while the oldest
// is backing off, nothing after it is sent.
func (f *Feedback) NextUnforwarded(now time.Time) (FeedbackRow, bool, error) {
	var next int64
	r, err := scanFeedback(f.db.QueryRow(`SELECT `+feedbackCols+`, next_attempt_at FROM feedback
		WHERE forwarded = 0 ORDER BY seq LIMIT 1`), &next)
	if errors.Is(err, sql.ErrNoRows) {
		return FeedbackRow{}, false, nil
	}
	if err != nil {
		storeErrors.WithLabelValues("feedback_read").Inc()
		return FeedbackRow{}, false, err
	}
	if next > unixMilli(now) {
		return FeedbackRow{}, false, nil
	}
	return r, true, nil
}

// Forwarded marks a verdict copied to ClickHouse.
func (f *Feedback) Forwarded(seq int64) error {
	if _, err := f.db.Exec(`UPDATE feedback SET forwarded = 1, last_error = '' WHERE seq = ?`, seq); err != nil {
		storeErrors.WithLabelValues("feedback_update").Inc()
		return err
	}
	return nil
}

// RetryForward records a failed copy and when to try again.
func (f *Feedback) RetryForward(seq int64, next time.Time, reason string) error {
	if _, err := f.db.Exec(`UPDATE feedback SET attempts = attempts + 1, next_attempt_at = ?,
		last_error = ? WHERE seq = ? AND forwarded = 0`, unixMilli(next), truncate(reason, 512), seq); err != nil {
		storeErrors.WithLabelValues("feedback_update").Inc()
		return err
	}
	return nil
}

// Unforwarded is the number of verdicts not yet copied to ClickHouse.
func (f *Feedback) Unforwarded() (int, error) {
	var n int
	err := f.db.QueryRow(`SELECT COUNT(*) FROM feedback WHERE forwarded = 0`).Scan(&n)
	return n, err
}

// Count is the number of verdicts in the journal.
func (f *Feedback) Count() (int, error) {
	var n int
	err := f.db.QueryRow(`SELECT COUNT(*) FROM feedback`).Scan(&n)
	return n, err
}

// Prune forgets verdicts recorded before cutoff — they no longer suppress
// anything, and replay ignores them — once they are in ClickHouse, or at
// once when nothing copies them there (forwarding false).
func (f *Feedback) Prune(cutoff time.Time, forwarding bool) (int64, error) {
	res, err := f.db.Exec(`DELETE FROM feedback WHERE recorded_at < ? AND (forwarded = 1 OR ? = 0)`,
		unixMilli(cutoff), boolInt(forwarding))
	if err != nil {
		storeErrors.WithLabelValues("feedback_prune").Inc()
		return 0, err
	}
	return res.RowsAffected()
}

// Compact forgets every verdict that replay does not need: all but keep
// (the verdicts behind the suppressions in force), among those recorded
// before the oldest verdict ClickHouse still lacks (all of them when nothing
// copies them there, forwarding false).
//
// Replaying what is left gives the same suppressions. What goes is a prefix
// of the replay order minus keep: a verdict no suppression rests on was
// superseded, ended, or ended something — and whatever it ended is older
// and goes with it.
func (f *Feedback) Compact(keep []int64, forwarding bool) (int64, error) {
	if keep == nil {
		keep = []int64{}
	}
	ids, err := json.Marshal(keep)
	if err != nil {
		return 0, err
	}
	boundary := int64(math.MaxInt64)
	if forwarding {
		var oldest sql.NullInt64
		if err := f.db.QueryRow(`SELECT MIN(recorded_at) FROM feedback WHERE forwarded = 0`).Scan(&oldest); err != nil {
			storeErrors.WithLabelValues("feedback_prune").Inc()
			return 0, err
		}
		if oldest.Valid {
			boundary = oldest.Int64
		}
	}
	res, err := f.db.Exec(`DELETE FROM feedback WHERE recorded_at < ?
		AND seq NOT IN (SELECT value FROM json_each(?))`, boundary, string(ids))
	if err != nil {
		storeErrors.WithLabelValues("feedback_prune").Inc()
		return 0, err
	}
	return res.RowsAffected()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
