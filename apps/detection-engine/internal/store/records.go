package store

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"
)

// Records remembers which input records (a querylog entry, a sensor row)
// have already made a detection.
//
// The readers re-read on purpose: each poll looks a little behind its
// cursor for records that became visible late, and a restart re-reads from
// the last stored position, or from the look-back when that is lost. A
// record read again must not become a second alert and a second delivery.
// Detection ids cannot carry that — they are per process (contract §1), so
// the same record gets a new id after a restart — hence this ledger, keyed
// by the record itself. A record is kept as long as it can still be re-read:
// the look-back plus a margin.
type Records struct {
	db     *sql.DB
	maxAge time.Duration
	now    func() time.Time
}

// Records returns the ledger, keeping entries for maxAge (1 h when <= 0).
func (s *Store) Records(maxAge time.Duration) *Records {
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	return &Records{db: s.db, maxAge: maxAge, now: time.Now}
}

func recordKey(record string) []byte {
	sum := sha256.Sum256([]byte(record))
	return sum[:16]
}

// Seen reports whether record already made a detection. A read error says
// no: the detection is then made again rather than lost.
func (r *Records) Seen(record string) bool {
	var one int
	err := r.db.QueryRow(`SELECT 1 FROM ingest_records WHERE record = ?`, recordKey(record)).Scan(&one)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		storeErrors.WithLabelValues("record_read").Inc()
	}
	return err == nil
}

// Remember records that record has made its detection.
func (r *Records) Remember(record string) {
	if _, err := r.db.Exec(`INSERT OR IGNORE INTO ingest_records (record, seen_at) VALUES (?, ?)`,
		recordKey(record), unixMilli(r.now())); err != nil {
		storeErrors.WithLabelValues("record_write").Inc()
	}
}

// Prune forgets records that can no longer be read again.
func (r *Records) Prune() (int64, error) {
	res, err := r.db.Exec(`DELETE FROM ingest_records WHERE seen_at < ?`, unixMilli(r.now().Add(-r.maxAge)))
	if err != nil {
		storeErrors.WithLabelValues("record_prune").Inc()
		return 0, err
	}
	return res.RowsAffected()
}
