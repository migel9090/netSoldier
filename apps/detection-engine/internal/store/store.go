// Package store is detection-engine's local state: the alert history served
// by GET /alerts, the outbox of detections still owed to the killswitch, how
// far each input (the AdGuard querylog, each sensor table) has been read,
// which input records have already made a detection, and the analysts'
// verdicts that suppress detections.
//
// It is one SQLite file (pure Go, modernc.org/sqlite) on the pod's volume.
// Both halves used to live in memory — a 1000-entry ring and a 64-slot
// channel — so a burst evicted real alerts, a slow receiver dropped
// detections, and every restart lost both. A local file is enough: the data
// is per instance, small, and must survive exactly the events (restart,
// receiver outage) during which a network database may not be there either.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

var (
	storeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "store_errors_total",
		Help:      "Local store operations that failed, by operation.",
	}, []string{"op"})
	durableGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "store_durable",
		Help:      "1 when alerts, undelivered detections and analyst verdicts are kept on disk, 0 when only in memory (lost on restart).",
	})
)

func init() {
	prometheus.MustRegister(storeErrors, durableGauge)
}

// schema is applied in order; PRAGMA user_version records how far a file
// has got. Append, never edit: files on existing volumes are at some step.
var schema = []string{
	`CREATE TABLE alerts (
		seq         INTEGER PRIMARY KEY AUTOINCREMENT,
		id          TEXT NOT NULL UNIQUE,
		recorded_at INTEGER NOT NULL, -- unix ms, server clock
		sev_rank    INTEGER NOT NULL,
		body        BLOB NOT NULL     -- detection.Alert as JSON
	);
	CREATE INDEX alerts_prune ON alerts (sev_rank, seq);
	CREATE INDEX alerts_age ON alerts (recorded_at);

	CREATE TABLE outbox (
		seq             INTEGER PRIMARY KEY AUTOINCREMENT,
		event_id        TEXT NOT NULL UNIQUE,
		agg_key         TEXT NOT NULL,
		sev_rank        INTEGER NOT NULL,
		confidence      INTEGER NOT NULL,
		state           INTEGER NOT NULL DEFAULT 0, -- 0 pending, 1 delivered, 2 rejected
		enqueued_at     INTEGER NOT NULL,           -- unix ms
		repeats         INTEGER NOT NULL DEFAULT 0,
		attempts        INTEGER NOT NULL DEFAULT 0,
		next_attempt_at INTEGER NOT NULL,
		last_error      TEXT NOT NULL DEFAULT '',
		body            BLOB NOT NULL               -- events.DetectionEvent as JSON
	);
	CREATE INDEX outbox_due ON outbox (state, sev_rank DESC, seq);
	CREATE INDEX outbox_agg ON outbox (agg_key, enqueued_at);
	CREATE INDEX outbox_age ON outbox (state, enqueued_at);`,

	`CREATE TABLE ingest_cursors (
		source     TEXT PRIMARY KEY,
		position   BLOB NOT NULL,    -- the reader's own encoding
		updated_at INTEGER NOT NULL  -- unix ms, server clock
	);

	CREATE TABLE ingest_records (
		record  BLOB PRIMARY KEY,    -- digest of (input, record)
		seen_at INTEGER NOT NULL     -- unix ms, server clock
	) WITHOUT ROWID;
	CREATE INDEX ingest_records_age ON ingest_records (seen_at);`,

	`CREATE TABLE feedback (
		seq             INTEGER PRIMARY KEY AUTOINCREMENT,
		recorded_at     INTEGER NOT NULL,           -- unix ms, server clock
		alert_id        TEXT NOT NULL DEFAULT '',
		matched_ioc     TEXT NOT NULL,
		client_ip       TEXT NOT NULL DEFAULT '',
		signal_class    TEXT NOT NULL,
		verdict         TEXT NOT NULL,              -- false_positive | confirmed | lifted
		reason          TEXT NOT NULL DEFAULT '',
		analyst         TEXT NOT NULL DEFAULT '',
		forwarded       INTEGER NOT NULL DEFAULT 0, -- 1 once ClickHouse accepted it
		attempts        INTEGER NOT NULL DEFAULT 0,
		next_attempt_at INTEGER NOT NULL DEFAULT 0, -- unix ms
		last_error      TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX feedback_replay ON feedback (recorded_at, seq);
	CREATE INDEX feedback_outbox ON feedback (forwarded, seq);`,
}

// Store is an open local database.
type Store struct {
	db      *sql.DB
	path    string
	durable bool
}

// Open opens (creating if needed) the database file at path. The directory
// is created with owner-only permissions: the file holds which names each
// device resolved.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store path is empty")
	}
	if strings.ContainsAny(path, "?#") {
		// They would end the file: URI the driver is given.
		return nil, fmt.Errorf("store path %q contains ? or #", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	// Create the file ourselves so it is 0600; SQLite gives the -wal and
	// -shm files the same mode as the database.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open store file: %w", err)
	}
	f.Close()

	// WAL + synchronous=NORMAL: a commit survives the process being killed;
	// only a power cut can lose the last commits before a checkpoint. FULL
	// would cost an fsync per detection, which on an SD card turns a burst
	// into seconds of stalled polling.
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)"
	s, err := open(dsn)
	if err != nil {
		return nil, err
	}
	s.path, s.durable = path, true
	durableGauge.Set(1)
	return s, nil
}

// OpenMemory opens a store that lives only as long as the process. It is
// the fallback when no usable path exists; nothing in it survives a restart.
func OpenMemory() (*Store, error) {
	s, err := open("file::memory:?_pragma=foreign_keys(ON)")
	if err == nil {
		durableGauge.Set(0)
	}
	return s, err
}

func open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	// One connection: SQLite has one writer anyway, an in-memory database
	// exists per connection, and serialising here means no SQLITE_BUSY.
	db.SetMaxOpenConns(1)
	db.SetConnMaxIdleTime(0)
	db.SetConnMaxLifetime(0)
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func migrate(db *sql.DB) error {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read store version: %w", err)
	}
	if version > len(schema) {
		return fmt.Errorf("store schema version %d is newer than this binary (%d)", version, len(schema))
	}
	for i := version; i < len(schema); i++ {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(schema[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("store schema step %d: %w", i+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Durable reports whether the store is backed by a file.
func (s *Store) Durable() bool { return s.durable }

// Path is the database file, "" for an in-memory store.
func (s *Store) Path() string { return s.path }

// Close checkpoints and closes the database.
func (s *Store) Close() error {
	if s.durable {
		_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return s.db.Close()
}

// severityRank orders severities for retention and delivery: higher first.
func severityRank(sev string) int {
	switch sev {
	case events.SeverityCritical:
		return 3
	case events.SeverityHigh:
		return 2
	case events.SeverityMedium:
		return 1
	default:
		return 0
	}
}

func unixMilli(t time.Time) int64 { return t.UnixMilli() }

func fromMilli(ms int64) time.Time { return time.UnixMilli(ms).UTC() }
