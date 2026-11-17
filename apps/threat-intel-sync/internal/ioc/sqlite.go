package ioc

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/migel9090/netSoldier/libs/indicator"
	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"
)

// schemaVersion is stored in PRAGMA user_version. A database written by a
// newer build is refused rather than guessed at. Additive changes — a new
// table an older build never reads (volume_history, quarantine,
// quarantine_rows) — keep the version, so rolling the image back still
// starts on the same file.
const schemaVersion = 1

// sqliteDB persists each feed's assertions so a restart serves the last
// good set immediately. Before it existed the store was memory-only: a pod
// restarted during a feed outage came up empty, answered every export with
// an empty list, and every sensor replaced its good list with nothing.
type sqliteDB struct {
	db *sql.DB
}

type assertionKey struct {
	typ, value, feed string
}

// LoadStats reports what OpenStore found in the database.
type LoadStats struct {
	Loaded     int // assertions loaded
	Invalid    int // assertions that no longer pass validation, deleted
	NeverBlock int // assertions naming a host now on the never-block list, deleted
	Dropped    int // assertions beyond the store cap, deleted
	Held       int // held fetches loaded (volume guard quarantine)
}

// OpenStore opens (creating if needed) the SQLite database at path and
// returns a store holding its contents. Every persisted row is validated
// again on load: the rules may have tightened since it was written, and a
// row must not bypass them just because it was already on disk.
func OpenStore(path string, opts ...Option) (*Store, LoadStats, error) {
	var ls LoadStats
	d, err := openSQLite(path)
	if err != nil {
		return nil, ls, err
	}
	s := NewStore(opts...)
	s.db = d

	if s.feedSuccess, err = d.loadFeeds(); err != nil {
		d.close()
		return nil, ls, err
	}
	if s.history, err = d.loadVolumeHistory(); err != nil {
		d.close()
		return nil, ls, err
	}
	if s.held, err = d.loadHeld(); err != nil {
		d.close()
		return nil, ls, err
	}
	ls.Held = len(s.held)

	var stale []assertionKey
	rewrite := map[string][]Indicator{}
	err = d.loadAssertions(func(feed string, raw Indicator) {
		v, verr := Validate(raw)
		if verr != nil {
			if errors.Is(verr, indicator.ErrNeverBlock) {
				ls.NeverBlock++
			} else {
				ls.Invalid++
			}
			stale = append(stale, assertionKey{typ: raw.Type, value: raw.Value, feed: feed})
			return
		}
		v.LastAsserted = raw.LastAsserted
		if v.Value != raw.Value {
			// The canonical spelling changed since the row was written:
			// re-key it, or the old row would linger beyond every prune.
			stale = append(stale, assertionKey{typ: raw.Type, value: raw.Value, feed: feed})
			rewrite[feed] = append(rewrite[feed], v)
		}
		k := v.Key()
		e := s.items[k]
		if e == nil {
			if s.max > 0 && len(s.items) >= s.max {
				ls.Dropped++
				stale = append(stale, assertionKey{typ: raw.Type, value: raw.Value, feed: feed})
				return
			}
			e = &entry{}
			s.items[k] = e
		}
		e.set(feed, v)
		ls.Loaded++
	})
	if err != nil {
		d.close()
		return nil, ls, err
	}
	if len(stale) > 0 {
		if err := d.deleteAssertions(stale); err != nil {
			slog.Error("indicator database: deleting invalid rows failed", "error", err)
		}
	}
	for feed, inds := range rewrite {
		if err := d.upsertAssertions(feed, inds); err != nil {
			slog.Error("indicator database: re-keying rows failed", "feed", feed, "error", err)
		}
	}
	return s, ls, nil
}

func openSQLite(path string) (*sqliteDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s on %s: %w", pragma, path, err)
		}
	}

	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, fmt.Errorf("read schema version of %s: %w", path, err)
	}
	if version > schemaVersion {
		db.Close()
		return nil, fmt.Errorf("%s has schema version %d, this build understands %d",
			path, version, schemaVersion)
	}

	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS assertions (
			type          TEXT    NOT NULL,
			value         TEXT    NOT NULL,
			feed          TEXT    NOT NULL,
			source        TEXT    NOT NULL DEFAULT '',
			threat        TEXT    NOT NULL DEFAULT '',
			confidence    INTEGER NOT NULL DEFAULT 0,
			first_seen    INTEGER NOT NULL DEFAULT 0,
			last_seen     INTEGER NOT NULL DEFAULT 0,
			tags          TEXT    NOT NULL DEFAULT '[]',
			reference     TEXT    NOT NULL DEFAULT '',
			last_asserted INTEGER NOT NULL,
			PRIMARY KEY (type, value, feed)
		) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS feeds (
			feed         TEXT PRIMARY KEY,
			last_success INTEGER NOT NULL
		) WITHOUT ROWID`,
		// The volume guard's memory of each feed's usual size (distinct
		// indicators per applied fetch, a JSON array, oldest first). Without
		// it every restart would be a cold start, and a poisoned feed would
		// pass the guard by waiting for one.
		`CREATE TABLE IF NOT EXISTS volume_history (
			feed  TEXT PRIMARY KEY,
			sizes TEXT NOT NULL
		) WITHOUT ROWID`,
		// Fetches held back by the volume guard, kept across a restart so
		// the alert stays up and the operator can still release them.
		`CREATE TABLE IF NOT EXISTS quarantine (
			feed TEXT PRIMARY KEY,
			meta TEXT NOT NULL
		) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS quarantine_rows (
			feed       TEXT    NOT NULL,
			type       TEXT    NOT NULL,
			value      TEXT    NOT NULL,
			source     TEXT    NOT NULL DEFAULT '',
			threat     TEXT    NOT NULL DEFAULT '',
			confidence INTEGER NOT NULL DEFAULT 0,
			first_seen INTEGER NOT NULL DEFAULT 0,
			last_seen  INTEGER NOT NULL DEFAULT 0,
			tags       TEXT    NOT NULL DEFAULT '[]',
			reference  TEXT    NOT NULL DEFAULT '',
			PRIMARY KEY (feed, type, value)
		) WITHOUT ROWID`,
		fmt.Sprintf("PRAGMA user_version = %d", schemaVersion),
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("create schema in %s: %w", path, err)
		}
	}
	return &sqliteDB{db: db}, nil
}

func (d *sqliteDB) loadFeeds() (map[string]time.Time, error) {
	rows, err := d.db.Query(`SELECT feed, last_success FROM feeds`)
	if err != nil {
		return nil, fmt.Errorf("load feeds: %w", err)
	}
	defer rows.Close()
	out := make(map[string]time.Time)
	for rows.Next() {
		var feed string
		var ts int64
		if err := rows.Scan(&feed, &ts); err != nil {
			return nil, fmt.Errorf("load feeds: %w", err)
		}
		out[feed] = fromUnixNano(ts)
	}
	return out, rows.Err()
}

// loadAssertions streams every row, newest assertion first, so that when the
// cap is lower than the persisted set the freshest indicators survive.
func (d *sqliteDB) loadAssertions(fn func(feed string, ind Indicator)) error {
	rows, err := d.db.Query(`SELECT type, value, feed, source, threat, confidence,
		first_seen, last_seen, tags, reference, last_asserted
		FROM assertions ORDER BY last_asserted DESC`)
	if err != nil {
		return fmt.Errorf("load assertions: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			ind                     Indicator
			feed, tags              string
			first, last, assertedAt int64
		)
		if err := rows.Scan(&ind.Type, &ind.Value, &feed, &ind.Source, &ind.Threat,
			&ind.Confidence, &first, &last, &tags, &ind.Reference, &assertedAt); err != nil {
			return fmt.Errorf("load assertions: %w", err)
		}
		ind.FirstSeen = fromUnixNano(first)
		ind.LastSeen = fromUnixNano(last)
		ind.LastAsserted = fromUnixNano(assertedAt)
		if err := json.Unmarshal([]byte(tags), &ind.Tags); err != nil {
			ind.Tags = nil
		}
		fn(feed, ind)
	}
	return rows.Err()
}

func (d *sqliteDB) upsertAssertions(feed string, inds []Indicator) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("persist %s: %w", feed, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	stmt, err := tx.Prepare(`INSERT INTO assertions (type, value, feed, source, threat,
			confidence, first_seen, last_seen, tags, reference, last_asserted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (type, value, feed) DO UPDATE SET
			source = excluded.source, threat = excluded.threat,
			confidence = excluded.confidence, first_seen = excluded.first_seen,
			last_seen = excluded.last_seen, tags = excluded.tags,
			reference = excluded.reference, last_asserted = excluded.last_asserted`)
	if err != nil {
		return fmt.Errorf("persist %s: %w", feed, err)
	}
	defer stmt.Close()
	for _, ind := range inds {
		tags, _ := json.Marshal(ind.Tags)
		if ind.Tags == nil {
			tags = []byte("[]")
		}
		if _, err := stmt.Exec(ind.Type, ind.Value, feed, ind.Source, ind.Threat,
			ind.Confidence, toUnixNano(ind.FirstSeen), toUnixNano(ind.LastSeen),
			string(tags), ind.Reference, toUnixNano(ind.LastAsserted)); err != nil {
			return fmt.Errorf("persist %s: %w", feed, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("persist %s: %w", feed, err)
	}
	return nil
}

func (d *sqliteDB) deleteAssertions(keys []assertionKey) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	stmt, err := tx.Prepare(`DELETE FROM assertions WHERE type = ? AND value = ? AND feed = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, k := range keys {
		if _, err := stmt.Exec(k.typ, k.value, k.feed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// deleteFeed forgets everything recorded about a feed apart from its
// assertions (those go through deleteAssertions).
func (d *sqliteDB) deleteFeed(feed string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	for _, stmt := range []string{
		`DELETE FROM feeds WHERE feed = ?`,
		`DELETE FROM volume_history WHERE feed = ?`,
		`DELETE FROM quarantine WHERE feed = ?`,
		`DELETE FROM quarantine_rows WHERE feed = ?`,
	} {
		if _, err := tx.Exec(stmt, feed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *sqliteDB) loadVolumeHistory() (map[string][]int, error) {
	rows, err := d.db.Query(`SELECT feed, sizes FROM volume_history`)
	if err != nil {
		return nil, fmt.Errorf("load volume history: %w", err)
	}
	defer rows.Close()
	out := make(map[string][]int)
	for rows.Next() {
		var feed, sizes string
		if err := rows.Scan(&feed, &sizes); err != nil {
			return nil, fmt.Errorf("load volume history: %w", err)
		}
		var v []int
		if err := json.Unmarshal([]byte(sizes), &v); err != nil {
			// A row this build cannot read is a cold start for that feed,
			// not a reason to refuse to serve the indicator set.
			slog.Error("indicator database: unreadable volume history, starting it afresh",
				"feed", feed, "error", err)
			continue
		}
		clean := v[:0]
		for _, n := range v {
			if n >= 0 {
				clean = append(clean, n)
			}
		}
		if len(clean) > 0 {
			out[feed] = clean
		}
	}
	return out, rows.Err()
}

func (d *sqliteDB) setVolumeHistory(feed string, sizes []int) error {
	if len(sizes) == 0 {
		_, err := d.db.Exec(`DELETE FROM volume_history WHERE feed = ?`, feed)
		return err
	}
	b, _ := json.Marshal(sizes)
	_, err := d.db.Exec(`INSERT INTO volume_history (feed, sizes) VALUES (?, ?)
		ON CONFLICT (feed) DO UPDATE SET sizes = excluded.sizes`, feed, string(b))
	return err
}

// saveHeld replaces feed's held fetch, rows and description, in one
// transaction.
func (d *sqliteDB) saveHeld(h HeldSet) error {
	meta, err := json.Marshal(h)
	if err != nil {
		return err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("persist held %s: %w", h.Feed, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if _, err := tx.Exec(`DELETE FROM quarantine_rows WHERE feed = ?`, h.Feed); err != nil {
		return fmt.Errorf("persist held %s: %w", h.Feed, err)
	}
	stmt, err := tx.Prepare(`INSERT OR REPLACE INTO quarantine_rows (feed, type, value, source,
			threat, confidence, first_seen, last_seen, tags, reference)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("persist held %s: %w", h.Feed, err)
	}
	defer stmt.Close()
	for _, ind := range h.Rows {
		tags, _ := json.Marshal(ind.Tags)
		if ind.Tags == nil {
			tags = []byte("[]")
		}
		if _, err := stmt.Exec(h.Feed, ind.Type, ind.Value, ind.Source, ind.Threat, ind.Confidence,
			toUnixNano(ind.FirstSeen), toUnixNano(ind.LastSeen), string(tags), ind.Reference); err != nil {
			return fmt.Errorf("persist held %s: %w", h.Feed, err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO quarantine (feed, meta) VALUES (?, ?)
		ON CONFLICT (feed) DO UPDATE SET meta = excluded.meta`, h.Feed, string(meta)); err != nil {
		return fmt.Errorf("persist held %s: %w", h.Feed, err)
	}
	return tx.Commit()
}

func (d *sqliteDB) deleteHeld(feed string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after Commit
	if _, err := tx.Exec(`DELETE FROM quarantine_rows WHERE feed = ?`, feed); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM quarantine WHERE feed = ?`, feed); err != nil {
		return err
	}
	return tx.Commit()
}

// loadHeld reads every held fetch. Its rows are validated again, like the
// assertions: a row the rules no longer accept (or that the never-block
// list now protects) is left out, so releasing an old held set can never
// bypass them.
func (d *sqliteDB) loadHeld() (map[string]HeldSet, error) {
	out := make(map[string]HeldSet)
	rows, err := d.db.Query(`SELECT feed, meta FROM quarantine`)
	if err != nil {
		return nil, fmt.Errorf("load quarantine: %w", err)
	}
	for rows.Next() {
		var feed, meta string
		if err := rows.Scan(&feed, &meta); err != nil {
			rows.Close()
			return nil, fmt.Errorf("load quarantine: %w", err)
		}
		var h HeldSet
		if err := json.Unmarshal([]byte(meta), &h); err != nil {
			slog.Error("indicator database: unreadable held fetch, ignoring it", "feed", feed, "error", err)
			continue
		}
		h.Feed = feed
		out[feed] = h
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load quarantine: %w", err)
	}

	r, err := d.db.Query(`SELECT feed, type, value, source, threat, confidence,
		first_seen, last_seen, tags, reference FROM quarantine_rows`)
	if err != nil {
		return nil, fmt.Errorf("load quarantine rows: %w", err)
	}
	defer r.Close()
	for r.Next() {
		var (
			ind         Indicator
			feed, tags  string
			first, last int64
		)
		if err := r.Scan(&feed, &ind.Type, &ind.Value, &ind.Source, &ind.Threat, &ind.Confidence,
			&first, &last, &tags, &ind.Reference); err != nil {
			return nil, fmt.Errorf("load quarantine rows: %w", err)
		}
		h, ok := out[feed]
		if !ok {
			continue
		}
		ind.FirstSeen = fromUnixNano(first)
		ind.LastSeen = fromUnixNano(last)
		if err := json.Unmarshal([]byte(tags), &ind.Tags); err != nil {
			ind.Tags = nil
		}
		v, err := Validate(ind)
		if err != nil {
			continue
		}
		h.Rows = append(h.Rows, v)
		out[feed] = h
	}
	return out, r.Err()
}

func (d *sqliteDB) setFeedSuccess(feed string, t time.Time) error {
	_, err := d.db.Exec(`INSERT INTO feeds (feed, last_success) VALUES (?, ?)
		ON CONFLICT (feed) DO UPDATE SET last_success = excluded.last_success`,
		feed, toUnixNano(t))
	return err
}

func (d *sqliteDB) clearAssertions() error {
	_, err := d.db.Exec(`DELETE FROM assertions`)
	return err
}

func (d *sqliteDB) close() error { return d.db.Close() }

func toUnixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromUnixNano(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
