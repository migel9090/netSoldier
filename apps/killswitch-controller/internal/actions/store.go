package actions

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"

	_ "modernc.org/sqlite" // pure-Go driver (BSD-3-Clause), registered as "sqlite"
)

// schemaVersion is stored in PRAGMA user_version. A database written by a
// newer build is refused rather than guessed at.
const schemaVersion = 1

// System actors. Every transition names who caused it; operators are named
// by the X-Netsoldier-Actor header and may not use these names. They are
// the contract's (libs/events), where every service that takes the header
// reserves the same ones.
const (
	ActorPolicy    = events.ActorPolicy    // the policy: creations and automatic approvals
	ActorTTL       = events.ActorTTL       // the reaper: expiries, TTL reverts, retries
	ActorReconcile = events.ActorReconcile // reconciliation with what is really in force
	ActorAgent     = events.ActorAgent     // a result reported by the netagent
	ActorSystem    = events.ActorSystem    // capacity eviction
)

// IsSystemActor reports whether name is reserved for the controller itself.
func IsSystemActor(name string) bool { return events.IsReservedActor(name) }

// Driver operations an action can have outstanding. They are the wire's
// in_flight values: Action serves Op as it is.
const (
	OpNone   = ""
	OpApply  = events.OperationApply
	OpRevert = events.OperationRevert
)

// Options configures retention and identity.
type Options struct {
	// MaxTerminal bounds how many finished actions are kept. Only terminal
	// actions are ever evicted; nothing that is or may be enforced is.
	MaxTerminal int
	// MaxPending bounds the approval queue. A new pending action beyond it
	// expires the oldest pending one.
	MaxPending int
	// PendingTTL is how long a pending action waits for a human.
	PendingTTL time.Duration
	// IDPrefix namespaces action ids. The default carries a random id made
	// once per database, so ids stay unique across restarts and across a
	// lost database.
	IDPrefix string
	// Now is the clock; time.Now when nil.
	Now func() time.Time
}

// Store is the durable record of every action, the rules and commands the
// drivers own, the evaluation ledger and the audit log. See the package
// documentation for the state machine.
type Store struct {
	db       *sql.DB
	opts     Options
	instance string
}

// Record is an action with the bookkeeping that is not part of the wire
// contract.
type Record struct {
	events.EnforcementAction

	Seq       int64
	DedupeKey string
	UpdatedAt time.Time
	// PendingUntil is when a pending action expires.
	PendingUntil time.Time
	// NextAttemptAt is when the reaper next retries a revert_failed action.
	NextAttemptAt time.Time
	Attempts      int
	// Op is the driver operation outstanding on this action, with who asked
	// for it and by when it must have an outcome. It is persisted before the
	// driver is called, so a restart knows which calls were interrupted.
	Op, OpActor, OpReason string
	OpDeadline            time.Time
	// Repeats counts detections folded into this action.
	Repeats         int
	LastDetectionID string
	LastSeenAt      time.Time
}

// Action returns the wire form. Its in_flight is the outstanding operation
// (Op), so that an action whose revert is under way can be told from one
// nobody is lifting; Op is the one place it is kept.
func (r Record) Action() events.EnforcementAction {
	a := r.EnforcementAction
	a.InFlight = r.Op
	return a
}

// ErrNotFound is returned for an unknown action id.
var ErrNotFound = errors.New("action not found")

// ConflictError is returned when an action is not in a state the requested
// transition may start from. Current is the action as it is.
type ConflictError struct {
	Current Record
	Msg     string
}

func (e *ConflictError) Error() string { return e.Msg }

func conflict(r *Record, format string, args ...any) error {
	return &ConflictError{Current: *r, Msg: fmt.Sprintf(format, args...)}
}

var (
	auditWriteFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "audit_write_failures_total",
		Help:      "Transitions that could not be persisted together with their audit record (the transition did not happen).",
	})
	storeErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "store_errors_total",
		Help:      "Durable store operations that failed, by operation.",
	}, []string{"operation"})
)

func init() {
	prometheus.MustRegister(auditWriteFailures, storeErrors)
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
	seq               INTEGER PRIMARY KEY AUTOINCREMENT,
	id                TEXT    NOT NULL UNIQUE,
	state             TEXT    NOT NULL,
	action_type       TEXT    NOT NULL,
	detection_id      TEXT    NOT NULL,
	target_mac        TEXT    NOT NULL,
	dedupe_key        TEXT    NOT NULL,
	updated_at        INTEGER NOT NULL,
	pending_until     INTEGER NOT NULL DEFAULT 0,
	expires_at        INTEGER NOT NULL DEFAULT 0,
	next_attempt_at   INTEGER NOT NULL DEFAULT 0,
	attempts          INTEGER NOT NULL DEFAULT 0,
	op                TEXT    NOT NULL DEFAULT '',
	op_actor          TEXT    NOT NULL DEFAULT '',
	op_reason         TEXT    NOT NULL DEFAULT '',
	op_deadline       INTEGER NOT NULL DEFAULT 0,
	repeats           INTEGER NOT NULL DEFAULT 0,
	last_detection_id TEXT    NOT NULL DEFAULT '',
	last_seen_at      INTEGER NOT NULL DEFAULT 0,
	body              TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS actions_state     ON actions(state, seq);
CREATE INDEX IF NOT EXISTS actions_ended     ON actions(state, updated_at);
CREATE INDEX IF NOT EXISTS actions_detection ON actions(detection_id);
CREATE INDEX IF NOT EXISTS actions_last_det  ON actions(last_detection_id);
CREATE INDEX IF NOT EXISTS actions_dedupe    ON actions(dedupe_key, state);
CREATE INDEX IF NOT EXISTS actions_target    ON actions(action_type, target_mac, state);

CREATE TABLE IF NOT EXISTS evaluations (
	detection_id TEXT PRIMARY KEY,
	digest       BLOB    NOT NULL,
	decision     TEXT    NOT NULL,
	action_id    TEXT    NOT NULL,
	evaluated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS evaluations_at ON evaluations(evaluated_at);

CREATE TABLE IF NOT EXISTS audit_log (
	seq               INTEGER PRIMARY KEY AUTOINCREMENT,
	at                INTEGER NOT NULL,
	action_id         TEXT    NOT NULL,
	from_state        TEXT    NOT NULL,
	to_state          TEXT    NOT NULL,
	actor             TEXT    NOT NULL,
	reason            TEXT    NOT NULL,
	detection_id      TEXT    NOT NULL,
	detection_summary TEXT    NOT NULL,
	target_mac        TEXT    NOT NULL,
	target_ip         TEXT    NOT NULL,
	action_type       TEXT    NOT NULL,
	blocked_domain    TEXT    NOT NULL,
	policy_rule       TEXT    NOT NULL,
	forwarded         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS audit_outbox ON audit_log(forwarded, seq);
CREATE INDEX IF NOT EXISTS audit_action ON audit_log(action_id, seq);

CREATE TABLE IF NOT EXISTS sinkhole_rules (
	rule     TEXT PRIMARY KEY,
	owned    INTEGER NOT NULL,
	added_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sinkhole_refs (
	action_id TEXT PRIMARY KEY,
	rule      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sinkhole_refs_rule ON sinkhole_refs(rule);

CREATE TABLE IF NOT EXISTS agent_commands (
	seq         INTEGER PRIMARY KEY AUTOINCREMENT,
	id          TEXT    NOT NULL UNIQUE,
	type        TEXT    NOT NULL,
	action_id   TEXT    NOT NULL,
	mac         TEXT    NOT NULL,
	ip          TEXT    NOT NULL,
	ttl_seconds INTEGER NOT NULL,
	state       TEXT    NOT NULL,
	created_at  INTEGER NOT NULL,
	sent_at     INTEGER NOT NULL DEFAULT 0,
	finished_at INTEGER NOT NULL DEFAULT 0,
	error       TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS agent_commands_state ON agent_commands(state, seq);
`

// Open opens (creating if needed) the database at path.
//
// The database is the only record of what this service has enforced, so it
// is written with synchronous=FULL: a transition the API reported must
// survive a power cut, not only a crash.
func Open(path string, opts Options) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create data directory %s: %w", dir, err)
		}
	}
	dsn := "file:" + path +
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	// One connection: every read-check-write below is then serialised by
	// the pool, which is all the write rate here needs.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	s := &Store{db: db, opts: opts}
	if err := s.init(); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.opts.MaxTerminal <= 0 {
		s.opts.MaxTerminal = 10000
	}
	if s.opts.MaxPending <= 0 {
		s.opts.MaxPending = 500
	}
	if s.opts.PendingTTL <= 0 {
		s.opts.PendingTTL = 24 * time.Hour
	}
	if s.opts.IDPrefix == "" {
		s.opts.IDPrefix = "ACT-" + s.instance
	}
	if s.opts.Now == nil {
		s.opts.Now = time.Now
	}
	return s, nil
}

func (s *Store) init() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than this build (%d); refusing to guess",
			version, schemaVersion)
	}
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("set schema version: %w", err)
	}
	err := s.db.QueryRow("SELECT value FROM meta WHERE key = 'instance'").Scan(&s.instance)
	if errors.Is(err, sql.ErrNoRows) {
		b := make([]byte, 4)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		s.instance = hex.EncodeToString(b)
		_, err = s.db.Exec("INSERT INTO meta (key, value) VALUES ('instance', ?)", s.instance)
	}
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Instance is the random id this database was created with.
func (s *Store) Instance() string { return s.instance }

// PendingTTL is how long a pending action waits for a human.
func (s *Store) PendingTTL() time.Duration { return s.opts.PendingTTL }

func (s *Store) now() time.Time { return s.opts.Now().UTC().Truncate(time.Millisecond) }

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func timeOrZero(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

const recordCols = `seq, body, dedupe_key, updated_at, pending_until, next_attempt_at, attempts,
	op, op_actor, op_reason, op_deadline, repeats, last_detection_id, last_seen_at`

type scanner interface{ Scan(dest ...any) error }

func scanRecord(sc scanner) (Record, error) {
	var r Record
	var body string
	var updated, pending, next, deadline, seen int64
	if err := sc.Scan(&r.Seq, &body, &r.DedupeKey, &updated, &pending, &next, &r.Attempts,
		&r.Op, &r.OpActor, &r.OpReason, &deadline, &r.Repeats, &r.LastDetectionID, &seen); err != nil {
		return r, err
	}
	if err := json.Unmarshal([]byte(body), &r.EnforcementAction); err != nil {
		return r, fmt.Errorf("decode action %d: %w", r.Seq, err)
	}
	r.UpdatedAt, r.PendingUntil, r.NextAttemptAt = fromMS(updated), fromMS(pending), fromMS(next)
	r.OpDeadline, r.LastSeenAt = fromMS(deadline), fromMS(seen)
	return r, nil
}

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

func queryRecords(q querier, where string, args ...any) ([]Record, error) {
	rows, err := q.Query("SELECT "+recordCols+" FROM actions WHERE "+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func getRecord(q querier, id string) (Record, error) {
	r, err := scanRecord(q.QueryRow("SELECT "+recordCols+" FROM actions WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// put writes r, inserting it (and assigning its id) when it has no seq yet.
func (s *Store) put(tx *sql.Tx, r *Record, now time.Time) error {
	r.UpdatedAt = now
	if r.Seq == 0 {
		res, err := tx.Exec(`INSERT INTO actions (id, state, action_type, detection_id, target_mac,
			dedupe_key, updated_at, body) VALUES ('', '', '', '', '', '', 0, '{}')`)
		if err != nil {
			return err
		}
		if r.Seq, err = res.LastInsertId(); err != nil {
			return err
		}
		r.ID = fmt.Sprintf("%s-%d", s.opts.IDPrefix, r.Seq)
	}
	// The body never carries in_flight: the op column is its source, and a
	// copy in the body could only go stale.
	stored := r.EnforcementAction
	stored.InFlight = ""
	body, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`UPDATE actions SET id = ?, state = ?, action_type = ?, detection_id = ?,
		target_mac = ?, dedupe_key = ?, updated_at = ?, pending_until = ?, expires_at = ?,
		next_attempt_at = ?, attempts = ?, op = ?, op_actor = ?, op_reason = ?, op_deadline = ?,
		repeats = ?, last_detection_id = ?, last_seen_at = ?, body = ? WHERE seq = ?`,
		r.ID, r.State, r.ActionType, r.DetectionID, strings.ToLower(r.TargetMAC), r.DedupeKey,
		ms(r.UpdatedAt), ms(r.PendingUntil), ms(timeOrZero(r.ExpiresAt)), ms(r.NextAttemptAt),
		r.Attempts, r.Op, r.OpActor, r.OpReason, ms(r.OpDeadline), r.Repeats, r.LastDetectionID,
		ms(r.LastSeenAt), string(body), r.Seq)
	return err
}

func insertAudit(tx *sql.Tx, at time.Time, r *Record, from, actor, reason string) error {
	_, err := tx.Exec(`INSERT INTO audit_log (at, action_id, from_state, to_state, actor, reason,
		detection_id, detection_summary, target_mac, target_ip, action_type, blocked_domain,
		policy_rule) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ms(at), r.ID, from, r.State, actor, reason, r.DetectionID, r.DetectionSummary,
		r.TargetMAC, r.TargetIP, r.ActionType, r.BlockedDomain, r.PolicyRule)
	return err
}

// Transition is the audit record of a change: who caused it and why.
type Transition struct {
	Actor  string
	Reason string
}

// mutate loads the action, lets fn change it and stores it, together with
// the audit entry fn returns, in one transaction: a transition is never
// visible without its audit record, and vice versa. fn returning nil
// records no audit entry (a change of bookkeeping, not of state).
func (s *Store) mutate(op, id string, fn func(r *Record, now time.Time) (*Transition, error)) (Record, error) {
	now := s.now()
	tx, err := s.db.Begin()
	if err != nil {
		storeErrors.WithLabelValues(op).Inc()
		return Record{}, err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	r, err := getRecord(tx, id)
	if err != nil {
		return r, err
	}
	before := r.State
	tr, err := fn(&r, now)
	if err != nil {
		return r, err
	}
	if err := s.put(tx, &r, now); err != nil {
		return s.failed(op, tr, err)
	}
	if tr != nil {
		if err := insertAudit(tx, now, &r, before, tr.Actor, tr.Reason); err != nil {
			return s.failed(op, tr, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return s.failed(op, tr, err)
	}
	return r, nil
}

func (s *Store) failed(op string, tr *Transition, err error) (Record, error) {
	storeErrors.WithLabelValues(op).Inc()
	if tr != nil {
		auditWriteFailures.Inc()
	}
	return Record{}, fmt.Errorf("persist %s: %w", op, err)
}

// Get returns one action.
func (s *Store) Get(id string) (Record, error) { return getRecord(s.db, id) }

// listLimit bounds the lists that can hold finished actions.
const listLimit = 1000

var (
	enforcedList = quoteStates(events.StateActive, events.StateRevertFailed)
	failedList   = quoteStates(events.StateApplyFailed, events.StateRevertFailed)
	terminalList = quoteStates(events.StateReverted, events.StateRejected, events.StateExpired,
		events.StateApplyFailed)
	openList = quoteStates(events.StatePending, events.StateApproved, events.StateActive,
		events.StateRevertFailed)
	inForceList = quoteStates(events.StateApproved, events.StateActive, events.StateRevertFailed)
)

func quoteStates(states ...string) string {
	q := make([]string, len(states))
	for i, s := range states {
		q[i] = "'" + s + "'"
	}
	return "(" + strings.Join(q, ", ") + ")"
}

// ListPending returns the approval queue, oldest first.
func (s *Store) ListPending() ([]Record, error) {
	return queryRecords(s.db, "state = 'pending' ORDER BY seq ASC")
}

// ListEnforced returns everything still enforced (active and
// revert_failed), newest first. It is never truncated: hiding an
// enforcement is the one thing this list must not do.
func (s *Store) ListEnforced() ([]Record, error) {
	return queryRecords(s.db, "state IN "+enforcedList+" ORDER BY seq DESC")
}

// ListFailed returns apply_failed and revert_failed actions, newest first.
func (s *Store) ListFailed() ([]Record, error) {
	return queryRecords(s.db, "state IN "+failedList+" ORDER BY seq DESC LIMIT ?", listLimit)
}

// ListHistory returns finished actions, most recently finished first.
func (s *Store) ListHistory(limit int) ([]Record, error) {
	return queryRecords(s.db, "state IN "+terminalList+" ORDER BY updated_at DESC, seq DESC LIMIT ?", limit)
}

// ListStates returns the actions in the given states, oldest first.
func (s *Store) ListStates(states ...string) ([]Record, error) {
	if len(states) == 0 {
		return []Record{}, nil
	}
	return queryRecords(s.db, "state IN "+quoteStates(states...)+" ORDER BY seq ASC")
}

// InForce returns the actions of a type that are, or may be, enforced:
// approved (an apply outstanding), active and revert_failed.
func (s *Store) InForce(actionType string) ([]Record, error) {
	return queryRecords(s.db, "action_type = ? AND state IN "+inForceList+" ORDER BY seq ASC", actionType)
}

// EnforcedOn returns an action of the given type that is, or may be, in
// force on the device with this MAC.
func (s *Store) EnforcedOn(actionType, mac string) (Record, bool, error) {
	recs, err := queryRecords(s.db, "action_type = ? AND target_mac = ? AND state IN "+inForceList+
		" ORDER BY seq ASC LIMIT 1", actionType, strings.ToLower(mac))
	if err != nil || len(recs) == 0 {
		return Record{}, false, err
	}
	return recs[0], true, nil
}

// WithOp returns the actions that have a driver operation outstanding.
func (s *Store) WithOp() ([]Record, error) {
	return queryRecords(s.db, "op != '' ORDER BY seq ASC")
}

// Due is what the reaper owns at a given moment.
type Due struct {
	// Expire: pending actions past their deadline.
	Expire []Record
	// Revert: active actions past their TTL, and revert_failed actions
	// whose next retry is due.
	Revert []Record
	// Overdue: actions whose outstanding operation passed its deadline.
	Overdue []Record
}

// Due returns what the reaper must act on at now.
func (s *Store) Due(now time.Time) (Due, error) {
	var d Due
	var err error
	t := ms(now)
	if d.Expire, err = queryRecords(s.db, "state = 'pending' AND pending_until > 0 AND pending_until <= ? ORDER BY seq", t); err != nil {
		return d, err
	}
	if d.Revert, err = queryRecords(s.db, `op = '' AND (
		(state = 'active' AND expires_at > 0 AND expires_at <= ?) OR
		(state = 'revert_failed' AND next_attempt_at <= ?)) ORDER BY seq`, t, t); err != nil {
		return d, err
	}
	d.Overdue, err = queryRecords(s.db, "op != '' AND op_deadline > 0 AND op_deadline <= ? ORDER BY seq", t)
	return d, err
}

// Counts returns the number of actions per state.
func (s *Store) Counts() (map[string]int, error) {
	rows, err := s.db.Query("SELECT state, COUNT(*) FROM actions GROUP BY state")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var st string
		var n int
		if err := rows.Scan(&st, &n); err != nil {
			return nil, err
		}
		out[st] = n
	}
	return out, rows.Err()
}

// PruneOptions says what Prune may forget.
type PruneOptions struct {
	EvaluationRetention time.Duration
	MaxEvaluations      int
	AuditRetention      time.Duration
	// AuditForwarding is true when a sink is configured: then an entry is
	// only forgotten once it has been forwarded.
	AuditForwarding  bool
	CommandRetention time.Duration
}

// Prune drops what is no longer needed: finished actions beyond
// MaxTerminal (oldest first), evaluations past retention, old audit
// entries and finished agent commands. Nothing that is or may be enforced
// is ever dropped.
func (s *Store) Prune(now time.Time, o PruneOptions) error {
	var n int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM actions WHERE state IN " + terminalList).Scan(&n); err != nil {
		return err
	}
	type stmt struct {
		q    string
		args []any
	}
	var stmts []stmt
	add := func(q string, args ...any) { stmts = append(stmts, stmt{q, args}) }
	if over := n - s.opts.MaxTerminal; over > 0 {
		add("DELETE FROM actions WHERE seq IN (SELECT seq FROM actions WHERE state IN "+terminalList+
			" ORDER BY seq ASC LIMIT ?)", over)
	}
	if o.EvaluationRetention > 0 {
		add("DELETE FROM evaluations WHERE evaluated_at < ?", ms(now.Add(-o.EvaluationRetention)))
	}
	if o.MaxEvaluations > 0 {
		add(`DELETE FROM evaluations WHERE detection_id IN (SELECT detection_id FROM evaluations
			ORDER BY evaluated_at DESC LIMIT -1 OFFSET ?)`, o.MaxEvaluations)
	}
	if o.AuditRetention > 0 {
		add("DELETE FROM audit_log WHERE at < ? AND (forwarded = 1 OR ? = 0)",
			ms(now.Add(-o.AuditRetention)), boolInt(o.AuditForwarding))
	}
	if o.CommandRetention > 0 {
		add("DELETE FROM agent_commands WHERE state IN ('done', 'failed', 'cancelled') AND finished_at < ?",
			ms(now.Add(-o.CommandRetention)))
	}
	for _, st := range stmts {
		if _, err := s.db.Exec(st.q, st.args...); err != nil {
			storeErrors.WithLabelValues("prune").Inc()
			return err
		}
	}
	return nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
