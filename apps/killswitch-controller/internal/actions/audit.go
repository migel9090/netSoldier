package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// AuditEntry is one transition: what changed, who caused it, and what it
// was about. It is written in the same transaction as the transition, so
// the local log is complete by construction.
type AuditEntry struct {
	Seq              int64     `json:"seq"`
	Timestamp        time.Time `json:"timestamp"`
	ActionID         string    `json:"action_id"`
	FromState        string    `json:"from_state"`
	ToState          string    `json:"to_state"`
	Actor            string    `json:"actor"`
	Reason           string    `json:"reason"`
	DetectionID      string    `json:"detection_id"`
	DetectionSummary string    `json:"detection_summary"`
	TargetMAC        string    `json:"target_mac"`
	TargetIP         string    `json:"target_ip"`
	ActionType       string    `json:"action_type"`
	BlockedDomain    string    `json:"blocked_domain"`
	PolicyRule       string    `json:"policy_rule"`
}

const auditCols = `seq, at, action_id, from_state, to_state, actor, reason, detection_id,
	detection_summary, target_mac, target_ip, action_type, blocked_domain, policy_rule`

func (s *Store) queryAudit(where string, args ...any) ([]AuditEntry, error) {
	rows, err := s.db.Query("SELECT "+auditCols+" FROM audit_log WHERE "+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		var at int64
		if err := rows.Scan(&e.Seq, &at, &e.ActionID, &e.FromState, &e.ToState, &e.Actor, &e.Reason,
			&e.DetectionID, &e.DetectionSummary, &e.TargetMAC, &e.TargetIP, &e.ActionType,
			&e.BlockedDomain, &e.PolicyRule); err != nil {
			return nil, err
		}
		e.Timestamp = fromMS(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditQuery selects entries of the local audit log.
type AuditQuery struct {
	Limit int
	// Before returns entries older than this sequence number (0: from the
	// newest), for paging.
	Before int64
	// ActionID restricts the log to one action.
	ActionID string
}

// Audit returns the local audit log, newest first.
func (s *Store) Audit(q AuditQuery) ([]AuditEntry, error) {
	where, args := []string{"1 = 1"}, []any{}
	if q.Before > 0 {
		where, args = append(where, "seq < ?"), append(args, q.Before)
	}
	if q.ActionID != "" {
		where, args = append(where, "action_id = ?"), append(args, q.ActionID)
	}
	if q.Limit <= 0 {
		q.Limit = 100
	}
	return s.queryAudit(strings.Join(where, " AND ")+" ORDER BY seq DESC LIMIT ?", append(args, q.Limit)...)
}

// Outbox returns entries not yet accepted by the sink, oldest first.
func (s *Store) Outbox(limit int) ([]AuditEntry, error) {
	return s.queryAudit("forwarded = 0 ORDER BY seq ASC LIMIT ?", limit)
}

// MarkForwarded records that every entry up to seq was accepted. Entries
// are committed in sequence order (one writer), so nothing below seq can
// still be on its way.
func (s *Store) MarkForwarded(seq int64) error {
	_, err := s.db.Exec("UPDATE audit_log SET forwarded = 1 WHERE forwarded = 0 AND seq <= ?", seq)
	if err != nil {
		storeErrors.WithLabelValues("audit_mark").Inc()
	}
	return err
}

// OutboxStats returns how many entries wait for the sink and when the
// oldest of them was written.
func (s *Store) OutboxStats() (int, time.Time, error) {
	var n int
	var oldest int64
	err := s.db.QueryRow("SELECT COUNT(*), COALESCE(MIN(at), 0) FROM audit_log WHERE forwarded = 0").Scan(&n, &oldest)
	return n, fromMS(oldest), err
}

// Sink receives audit entries. Send must not return nil unless every entry
// was accepted.
type Sink interface {
	Send(ctx context.Context, entries []AuditEntry) error
}

// ClickHouseSink inserts audit entries into netsoldier.audit_log over the
// HTTP interface.
//
// Credentials go in the X-ClickHouse-User/Key headers rather than the URL,
// so they stay out of ClickHouse's query_log and any proxy's access log.
// The account should hold INSERT on this table only.
type ClickHouseSink struct {
	baseURL  string
	database string
	user     string
	password string
	http     *http.Client
}

// NewClickHouseSink returns a sink for the given server.
func NewClickHouseSink(baseURL, database, user, password string) *ClickHouseSink {
	return &ClickHouseSink{
		baseURL:  strings.TrimRight(baseURL, "/"),
		database: database,
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

// chTime is the DateTime64(3) text form migration 023 expects, in UTC.
const chTime = "2006-01-02 15:04:05.000"

// Send inserts the entries as one JSONEachRow batch.
//
// The table has fewer columns than an entry (no blocked_domain, policy_rule
// or detection_summary until a migration adds them), so unknown fields are
// skipped rather than refused; once the columns exist they fill without a
// change here. The deduplication token makes a retried batch idempotent on
// tables that enable insert deduplication.
func (c *ClickHouseSink) Send(ctx context.Context, entries []AuditEntry) error {
	if len(entries) == 0 {
		return nil
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, e := range entries {
		row := map[string]any{
			"timestamp":         e.Timestamp.UTC().Format(chTime),
			"action_id":         e.ActionID,
			"from_state":        e.FromState,
			"to_state":          e.ToState,
			"actor":             e.Actor,
			"reason":            e.Reason,
			"detection_id":      e.DetectionID,
			"target_mac":        e.TargetMAC,
			"target_ip":         e.TargetIP,
			"action_type":       e.ActionType,
			"blocked_domain":    e.BlockedDomain,
			"policy_rule":       e.PolicyRule,
			"detection_summary": e.DetectionSummary,
		}
		if err := enc.Encode(row); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}
	q := url.Values{}
	q.Set("database", c.database)
	q.Set("query", "INSERT INTO audit_log FORMAT JSONEachRow")
	q.Set("input_format_skip_unknown_fields", "1")
	q.Set("insert_deduplication_token", fmt.Sprintf("killswitch-%d-%d", entries[0].Seq, entries[len(entries)-1].Seq))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/?"+q.Encode(), &body)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
		req.Header.Set("X-ClickHouse-Key", c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

var (
	auditForwarded = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "audit_forwarded_total",
		Help:      "Audit entries accepted by ClickHouse.",
	})
	auditForwardFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "audit_forward_failures_total",
		Help:      "Failed attempts to forward audit entries to ClickHouse (each is retried).",
	})
	auditOutboxPending = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "audit_outbox_pending",
		Help:      "Audit entries recorded locally and not yet accepted by ClickHouse.",
	})
	auditOutboxOldest = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "audit_outbox_oldest_age_seconds",
		Help:      "Age of the oldest audit entry not yet accepted by ClickHouse (0 when none).",
	})
)

func init() {
	prometheus.MustRegister(auditForwarded, auditForwardFailures, auditOutboxPending, auditOutboxOldest)
}

// Forwarder drains the audit outbox into a sink, in order, until every
// entry is accepted. A failure is retried with backoff; entries are never
// dropped for being hard to deliver.
type Forwarder struct {
	Store      *Store
	Sink       Sink
	Interval   time.Duration // between passes when idle (default 2s)
	MaxBackoff time.Duration // ceiling of the retry backoff (default 5m)
	Batch      int           // entries per insert (default 500)
}

// Run forwards until ctx is done.
func (f *Forwarder) Run(ctx context.Context) {
	interval, maxBackoff := f.Interval, f.MaxBackoff
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if maxBackoff <= 0 {
		maxBackoff = 5 * time.Minute
	}
	wait := time.Duration(0)
	backoff := interval
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		_, err := f.Flush(ctx)
		if err != nil {
			slog.Error("audit forwarding failed; entries stay in the local outbox and will be retried",
				"error", err, "retry_in", backoff)
			wait, backoff = backoff, min(2*backoff, maxBackoff)
			continue
		}
		wait, backoff = interval, interval
	}
}

// Flush forwards everything currently in the outbox.
func (f *Forwarder) Flush(ctx context.Context) (int, error) {
	batch := f.Batch
	if batch <= 0 {
		batch = 500
	}
	sent := 0
	defer f.updateGauges()
	for {
		entries, err := f.Store.Outbox(batch)
		if err != nil || len(entries) == 0 {
			return sent, err
		}
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = f.Sink.Send(sctx, entries)
		cancel()
		if err != nil {
			auditForwardFailures.Inc()
			return sent, err
		}
		if err := f.Store.MarkForwarded(entries[len(entries)-1].Seq); err != nil {
			return sent, err
		}
		sent += len(entries)
		auditForwarded.Add(float64(len(entries)))
		if len(entries) < batch {
			return sent, nil
		}
	}
}

func (f *Forwarder) updateGauges() {
	n, oldest, err := f.Store.OutboxStats()
	if err != nil {
		return
	}
	auditOutboxPending.Set(float64(n))
	if n == 0 || oldest.IsZero() {
		auditOutboxOldest.Set(0)
		return
	}
	auditOutboxOldest.Set(time.Since(oldest).Seconds())
}
