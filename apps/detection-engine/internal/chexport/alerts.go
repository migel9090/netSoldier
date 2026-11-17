// Package chexport copies what detection-engine knows into the ClickHouse
// tables the dashboards and the device pages read: the alert history
// (netsoldier.alerts) and the AdGuard query log it checks
// (netsoldier.dns_queries).
//
// Neither copy is read back. The engine's record of its alerts is the local
// store, and the query log is AdGuard's; ClickHouse holds the history people
// look at. Both copies therefore run beside the detection path and never in
// it: a slow or absent ClickHouse costs a backlog or dropped log rows, which
// are counted, and never a detection. Without ClickHouse (the lite profile)
// neither exists.
package chexport

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

// AlertsTable is netsoldier.alerts (migrations 005, 019, 020, 030).
const AlertsTable = "alerts"

const (
	// alertsCursor names the copy's position (the last copied alert's seq)
	// in the cursor store.
	alertsCursor = "clickhouse_alerts_copy"
	// alertBatch is how many alerts one insert carries.
	alertBatch = 500
	// After the n-th failed insert in a row the copier waits
	// copyBase·2^(n-1), at most copyMax, and then tries the same batch again.
	copyBase = 2 * time.Second
	copyMax  = 5 * time.Minute
	// copyIdle is how often an idle copier looks for new alerts.
	copyIdle = 2 * time.Second
	// insertTimeout bounds one insert.
	insertTimeout = 15 * time.Second
)

var (
	alertsCopied = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "alerts_copied_total",
		Help:      "Alerts copied from the local history to ClickHouse.",
	})
	alertsCopySkipped = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "alerts_copy_skipped_total",
		Help:      "Alerts the local retention removed before they were copied to ClickHouse.",
	})
	alertsCopyBacklog = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "alerts_copy_backlog",
		Help:      "Alerts recorded locally and not yet copied to ClickHouse.",
	})
)

func init() {
	prometheus.MustRegister(alertsCopied, alertsCopySkipped, alertsCopyBacklog)
}

// Inserter writes rows to ClickHouse (*clickhouse.Client). It logs and
// counts its own failures.
type Inserter interface {
	Insert(ctx context.Context, table string, rows ...any) error
}

// AlertHistory is the local alert history (*store.Alerts).
type AlertHistory interface {
	After(seq int64, limit int) ([]store.StoredAlert, error)
	CountAfter(seq int64) (int, error)
}

// CursorStore keeps the copy's position across restarts (*store.Cursors).
type CursorStore interface {
	Load(source string) (position []byte, updated time.Time, ok bool, err error)
	Save(source string, position []byte) error
}

// AlertCopier copies the local alert history to ClickHouse in the order it
// was recorded, each alert once it is in the history, retrying a batch until
// ClickHouse takes it. Its position survives a restart, so a ClickHouse
// outage is a backlog, not a hole. An alert the local retention removed
// before it could be copied (a long outage and a flood) is counted in
// alerts_copy_skipped_total.
//
// A batch repeated after a crash between the insert and saving the position
// has the same (timestamp, id) rows, which the table's ReplacingMergeTree
// collapses.
type AlertCopier struct {
	src AlertHistory
	cur CursorStore
	ch  Inserter

	pos      int64
	known    bool // pos came from the cursor store or a copied batch
	failures int

	base, retryCap, idle time.Duration
}

// NewAlertCopier returns a copier; start it with Run.
func NewAlertCopier(src AlertHistory, cur CursorStore, ch Inserter) *AlertCopier {
	return &AlertCopier{src: src, cur: cur, ch: ch, base: copyBase, retryCap: copyMax, idle: copyIdle}
}

// Run copies until ctx ends. What it has not copied is copied after the
// next start.
func (c *AlertCopier) Run(ctx context.Context) {
	c.load()
	for ctx.Err() == nil {
		more, err := c.step(ctx)
		wait := c.idle
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			c.failures++
			wait = backoff(c.base, c.retryCap, c.failures)
			slog.Warn("copying alerts to ClickHouse failed, will retry; they are in the local history meanwhile",
				"after_seq", c.pos, "attempt", c.failures, "retry_in", wait, "error", err)
		case more:
			c.failures = 0
			continue
		default:
			c.failures = 0
		}
		c.refreshBacklog()
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
}

func (c *AlertCopier) load() {
	raw, _, ok, err := c.cur.Load(alertsCursor)
	switch {
	case err != nil:
		slog.Warn("alert copy position unreadable: copying the whole local history again "+
			"(ClickHouse collapses the repeats)", "error", err)
	case ok:
		n, perr := strconv.ParseInt(string(raw), 10, 64)
		if perr != nil || n < 0 {
			slog.Warn("alert copy position malformed: copying the whole local history again", "position", string(raw))
			return
		}
		c.pos, c.known = n, true
	}
}

// step copies one batch and reports whether it was full (more may wait).
func (c *AlertCopier) step(ctx context.Context) (bool, error) {
	batch, err := c.src.After(c.pos, alertBatch)
	if err != nil {
		return false, fmt.Errorf("read local history: %w", err)
	}
	if len(batch) == 0 {
		return false, nil
	}
	rows := make([]any, 0, len(batch))
	prev, skipped := c.pos, int64(0)
	for i, s := range batch {
		if i == 0 && !c.known {
			// Nothing was ever copied: alerts that aged out before this
			// copy existed are not a loss to count.
			prev = s.Seq - 1
		}
		skipped += s.Seq - prev - 1
		prev = s.Seq
		if s.Alert.ID == "" {
			continue // undecodable row, already counted by the store
		}
		rows = append(rows, alertRow(s))
	}
	if len(rows) > 0 {
		ictx, cancel := context.WithTimeout(ctx, insertTimeout)
		err := c.ch.Insert(ictx, AlertsTable, rows...)
		cancel()
		if err != nil {
			return false, err
		}
	}
	alertsCopied.Add(float64(len(rows)))
	if skipped > 0 {
		alertsCopySkipped.Add(float64(skipped))
		slog.Warn("alerts removed by the local retention before they reached ClickHouse",
			"count", skipped, "before_seq", prev)
	}
	c.pos, c.known = prev, true
	if err := c.cur.Save(alertsCursor, []byte(strconv.FormatInt(c.pos, 10))); err != nil {
		// Copied; after a restart the batch is copied again and collapsed.
		slog.Warn("alert copy position not saved", "error", err)
	}
	return len(batch) == alertBatch, nil
}

func (c *AlertCopier) refreshBacklog() {
	if n, err := c.src.CountAfter(c.pos); err == nil {
		alertsCopyBacklog.Set(float64(n))
	}
}

// alertRecord is one row of netsoldier.alerts. Every field is a column:
// the client refuses unknown fields, so a column a migration has not added
// fails the insert instead of vanishing.
type alertRecord struct {
	Timestamp   int64  `json:"timestamp"`   // DateTime: when the engine recorded it
	ObservedAt  string `json:"observed_at"` // DateTime64(3): the input record's time
	ID          string `json:"id"`
	Summary     string `json:"summary"`
	Domain      string `json:"domain"`
	ClientIP    string `json:"client_ip"`
	ClientMAC   string `json:"client_mac"`
	ClientName  string `json:"client_name"`
	QueryType   string `json:"query_type"`
	MatchedIoC  string `json:"matched_ioc"`
	IoCType     string `json:"ioc_type"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	SignalClass string `json:"signal_class"`
	Confidence  uint8  `json:"confidence"`
	TargetType  string `json:"target_type"`
	TargetValue string `json:"target_value"`
	Threat      string `json:"threat"`
	MitreID     string `json:"mitre_id"`
	Suppressed  uint8  `json:"suppressed"`
}

func alertRow(s store.StoredAlert) alertRecord {
	a := s.Alert
	observed := a.Timestamp
	// A sensor's clock can say anything; DateTime64 holds 1900-2299 and the
	// row's own time keeps the partition and the retention honest anyway.
	if observed.IsZero() || observed.Unix() < 0 || observed.Year() > 2200 {
		observed = s.RecordedAt
	}
	r := alertRecord{
		Timestamp:   s.RecordedAt.Unix(),
		ObservedAt:  unixMilliText(observed),
		ID:          a.ID,
		Summary:     a.Summary,
		Domain:      a.Domain,
		ClientIP:    a.ClientIP,
		ClientMAC:   a.ClientMAC,
		ClientName:  a.ClientName,
		QueryType:   a.QueryType,
		MatchedIoC:  a.MatchedIoC,
		IoCType:     a.IoCType,
		Severity:    a.Severity,
		Source:      a.Source,
		SignalClass: a.SignalClass,
		Confidence:  uint8(min(max(a.Confidence, 0), 100)),
		Threat:      a.Threat,
		MitreID:     a.MitreID,
	}
	if a.Target != nil {
		r.TargetType, r.TargetValue = a.Target.Type, a.Target.Value
	}
	if a.Suppressed {
		r.Suppressed = 1
	}
	return r
}

// unixMilliText renders t as "<unix seconds>.<milliseconds>", which a
// DateTime64(3) column parses the same whatever the server's time zone.
func unixMilliText(t time.Time) string {
	ms := t.UnixMilli()
	return fmt.Sprintf("%d.%03d", ms/1000, ms%1000)
}

// backoff is base·2^(n-1), capped.
func backoff(base, limit time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}
