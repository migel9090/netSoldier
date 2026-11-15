package feedback

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"
)

// feedbackTable is netsoldier.detection_feedback (migrations 017, 022; the
// signal_class column needs the migration that adds it).
const feedbackTable = "detection_feedback"

// clockSkew is how far in the future a stored verdict may be dated and
// still be believed. Verdicts are stamped by this service, so anything
// later was written by something else (or under the old client-supplied
// timestamps) and is ignored on replay.
const clockSkew = 5 * time.Minute

// Inserter writes rows to ClickHouse (*clickhouse.Client).
type Inserter interface {
	Insert(ctx context.Context, table string, rows ...any) error
}

// Querier runs a JSONEachRow SELECT (*clickhouse.Client).
type Querier interface {
	QueryJSONEachRow(ctx context.Context, query string, fn func(json.RawMessage) error) error
}

// CHSink persists verdicts to detection_feedback so suppressions survive
// restarts (replayed by LoadInto).
type CHSink struct {
	ch Inserter
}

func NewCHSink(ch Inserter) *CHSink { return &CHSink{ch: ch} }

// Write inserts one verdict. A failure is already logged and counted by
// the client; the caller only learns that the verdict is not durable.
func (s *CHSink) Write(v Verdict) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return s.ch.Insert(ctx, feedbackTable, map[string]any{
		"timestamp":    v.Timestamp.Unix(),
		"alert_id":     v.AlertID,
		"matched_ioc":  v.MatchedIoC,
		"client_ip":    v.ClientIP,
		"signal_class": v.SignalClass,
		"verdict":      v.Verdict,
		"reason":       v.Reason,
		"analyst":      v.Analyst,
	})
}

// LoadInto rebuilds the active suppressions after a restart by replaying
// the verdicts still inside the TTL in the order this service recorded
// them, so the last word wins — and within one second a "confirmed" counts
// as the later one: an ambiguous tie must not keep a detection silenced.
//
// The timestamp is only ever the server's (Record assigns it). A row dated
// in the future therefore did not come from Record and is ignored.
func LoadInto(ctx context.Context, ch Querier, store *Store) (int, error) {
	q := fmt.Sprintf(`SELECT matched_ioc, client_ip, signal_class, verdict, reason, analyst,
  toUnixTimestamp(timestamp) AS ts
FROM %s
WHERE timestamp >= now() - INTERVAL %d SECOND
ORDER BY timestamp ASC, verdict = 'confirmed' ASC
FORMAT JSONEachRow`, feedbackTable, int64(store.TTL()/time.Second))

	horizon := store.now().Add(clockSkew)
	var loaded, future, invalid int
	err := ch.QueryJSONEachRow(ctx, q, func(raw json.RawMessage) error {
		var r struct {
			MatchedIoC  string      `json:"matched_ioc"`
			ClientIP    string      `json:"client_ip"`
			SignalClass string      `json:"signal_class"`
			Verdict     string      `json:"verdict"`
			Reason      string      `json:"reason"`
			Analyst     string      `json:"analyst"`
			TS          json.Number `json:"ts"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			invalid++
			return nil
		}
		sec, err := r.TS.Int64()
		if err != nil {
			invalid++
			return nil
		}
		ts := time.Unix(sec, 0).UTC()
		if ts.After(horizon) {
			future++
			return nil
		}
		if err := store.applyLoaded(Verdict{
			MatchedIoC:  r.MatchedIoC,
			ClientIP:    r.ClientIP,
			SignalClass: r.SignalClass,
			Verdict:     r.Verdict,
			Reason:      r.Reason,
			Analyst:     r.Analyst,
			Timestamp:   ts,
		}); err != nil {
			invalid++
			return nil
		}
		loaded++
		return nil
	})
	if future > 0 {
		slog.Warn("ignored stored verdicts dated in the future; this service never writes those",
			"count", future)
	}
	if invalid > 0 {
		slog.Warn("ignored stored verdicts that are not valid any more (no signal class, oversized fields)",
			"count", invalid)
	}
	return loaded, err
}
