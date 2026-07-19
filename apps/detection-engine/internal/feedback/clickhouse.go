package feedback

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
)

// CHSink persists verdicts to netsoldier.detection_feedback over the HTTP
// interface, so suppressions survive restarts (loaded via LoadInto).
type CHSink struct {
	baseURL  string
	database string
	http     *http.Client
}

func NewCHSink(baseURL, database string) *CHSink {
	return &CHSink{
		baseURL:  baseURL,
		database: database,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (s *CHSink) Write(v Verdict) error {
	row, err := json.Marshal(map[string]any{
		"timestamp":   v.Timestamp.Unix(),
		"alert_id":    v.AlertID,
		"matched_ioc": v.MatchedIoC,
		"client_ip":   v.ClientIP,
		"verdict":     v.Verdict,
		"reason":      v.Reason,
		"analyst":     v.Analyst,
	})
	if err != nil {
		return fmt.Errorf("marshal verdict: %w", err)
	}
	u := fmt.Sprintf("%s/?database=%s&query=%s", s.baseURL,
		url.QueryEscape(s.database),
		url.QueryEscape("INSERT INTO detection_feedback FORMAT JSONEachRow"))
	resp, err := s.http.Post(u, "application/json", bytes.NewReader(row))
	if err != nil {
		return fmt.Errorf("insert feedback: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, body)
	}
	return nil
}

// LoadInto replays the latest verdict per (matched_ioc, client_ip) into the
// store so suppressions are rebuilt after a restart. ReplacingMergeTree
// keeps only the newest verdict per key via argMax on timestamp.
func LoadInto(ctx context.Context, ch *ingest.CHClient, store *Store) (int, error) {
	q := `SELECT matched_ioc, client_ip,
  argMax(verdict, timestamp) AS verdict,
  argMax(reason, timestamp) AS reason,
  argMax(analyst, timestamp) AS analyst,
  toUnixTimestamp(max(timestamp)) AS ts
FROM detection_feedback
GROUP BY matched_ioc, client_ip FORMAT JSONEachRow`

	var loaded int
	err := ch.QueryJSONEachRow(ctx, q, func(raw json.RawMessage) error {
		var r struct {
			MatchedIoC string      `json:"matched_ioc"`
			ClientIP   string      `json:"client_ip"`
			Verdict    string      `json:"verdict"`
			Reason     string      `json:"reason"`
			Analyst    string      `json:"analyst"`
			TS         json.Number `json:"ts"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil // skip malformed rows, keep loading
		}
		ts, _ := r.TS.Int64()
		v := Verdict{
			MatchedIoC: r.MatchedIoC,
			ClientIP:   r.ClientIP,
			Verdict:    r.Verdict,
			Reason:     r.Reason,
			Analyst:    r.Analyst,
			Timestamp:  time.Unix(ts, 0).UTC(),
		}
		// Record without re-persisting: it is already in ClickHouse.
		store.applyLoaded(v)
		loaded++
		return nil
	})
	return loaded, err
}
