package feedback

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
)

// TestClickHouseFeedbackRoundTrip runs against a real ClickHouse with
// authentication on, as deployed. Skipped unless configured:
//
//	DETECTION_ENGINE_TEST_CLICKHOUSE_URL       e.g. http://172.17.0.5:8123
//	DETECTION_ENGINE_TEST_CLICKHOUSE_USER      a user that may SELECT/INSERT
//	DETECTION_ENGINE_TEST_CLICKHOUSE_PASSWORD  netsoldier.detection_feedback
//
// The table must exist as migrations 017 and 022 create it, plus the
// signal_class column:
//
//	ALTER TABLE netsoldier.detection_feedback
//	    ADD COLUMN IF NOT EXISTS signal_class LowCardinality(String) AFTER client_ip,
//	    MODIFY ORDER BY (matched_ioc, client_ip, timestamp, signal_class);
func TestClickHouseFeedbackRoundTrip(t *testing.T) {
	url := os.Getenv("DETECTION_ENGINE_TEST_CLICKHOUSE_URL")
	if url == "" {
		t.Skip("DETECTION_ENGINE_TEST_CLICKHOUSE_URL not set")
	}
	ctx := context.Background()
	authed, err := clickhouse.New(clickhouse.Config{URL: url, Database: "netsoldier",
		User:     os.Getenv("DETECTION_ENGINE_TEST_CLICKHOUSE_USER"),
		Password: os.Getenv("DETECTION_ENGINE_TEST_CLICKHOUSE_PASSWORD")})
	if err != nil {
		t.Fatal(err)
	}
	bare, _ := clickhouse.New(clickhouse.Config{URL: url, Database: "netsoldier"})

	run := time.Now().UnixNano()
	c2 := fmt.Sprintf("c2-%d.real-threat.example", run)
	vendor := fmt.Sprintf("telemetry-%d.vendor.example", run)
	forged := fmt.Sprintf("forged-%d.example", run)

	// As shipped before: no credentials. The verdict applies in memory, the
	// write is refused, and the caller is told it did not persist.
	s0 := New(NewCHSink(bare))
	if persisted, err := s0.record(fp(c2+".bare", "", ioc)); err != nil || persisted {
		t.Errorf("unauthenticated write: persisted=%v err=%v, want a reported failure", persisted, err)
	}
	if _, err := LoadInto(ctx, bare, New(nil)); err == nil {
		t.Error("an unauthenticated replay must fail, not come back empty")
	}

	// With credentials. The false positive and the "confirmed" land in the
	// same second; replay must still end on "confirmed".
	s1 := New(NewCHSink(authed))
	same := time.Now().UTC().Truncate(time.Second)
	s1.now = func() time.Time { return same }
	fake := fp(c2, "", ioc)
	fake.Timestamp = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC) // ignored by Record
	mustRecord(t, s1, fake)
	mustRecord(t, s1, confirmed(c2, "", ioc))
	// Two classes for one indicator in the same second must both survive.
	mustRecord(t, s1, fp(vendor, "192.168.1.50", detection.SignalBeacon))
	mustRecord(t, s1, fp(vendor, "192.168.1.50", detection.SignalTLS))
	// A row dated 2099, as the old client-supplied timestamps could write.
	if err := authed.Insert(ctx, "detection_feedback", map[string]any{
		"timestamp": time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), "matched_ioc": forged,
		"signal_class": ioc, "verdict": VerdictFalsePositive, "analyst": "mallory",
	}); err != nil {
		t.Fatal(err)
	}
	// Merges must not change the outcome either.
	_ = authed.QueryJSONEachRow(ctx, "OPTIMIZE TABLE detection_feedback FINAL", func(json.RawMessage) error { return nil })

	// Restart.
	s2 := New(nil)
	n, err := LoadInto(ctx, authed, s2)
	if err != nil {
		t.Fatalf("replay with credentials: %v", err)
	}
	t.Logf("replayed %d verdicts", n)
	if s2.Suppressed(alertOf(c2, "192.168.1.77", ioc)) {
		t.Error("after restart the confirmed C2 indicator is suppressed again")
	}
	if !s2.Suppressed(alertOf(vendor, "192.168.1.50", detection.SignalBeacon)) ||
		!s2.Suppressed(alertOf(vendor, "192.168.1.50", detection.SignalTLS)) {
		t.Error("verdicts for two classes of one indicator did not both survive")
	}
	if s2.Suppressed(alertOf(forged, "192.168.1.77", ioc)) {
		t.Error("a verdict dated 2099 was replayed")
	}
	for _, v := range s2.Active() {
		if v.MatchedIoC == vendor && !v.Timestamp.Equal(same) {
			t.Errorf("replayed timestamp %v, want the server's %v", v.Timestamp, same)
		}
	}
}
