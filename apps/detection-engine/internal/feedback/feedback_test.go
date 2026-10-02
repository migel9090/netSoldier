package feedback

import (
	"testing"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"
)

type recordingSink struct{ writes []Verdict }

func (r *recordingSink) Write(v Verdict) error {
	r.writes = append(r.writes, v)
	return nil
}

func TestRecordValidation(t *testing.T) {
	s := New(nil)
	if err := s.Record(Verdict{Verdict: VerdictFalsePositive}); err == nil {
		t.Error("expected error for missing matched_ioc")
	}
	if err := s.Record(Verdict{MatchedIoC: "x", Verdict: "bogus"}); err == nil {
		t.Error("expected error for invalid verdict")
	}
}

func TestFalsePositiveSuppressesScopedToClient(t *testing.T) {
	s := New(nil)
	if err := s.Record(Verdict{
		MatchedIoC: "cdn.example",
		ClientIP:   "192.168.1.5",
		Verdict:    VerdictFalsePositive, Analyst: "tester"}); err != nil {
		t.Fatal(err)
	}

	same := detection.Alert{MatchedIoC: "cdn.example", ClientIP: "192.168.1.5"}
	other := detection.Alert{MatchedIoC: "cdn.example", ClientIP: "192.168.1.9"}
	if !s.Suppressed(same) {
		t.Error("verdict should suppress the same (ioc, client)")
	}
	if s.Suppressed(other) {
		t.Error("client-scoped verdict must not suppress a different client")
	}
}

func TestIndicatorWideSuppression(t *testing.T) {
	s := New(nil)
	s.Record(Verdict{MatchedIoC: "benign.example", Verdict: VerdictFalsePositive, Analyst: "tester"})
	// empty client scope suppresses the indicator on any client
	if !s.Suppressed(detection.Alert{MatchedIoC: "benign.example", ClientIP: "10.0.0.2"}) {
		t.Error("indicator-wide verdict should suppress any client")
	}
}

func TestMatchIsCaseInsensitive(t *testing.T) {
	s := New(nil)
	s.Record(Verdict{MatchedIoC: "Evil.Example", Verdict: VerdictFalsePositive, Analyst: "tester"})
	if !s.Suppressed(detection.Alert{MatchedIoC: "evil.example"}) {
		t.Error("suppression match should be case-insensitive")
	}
}

func TestConfirmedClearsSuppression(t *testing.T) {
	s := New(nil)
	a := detection.Alert{MatchedIoC: "x", ClientIP: "192.168.1.5"}
	s.Record(Verdict{MatchedIoC: "x", ClientIP: "192.168.1.5", Verdict: VerdictFalsePositive, Analyst: "tester"})
	if !s.Suppressed(a) {
		t.Fatal("should be suppressed after FP")
	}
	s.Record(Verdict{MatchedIoC: "x", ClientIP: "192.168.1.5", Verdict: VerdictConfirmed, Analyst: "tester"})
	if s.Suppressed(a) {
		t.Error("confirmed verdict should clear the suppression")
	}
}

func TestRecordPersistsToSink(t *testing.T) {
	sink := &recordingSink{}
	s := New(sink)
	s.Record(Verdict{MatchedIoC: "x", Verdict: VerdictFalsePositive, Analyst: "tester"})
	if len(sink.writes) != 1 {
		t.Fatalf("expected 1 persisted verdict, got %d", len(sink.writes))
	}
	if sink.writes[0].Timestamp.IsZero() {
		t.Error("timestamp should be stamped on record")
	}
}

func TestActiveSnapshot(t *testing.T) {
	s := New(nil)
	s.Record(Verdict{MatchedIoC: "a", Verdict: VerdictFalsePositive, Analyst: "tester"})
	s.Record(Verdict{MatchedIoC: "b", ClientIP: "10.0.0.1", Verdict: VerdictFalsePositive, Analyst: "tester"})
	if got := len(s.Active()); got != 2 {
		t.Errorf("active suppressions = %d, want 2", got)
	}
}

func TestRecordRequiresAnalyst(t *testing.T) {
	s := New(nil)
	err := s.Record(Verdict{MatchedIoC: "x", Verdict: VerdictFalsePositive})
	if err == nil {
		t.Fatal("a verdict with no analyst must be rejected: an unattributable " +
			"suppression silences detections with nobody accountable for it")
	}
}

// TestSuppressionExpires covers the step-124 fix. A suppression used to last
// forever and was replayed from ClickHouse on every restart, so one verdict
// blinded the pipeline for that indicator permanently — and because
// Suppressed() is checked before the killswitch webhook, the killswitch never
// even saw the detection. An indicator that was benign in March can be live
// C2 in June.
func TestSuppressionExpires(t *testing.T) {
	s := NewWithOptions(nil, Options{TTL: time.Hour})
	now := time.Now()
	s.now = func() time.Time { return now }

	if err := s.Record(Verdict{
		MatchedIoC: "cdn.example",
		Verdict:    VerdictFalsePositive,
		Analyst:    "tester",
	}); err != nil {
		t.Fatal(err)
	}

	alert := detection.Alert{MatchedIoC: "cdn.example"}
	if !s.Suppressed(alert) {
		t.Fatal("a fresh verdict should suppress")
	}

	// Past the TTL the suppression stops applying...
	now = now.Add(2 * time.Hour)
	if s.Suppressed(alert) {
		t.Fatal("an expired suppression must stop silencing detections")
	}
	// ...and is swept so the gauge and /feedback reflect reality.
	if got := len(s.Active()); got != 0 {
		t.Errorf("expired suppression should be swept, Active() = %d", got)
	}
}

func TestExpiredVerdictNotReplayedOnStartup(t *testing.T) {
	s := NewWithOptions(nil, Options{TTL: time.Hour})
	now := time.Now()
	s.now = func() time.Time { return now }

	// Simulate ClickHouse handing back a verdict from last year.
	s.applyLoaded(Verdict{
		MatchedIoC: "old.example",
		Verdict:    VerdictFalsePositive,
		Analyst:    "tester",
		Timestamp:  now.Add(-365 * 24 * time.Hour),
	})
	if s.Suppressed(detection.Alert{MatchedIoC: "old.example"}) {
		t.Fatal("a stale persisted verdict must not re-blind the pipeline on restart")
	}
}

func TestSuppressionCapRejectsOverflow(t *testing.T) {
	s := NewWithOptions(nil, Options{MaxSuppressions: 2})
	for _, ioc := range []string{"a.example", "b.example"} {
		if err := s.Record(Verdict{
			MatchedIoC: ioc, Verdict: VerdictFalsePositive, Analyst: "tester",
		}); err != nil {
			t.Fatalf("%s: %v", ioc, err)
		}
	}
	err := s.Record(Verdict{
		MatchedIoC: "c.example", Verdict: VerdictFalsePositive, Analyst: "tester",
	})
	if err == nil {
		t.Fatal("exceeding the suppression cap must be rejected, not grow the map " +
			"without bound")
	}
	// Updating an existing suppression is still allowed at the cap.
	if err := s.Record(Verdict{
		MatchedIoC: "a.example", Verdict: VerdictFalsePositive, Analyst: "tester2",
	}); err != nil {
		t.Errorf("updating an existing suppression at the cap should succeed: %v", err)
	}
}

func TestHandleFeedbackUsesAuthenticatedActor(t *testing.T) {
	s := New(nil)
	body := `{"matched_ioc":"cdn.example","verdict":"false_positive","analyst":"spoofed"}`
	req := httptest.NewRequest(http.MethodPost, "/feedback", strings.NewReader(body))
	req.Header.Set("X-Netsoldier-Actor", "real-operator")
	rec := httptest.NewRecorder()

	s.HandleFeedback(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}

	active := s.Active()
	if len(active) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(active))
	}
	if active[0].Analyst != "real-operator" {
		t.Errorf("analyst should come from the authenticated identity, got %q",
			active[0].Analyst)
	}
}

func TestHandleFeedbackRejectsOversizedBody(t *testing.T) {
	s := New(nil)
	huge := `{"matched_ioc":"` + strings.Repeat("a", maxFeedbackBody) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/feedback", strings.NewReader(huge))
	rec := httptest.NewRecorder()
	s.HandleFeedback(rec, req)
	if rec.Code == http.StatusAccepted {
		t.Fatal("an oversized body should not be accepted")
	}
}
