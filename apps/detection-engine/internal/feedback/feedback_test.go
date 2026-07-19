package feedback

import (
	"testing"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
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
		Verdict:    VerdictFalsePositive,
	}); err != nil {
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
	s.Record(Verdict{MatchedIoC: "benign.example", Verdict: VerdictFalsePositive})
	// empty client scope suppresses the indicator on any client
	if !s.Suppressed(detection.Alert{MatchedIoC: "benign.example", ClientIP: "10.0.0.2"}) {
		t.Error("indicator-wide verdict should suppress any client")
	}
}

func TestMatchIsCaseInsensitive(t *testing.T) {
	s := New(nil)
	s.Record(Verdict{MatchedIoC: "Evil.Example", Verdict: VerdictFalsePositive})
	if !s.Suppressed(detection.Alert{MatchedIoC: "evil.example"}) {
		t.Error("suppression match should be case-insensitive")
	}
}

func TestConfirmedClearsSuppression(t *testing.T) {
	s := New(nil)
	a := detection.Alert{MatchedIoC: "x", ClientIP: "192.168.1.5"}
	s.Record(Verdict{MatchedIoC: "x", ClientIP: "192.168.1.5", Verdict: VerdictFalsePositive})
	if !s.Suppressed(a) {
		t.Fatal("should be suppressed after FP")
	}
	s.Record(Verdict{MatchedIoC: "x", ClientIP: "192.168.1.5", Verdict: VerdictConfirmed})
	if s.Suppressed(a) {
		t.Error("confirmed verdict should clear the suppression")
	}
}

func TestRecordPersistsToSink(t *testing.T) {
	sink := &recordingSink{}
	s := New(sink)
	s.Record(Verdict{MatchedIoC: "x", Verdict: VerdictFalsePositive})
	if len(sink.writes) != 1 {
		t.Fatalf("expected 1 persisted verdict, got %d", len(sink.writes))
	}
	if sink.writes[0].Timestamp.IsZero() {
		t.Error("timestamp should be stamped on record")
	}
}

func TestActiveSnapshot(t *testing.T) {
	s := New(nil)
	s.Record(Verdict{MatchedIoC: "a", Verdict: VerdictFalsePositive})
	s.Record(Verdict{MatchedIoC: "b", ClientIP: "10.0.0.1", Verdict: VerdictFalsePositive})
	if got := len(s.Active()); got != 2 {
		t.Errorf("active suppressions = %d, want 2", got)
	}
}
