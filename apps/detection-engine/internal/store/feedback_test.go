package store

import (
	"path/filepath"
	"testing"
	"time"
)

func verdictRow(at time.Time, ioc, verdict string) FeedbackRow {
	return FeedbackRow{RecordedAt: at, MatchedIoC: ioc, SignalClass: "ioc", Verdict: verdict, Analyst: "a"}
}

func replayed(t *testing.T, f *Feedback, since time.Time) []FeedbackRow {
	t.Helper()
	var out []FeedbackRow
	if err := f.Replay(since, func(r FeedbackRow) error { out = append(out, r); return nil }); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestFeedbackJournalSurvivesReopen: the journal is a file on the volume;
// what was appended is there for the next process, in the order it was
// recorded — by time, then by sequence within one millisecond.
func TestFeedbackJournalSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "de.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	f := st.Feedback()
	if fresh, err := f.Fresh(); err != nil || !fresh || !f.Durable() {
		t.Fatalf("new journal: fresh=%v durable=%v err=%v", fresh, f.Durable(), err)
	}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	for _, r := range []FeedbackRow{
		verdictRow(now, "b.example", "false_positive"),
		verdictRow(now, "b.example", "confirmed"),
		verdictRow(now.Add(-time.Hour), "a.example", "false_positive"), // adopted history, older
	} {
		if _, err := f.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	st.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got := replayed(t, st.Feedback(), time.Time{})
	if len(got) != 3 || got[0].MatchedIoC != "a.example" || got[1].Verdict != "false_positive" ||
		got[2].Verdict != "confirmed" || !got[1].RecordedAt.Equal(now) {
		t.Errorf("replay order %+v", got)
	}
	if got := replayed(t, st.Feedback(), now.Add(-time.Minute)); len(got) != 2 {
		t.Errorf("replay since: %d rows, want 2", len(got))
	}
	if fresh, _ := st.Feedback().Fresh(); fresh {
		t.Error("a journal that held verdicts is not fresh")
	}
	if _, err := st.Feedback().Prune(now.Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	if fresh, _ := st.Feedback().Fresh(); fresh {
		t.Error("pruning must not make the journal fresh again")
	}
}

// TestFeedbackOutboxOrderAndRetention: copies go oldest first and nothing
// overtakes a copy that is backing off; nothing ClickHouse lacks is
// forgotten.
func TestFeedbackOutboxOrderAndRetention(t *testing.T) {
	f := memStore(t).Feedback()
	if f.Durable() {
		t.Error("an in-memory journal claims to be durable")
	}
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	first, _ := f.Append(verdictRow(old, "a.example", "false_positive"))
	f.Append(verdictRow(now, "b.example", "false_positive"))
	if _, err := f.Adopt([]FeedbackRow{verdictRow(old, "c.example", "false_positive")}); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Unforwarded(); n != 2 {
		t.Fatalf("unforwarded = %d, want 2 (adopted rows are in ClickHouse already)", n)
	}

	r, ok, err := f.NextUnforwarded(now)
	if err != nil || !ok || r.Seq != first {
		t.Fatalf("next = %+v %v %v, want the oldest", r, ok, err)
	}
	if err := f.RetryForward(first, now.Add(time.Minute), "clickhouse 516"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.NextUnforwarded(now); ok {
		t.Error("a verdict overtook the one backing off")
	}
	r, ok, _ = f.NextUnforwarded(now.Add(time.Minute))
	if !ok || r.Seq != first || r.Attempts != 1 {
		t.Fatalf("after the back-off: %+v %v", r, ok)
	}

	// Old and not in ClickHouse yet: kept. Old and adopted: gone.
	if n, err := f.Prune(now.Add(-24*time.Hour), true); err != nil || n != 1 {
		t.Fatalf("prune with forwarding removed %d (%v), want only the adopted row", n, err)
	}
	if err := f.Forwarded(first); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Prune(now.Add(-24*time.Hour), true); n != 1 {
		t.Errorf("a copied old verdict was not forgotten: %d", n)
	}
	if n, _ := f.Count(); n != 1 {
		t.Errorf("%d rows left, want the recent one", n)
	}
	// Without forwarding, age alone decides.
	if n, _ := f.Prune(now.Add(time.Hour), false); n != 1 {
		t.Errorf("prune without forwarding removed %d", n)
	}
}

// TestFeedbackCompactKeepsWhatReplayNeeds: compaction removes every row not
// kept, but never one at or after the oldest verdict ClickHouse lacks.
func TestFeedbackCompactKeepsWhatReplayNeeds(t *testing.T) {
	f := memStore(t).Feedback()
	now := time.Now().UTC()
	var seqs []int64
	for i := 0; i < 6; i++ {
		seq, _ := f.Append(verdictRow(now.Add(time.Duration(i)*time.Second), "x.example", "false_positive"))
		seqs = append(seqs, seq)
	}
	for _, s := range seqs[:4] {
		f.Forwarded(s)
	}
	// Forwarding: rows from the oldest unforwarded one (seqs[4]) on stay.
	if n, err := f.Compact([]int64{seqs[1]}, true); err != nil || n != 3 {
		t.Fatalf("compact with forwarding removed %d (%v), want 3", n, err)
	}
	got := replayed(t, f, time.Time{})
	if len(got) != 3 || got[0].Seq != seqs[1] || got[1].Seq != seqs[4] {
		t.Fatalf("left %+v", got)
	}
	// Without forwarding only keep stays.
	if n, err := f.Compact([]int64{seqs[5]}, false); err != nil || n != 2 {
		t.Fatalf("compact removed %d (%v), want 2", n, err)
	}
	if n, err := f.Compact(nil, false); err != nil || n != 1 {
		t.Errorf("compact with nothing kept removed %d (%v)", n, err)
	}
}

// TestFeedbackJournalErrors: a closed store fails every call instead of
// pretending.
func TestFeedbackJournalErrors(t *testing.T) {
	st, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	f := st.Feedback()
	st.Close()
	if _, err := f.Append(verdictRow(time.Now(), "x", "false_positive")); err == nil {
		t.Error("Append on a closed store")
	}
	if _, err := f.Adopt([]FeedbackRow{verdictRow(time.Now(), "x", "false_positive")}); err == nil {
		t.Error("Adopt on a closed store")
	}
	if _, err := f.Fresh(); err == nil {
		t.Error("Fresh on a closed store")
	}
	if err := f.Replay(time.Time{}, func(FeedbackRow) error { return nil }); err == nil {
		t.Error("Replay on a closed store")
	}
	if _, _, err := f.NextUnforwarded(time.Now()); err == nil {
		t.Error("NextUnforwarded on a closed store")
	}
	if f.Forwarded(1) == nil || f.RetryForward(1, time.Now(), "x") == nil {
		t.Error("outbox updates on a closed store")
	}
	if _, err := f.Prune(time.Now(), false); err == nil {
		t.Error("Prune on a closed store")
	}
	if _, err := f.Compact(nil, true); err == nil {
		t.Error("Compact on a closed store")
	}
}
