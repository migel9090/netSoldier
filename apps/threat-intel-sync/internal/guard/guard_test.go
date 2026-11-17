package guard

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/libs/indicator"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestCheck(t *testing.T) {
	l := DefaultLimits()
	hist := []int{1000, 1100, 1050}
	for _, c := range []struct {
		name   string
		in     Input
		reason string // "" = applied
	}{
		{"cold start within the first-sync maximum", Input{Size: 20000}, ""},
		{"cold start above it", Input{Size: 60000}, ReasonFirstSync},
		{"a normal fetch", Input{Size: 1200, History: hist}, ""},
		{"legitimate growth, 2.5×", Input{Size: 2600, History: hist}, ""},
		{"tenfold jump", Input{Size: 10500, History: hist}, ReasonGrowth},
		{"collapse to a tenth", Input{Size: 100, History: hist}, ReasonCollapse},
		{"an empty answer after a thousand", Input{Size: 0, History: hist}, ReasonCollapse},
		{"a partial fetch is never a collapse", Input{Size: 100, History: hist, Partial: true}, ""},
		{"a partial fetch can still be a jump", Input{Size: 10500, History: hist, Partial: true}, ReasonGrowth},
		{"a small feed swings freely", Input{Size: 300, History: []int{20, 25, 30}}, ""},
		{"a small feed that suddenly lists thousands", Input{Size: 3000, History: []int{20, 25, 30}}, ReasonGrowth},
		{"a small feed going quiet", Input{Size: 0, History: []int{40, 50}}, ""},
		{"a new feed joining an established store", Input{Size: 9000, NewKeys: 9000, StoreTotal: 3000,
			TotalHistory: []int{3000, 3000, 3100}}, ReasonTotalGrowth},
		{"a modest new feed joining it", Input{Size: 2000, NewKeys: 2000, StoreTotal: 3000,
			TotalHistory: []int{3000, 3000, 3100}}, ""},
		{"no store history yet (fresh install)", Input{Size: 9000, NewKeys: 9000, StoreTotal: 3000}, ""},
	} {
		v := l.Check(c.in)
		got := ""
		if v.Hold {
			got = v.Reason
		}
		if got != c.reason {
			t.Errorf("%s: verdict %+v, want reason %q", c.name, v, c.reason)
		}
		if v.Hold && v.Detail == "" {
			t.Errorf("%s: a held fetch needs an explanation", c.name)
		}
	}
}

// TestMedianResistsRatcheting: one odd fetch does not move the usual size,
// so a poisoned feed cannot grow its own baseline by one big step.
func TestMedianResistsRatcheting(t *testing.T) {
	h := []int{1000, 1000, 1000, 1000}
	h = Append(h, 2900) // passes the 3× rule once
	if m := Median(h); m != 1000 {
		t.Errorf("median after one high fetch = %d, want 1000", m)
	}
	if v := DefaultLimits().Check(Input{Size: 8000, History: h}); !v.Hold {
		t.Error("the next, higher step was not held")
	}
	for i := 0; i < 20; i++ {
		h = Append(h, i)
	}
	if len(h) != HistoryLen {
		t.Errorf("history kept %d entries, want %d", len(h), HistoryLen)
	}
	if Median(nil) != 0 || Median([]int{5}) != 5 || Median([]int{1, 9}) != 1 {
		t.Error("median edge cases")
	}
}

func TestLimitsValidate(t *testing.T) {
	if err := DefaultLimits().Validate(); err != nil {
		t.Fatalf("defaults: %v", err)
	}
	for _, l := range []Limits{
		{GrowthFactor: 1, ShrinkFactor: 4, MinChange: 500, FirstSyncMax: 10},
		{GrowthFactor: 0.5, ShrinkFactor: 4, MinChange: 500, FirstSyncMax: 10},
		{GrowthFactor: 3, ShrinkFactor: 1, MinChange: 500, FirstSyncMax: 10},
		{GrowthFactor: 3, ShrinkFactor: 4, MinChange: -1, FirstSyncMax: 10},
		{GrowthFactor: 3, ShrinkFactor: 4, MinChange: 500, FirstSyncMax: 0},
		{GrowthFactor: 5000, ShrinkFactor: 4, MinChange: 500, FirstSyncMax: 10},
	} {
		if l.Validate() == nil {
			t.Errorf("%+v accepted", l)
		}
	}
}

func domains(prefix string, n int) []ioc.Indicator {
	out := make([]ioc.Indicator, n)
	for i := range out {
		out[i] = ioc.Indicator{Type: ioc.TypeDomain, Value: fmt.Sprintf("%s%d.evil.example", prefix, i), Source: "testfeed"}
	}
	return out
}

func has(s *ioc.Store, v string) bool {
	for _, i := range s.All() {
		if i.Value == v {
			return true
		}
	}
	return false
}

// TestTenfoldJumpIsHeldAndPreviousSetServed is the step's "done when" at
// the guard: a feed that answers with ten times its usual set is held, the
// store keeps exactly the previous set, and the feed is not recorded as
// having answered (nothing of the old set starts to expire).
func TestTenfoldJumpIsHeldAndPreviousSetServed(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, DefaultLimits(), []string{"testfeed"}, 100000)
	t0 := time.Now().Add(-time.Hour)
	if out := m.Ingest("testfeed", domains("a", 600), true, t0); !out.Applied || out.Held != nil {
		t.Fatalf("first fetch: %+v", out)
	}
	firstSuccess := s.FeedSuccess()["testfeed"]

	jump := append(domains("b", 6000), ioc.Indicator{Type: ioc.TypeDomain, Value: "google.com", Source: "testfeed"})
	out := m.Ingest("testfeed", jump, true, time.Now())
	if out.Applied || out.Held == nil || out.Verdict.Reason != ReasonGrowth {
		t.Fatalf("tenfold jump: %+v", out)
	}
	if out.Held.Size != 6000 || out.Held.Baseline != 600 || out.Held.NewKeys != 6000 {
		t.Errorf("held summary = %+v", out.Held)
	}
	if out.Prepare.NeverBlock[indicator.ReasonPopular] != 1 {
		t.Errorf("google.com in the held fetch not counted as never-block: %+v", out.Prepare)
	}
	if s.Len() != 600 || !has(s, "a0.evil.example") || has(s, "b0.evil.example") {
		t.Errorf("the store changed: %d indicators", s.Len())
	}
	if got := s.FeedSuccess()["testfeed"]; !got.Equal(firstSuccess) {
		t.Error("a held fetch was recorded as the feed's answer")
	}
	if h, ok := m.Get("testfeed"); !ok || len(h.Rows) != 6000 {
		t.Fatalf("held rows: %v %d", ok, len(h.Rows))
	}
	for _, r := range func() []ioc.Indicator { h, _ := m.Get("testfeed"); return h.Rows }() {
		if r.Value == "google.com" {
			t.Fatal("a never-block indicator is in the held set")
		}
	}

	// The feed recovers: its normal answer applies and supersedes the hold.
	out = m.Ingest("testfeed", domains("a", 620), true, time.Now())
	if !out.Applied || out.Superseded == nil {
		t.Fatalf("recovered fetch: %+v", out)
	}
	if _, ok := m.Get("testfeed"); ok {
		t.Error("the held fetch outlived a passing one")
	}
}

func TestReleaseAppliesAndResetsBaseline(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, DefaultLimits(), []string{"misp"}, 100000)
	m.Ingest("misp", domains("a", 600), true, time.Now().Add(-time.Hour))
	out := m.Ingest("misp", domains("b", 6000), true, time.Now().Add(-time.Minute))
	if out.Held == nil {
		t.Fatal("not held")
	}
	if _, err := m.Release("misp", "not-the-id"); !errors.Is(err, ErrStale) {
		t.Errorf("release with a stale id: %v", err)
	}
	rel, err := m.Release("misp", out.Held.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rel.Stats.Accepted != 6000 || rel.Baseline != 6000 || !has(s, "b5999.evil.example") {
		t.Errorf("release = %+v", rel)
	}
	if _, err := m.Release("misp", out.Held.ID); !errors.Is(err, ErrNotHeld) {
		t.Errorf("second release: %v", err)
	}
	if !s.FeedSuccess()["misp"].Equal(out.Held.Started) {
		t.Error("release did not record the held fetch as the feed's answer")
	}
	// The new size is the usual one now: the next fetch like it passes.
	if out := m.Ingest("misp", domains("b", 6100), true, time.Now()); !out.Applied {
		t.Errorf("the fetch after a release was held again: %+v", out.Verdict)
	}
}

func TestDiscardKeepsPreviousSet(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, DefaultLimits(), []string{"feed"}, 100000)
	m.Ingest("feed", domains("a", 2000), true, time.Now())
	if out := m.Ingest("feed", domains("a", 100), true, time.Now()); out.Held == nil || out.Verdict.Reason != ReasonCollapse {
		t.Fatalf("collapse not held: %+v", out.Verdict)
	}
	h, err := m.Discard("feed")
	if err != nil || h.Reason != ReasonCollapse {
		t.Fatalf("discard: %+v %v", h, err)
	}
	if s.Len() != 2000 {
		t.Errorf("store = %d", s.Len())
	}
	if _, err := m.Discard("feed"); !errors.Is(err, ErrNotHeld) {
		t.Errorf("second discard: %v", err)
	}
	if hist := s.VolumeHistory("feed"); len(hist) != 1 || hist[0] != 2000 {
		t.Errorf("discard changed the history: %v", hist)
	}
}

// TestPartialFetches: a failed fetch still contributes what validated, but
// is not the feed's answer — and a partial jump is held like a complete one.
func TestPartialFetches(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, DefaultLimits(), []string{"feed"}, 100000)
	m.Ingest("feed", domains("a", 1000), true, time.Now())
	before := s.FeedSuccess()["feed"]
	if out := m.Ingest("feed", domains("c", 50), false, time.Now()); !out.Applied {
		t.Errorf("partial rows not applied: %+v", out)
	}
	if !s.FeedSuccess()["feed"].Equal(before) || len(s.VolumeHistory("feed")) != 1 {
		t.Error("a partial fetch was recorded as an answer")
	}
	out := m.Ingest("feed", domains("d", 20000), false, time.Now())
	if out.Held == nil || !out.Held.Partial {
		t.Fatalf("partial jump: %+v", out)
	}
	rel, err := m.Release("feed", out.Held.ID)
	if err != nil || rel.Stats.Accepted != 20000 {
		t.Fatalf("release partial: %+v %v", rel, err)
	}
	if !s.FeedSuccess()["feed"].Equal(before) {
		t.Error("releasing a partial fetch recorded it as the feed's answer")
	}
}

func TestAllRejectedIsNotJudged(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, DefaultLimits(), []string{"feed"}, 100000)
	m.Ingest("feed", domains("a", 1000), true, time.Now())
	out := m.Ingest("feed", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "*.*.*"}}, true, time.Now())
	if out.Applied || out.Held != nil || out.Prepare.Rejected != 1 {
		t.Errorf("all-rejected fetch: %+v", out)
	}
}

func TestHoldCap(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, Limits{GrowthFactor: 3, ShrinkFactor: 4, MinChange: 0, FirstSyncMax: 10}, []string{"feed"}, 25)
	out := m.Ingest("feed", domains("a", 100), true, time.Now())
	if out.Held == nil || out.Held.Truncated != 75 || out.Verdict.Reason != ReasonFirstSync {
		t.Fatalf("held = %+v", out.Held)
	}
	if h, _ := m.Get("feed"); len(h.Rows) != 25 {
		t.Errorf("kept %d rows, want 25", len(h.Rows))
	}
}

// TestStoreWideHistoryStartsWhenSettled: the store-wide check waits until
// every enabled feed has answered once, so a fresh install is never held
// for being fresh; afterwards a newly enabled feed joining with a set many
// times the store's size is.
func TestStoreWideHistoryStartsWhenSettled(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, DefaultLimits(), []string{"spamhaus", "misp"}, 100000)
	m.Ingest("spamhaus", domains("s", 1500), true, time.Now())
	if len(s.VolumeHistory(ioc.TotalHistoryKey)) != 0 {
		t.Fatal("store-wide history recorded before every feed had answered")
	}
	// MISP was slow on the first cycle; its first answer is ten times the
	// store so far, and must pass (it is a fresh install).
	if out := m.Ingest("misp", domains("m", 15000), true, time.Now()); !out.Applied {
		t.Fatalf("fresh install held: %+v", out.Verdict)
	}
	if got := s.VolumeHistory(ioc.TotalHistoryKey); len(got) != 1 || got[0] != 16500 {
		t.Fatalf("store-wide history = %v", got)
	}

	// Later a third feed is enabled (a restart with a new guard over the
	// same store) and answers with far more than the store holds.
	m = New(s, DefaultLimits(), []string{"spamhaus", "misp", "threatfox"}, 100000)
	out := m.Ingest("threatfox", domains("t", 45000), true, time.Now())
	if out.Held == nil || out.Verdict.Reason != ReasonTotalGrowth {
		t.Fatalf("new feed tripling the store: %+v", out.Verdict)
	}
	if out := m.Ingest("threatfox", domains("t", 5000), true, time.Now()); !out.Applied {
		t.Errorf("a modest new feed was held: %+v", out.Verdict)
	}
}

// TestStateSurvivesRestart: history and held fetches are persisted, so a
// restart is not a cold start and a held fetch can still be released. Held
// rows are validated again on load.
func TestStateSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _, err := ioc.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	m := New(s, DefaultLimits(), []string{"feed"}, 100000)
	m.Ingest("feed", domains("a", 700), true, time.Now().Add(-time.Hour))
	out := m.Ingest("feed", domains("b", 9000), true, time.Now())
	if out.Held == nil {
		t.Fatal("not held")
	}
	s.Close()

	s, ls, err := ioc.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Held != 1 || s.Len() != 700 {
		t.Fatalf("after restart: %+v, %d indicators", ls, s.Len())
	}
	m = New(s, DefaultLimits(), []string{"feed"}, 100000)
	if base, ok := m.Baseline("feed"); !ok || base != 700 {
		t.Errorf("baseline after restart = %d, %v", base, ok)
	}
	h, ok := m.Get("feed")
	if !ok || h.ID != out.Held.ID || len(h.Rows) != 9000 || h.Reason != ReasonGrowth {
		t.Fatalf("held after restart: %v %+v (%d rows)", ok, h.Reason, len(h.Rows))
	}
	// The same jump again is still held (no cold start)...
	if again := m.Ingest("feed", domains("b", 9000), true, time.Now()); again.Held == nil || again.Held.ID != out.Held.ID {
		t.Errorf("after restart the same jump: %+v", again.Verdict)
	}
	// ...and releasing it works from the persisted copy.
	if _, err := m.Release("feed", out.Held.ID); err != nil || s.Len() != 9700 {
		t.Errorf("release after restart: %v, %d", err, s.Len())
	}
	s.Close()
	s2, ls, err := ioc.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if ls.Held != 0 || len(s2.VolumeHistory("feed")) != 1 || s2.VolumeHistory("feed")[0] != 9000 {
		t.Errorf("after release and restart: %+v, history %v", ls, s2.VolumeHistory("feed"))
	}
}

// TestHostileIndicatorsNeverReachAHeldSet: the audit's hostile set is
// rejected before the guard looks at anything, so no release can apply it.
func TestHostileIndicatorsNeverReachAHeldSet(t *testing.T) {
	s := ioc.NewStore()
	m := New(s, Limits{GrowthFactor: 3, ShrinkFactor: 4, MinChange: 0, FirstSyncMax: 1}, []string{"feed"}, 100)
	hostile := []ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "*.*.*"}, {Type: ioc.TypeDomain, Value: "co.uk"},
		{Type: ioc.TypeDomain, Value: "evil.example^$dnsrewrite=203.0.113.9"},
		{Type: ioc.TypeIP, Value: "0.0.0.0/1"}, {Type: ioc.TypeIP, Value: "192.168.1.1"},
		{Type: ioc.TypeIP, Value: "8.8.8.8"}, {Type: ioc.TypeDomain, Value: "raw.githubusercontent.com"},
		{Type: ioc.TypeMD5, Value: "not-a-hash;rm"},
	}
	out := m.Ingest("feed", append(hostile, domains("ok", 5)...), true, time.Now())
	if out.Held == nil {
		t.Fatalf("5 > first-sync max 1, expected a hold: %+v", out)
	}
	h, _ := m.Get("feed")
	for _, r := range h.Rows {
		if !strings.HasSuffix(r.Value, ".evil.example") {
			t.Errorf("hostile or protected value in the held set: %q", r.Value)
		}
	}
	if out.Prepare.Rejected != 6 || out.Prepare.NeverBlocked() != 2 {
		t.Errorf("prepare stats = %+v", out.Prepare)
	}
}
