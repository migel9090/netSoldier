package ioc

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/indicator"
)

// The volume guard (internal/guard) keeps its state in this store: each
// feed's usual size and the fetches it held back. These tests pin what the
// store itself promises about that state — that it survives a restart, that
// a failed write never leaves half a fetch on disk, and that a held row is
// held to today's rules when it is read back.

// gt0 is the fixed clock of these tests.
var gt0 = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

func gclock() Option { return WithClock(func() time.Time { return gt0 }) }

func openAt(t *testing.T, path string, opts ...Option) (*Store, LoadStats) {
	t.Helper()
	s, ls, err := OpenStore(path, opts...)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s, ls
}

// rawExec writes to the database file through a connection of its own, the
// way an older build or a damaged disk would have left it.
func rawExec(t *testing.T, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range stmts {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func rawCount(t *testing.T, path, query string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func key(typ, value string) string { return Indicator{Type: typ, Value: value}.Key() }

func heldValues(h HeldSet) []string {
	var out []string
	for _, r := range h.Rows {
		out = append(out, r.Value)
	}
	sort.Strings(out)
	return out
}

func domains(prefix string, n int) []Indicator {
	out := make([]Indicator, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, Indicator{Type: TypeDomain, Value: fmt.Sprintf("%s-%04d.evil.example", prefix, i)})
	}
	return out
}

// TestVolumeHistorySurvivesRestart: without the persisted history every
// restart is a cold start, and a poisoned feed passes the guard by waiting
// for one. Setting replaces (it does not append), nil forgets, and the store
// keeps its own copy in both directions.
func TestVolumeHistorySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path)
	sizes := []int{100, 110, 105}
	if err := s.SetVolumeHistory("threatfox", sizes); err != nil {
		t.Fatal(err)
	}
	sizes[0] = -1
	if err := s.SetVolumeHistory(TotalHistoryKey, []int{500}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVolumeHistory("spamhaus", []int{40}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetVolumeHistory("spamhaus", nil); err != nil {
		t.Fatal(err)
	}
	s.VolumeHistory("threatfox")[1] = -1
	if got, want := s.VolumeHistory("threatfox"), []int{100, 110, 105}; !reflect.DeepEqual(got, want) {
		t.Fatalf("history = %v, want %v: the store must not share slices with callers", got, want)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	r, _ := openAt(t, path)
	if got, want := r.VolumeHistory("threatfox"), []int{100, 110, 105}; !reflect.DeepEqual(got, want) {
		t.Errorf("after restart threatfox history = %v, want %v", got, want)
	}
	if got, want := r.VolumeHistory(TotalHistoryKey), []int{500}; !reflect.DeepEqual(got, want) {
		t.Errorf("after restart store-wide history = %v, want %v", got, want)
	}
	if got := r.VolumeHistory("spamhaus"); len(got) != 0 {
		t.Errorf("a forgotten history came back after restart: %v", got)
	}
	if err := r.SetVolumeHistory("threatfox", []int{7}); err != nil {
		t.Fatal(err)
	}
	r.Close()

	r, _ = openAt(t, path)
	defer r.Close()
	if got, want := r.VolumeHistory("threatfox"), []int{7}; !reflect.DeepEqual(got, want) {
		t.Errorf("replaced history = %v, want %v", got, want)
	}
}

// TestUnreadableVolumeHistoryIsAColdStart: a history row this build cannot
// read costs that feed its baseline, never the indicator set; negative
// sizes (which no build writes) are dropped rather than skewing the median.
func TestUnreadableVolumeHistoryIsAColdStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path)
	s.UpsertFeed("threatfox", []Indicator{{Type: TypeDomain, Value: "c2.evil.example"}})
	if err := s.SetVolumeHistory("threatfox", []int{10, 12}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	rawExec(t, path, `INSERT INTO volume_history (feed, sizes) VALUES
		('garbled', 'not json'), ('object', '{"n": 1}'),
		('negative', '[-5, 20, -1, 30]'), ('only-negative', '[-1]')`)

	r, ls := openAt(t, path)
	defer r.Close()
	if ls.Loaded != 1 || !has(r, "c2.evil.example") {
		t.Fatalf("an unreadable history row cost the indicator set: %+v", ls)
	}
	for feed, want := range map[string][]int{
		"threatfox": {10, 12}, "negative": {20, 30},
		"garbled": nil, "object": nil, "only-negative": nil,
	} {
		if got := r.VolumeHistory(feed); !reflect.DeepEqual(got, want) {
			t.Errorf("history of %s = %#v, want %#v", feed, got, want)
		}
	}
}

// TestHeldFetchSurvivesRestart: a held fetch, its description and every
// row, is back after a restart, so the alert stays up and the operator can
// still release it; it is not served meanwhile. A later hold of the same
// feed replaces the earlier one, rows included.
func TestHeldFetchSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path, gclock())
	s.UpsertFeed("urlhaus", []Indicator{{Type: TypeDomain, Value: "served.evil.example"}})
	c2 := Indicator{Type: TypeDomain, Value: "c2.evil.example", Source: "urlhaus", Threat: "Mozi",
		Confidence: 80, FirstSeen: gt0.Add(-48 * time.Hour), LastSeen: gt0.Add(-time.Hour),
		Tags: []string{"c2", "mozi"}, Reference: "https://urlhaus.example/url/1/"}
	h := HeldSet{Feed: "urlhaus", ID: "sha256:abc", Reason: "growth", Detail: "2 new against a usual 1",
		Partial: true, Started: gt0.Add(-time.Minute), HeldAt: gt0, Size: 2, Baseline: 1,
		NewKeys: 2, Total: 1, Truncated: 3,
		Rows: []Indicator{c2, {Type: TypeIP, Value: "203.0.113.9", Source: "urlhaus"}}}
	if err := s.Hold(h); err != nil {
		t.Fatal(err)
	}
	if err := s.Hold(HeldSet{Feed: "threatfox", ID: "sha256:def", Reason: "collapse",
		Rows: []Indicator{{Type: TypeDomain, Value: "tf.evil.example", Source: "threatfox"}}}); err != nil {
		t.Fatal(err)
	}
	all := s.HeldSets()
	if len(all) != 2 || all["urlhaus"].ID != "sha256:abc" || all["urlhaus"].Rows != nil {
		t.Fatalf("HeldSets = %+v, want both fetches without their rows", all)
	}
	if got, ok := s.Held("urlhaus"); !ok || len(got.Rows) != 2 {
		t.Fatalf("Held(urlhaus) = %+v, %v; want its two rows", got, ok)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	r, ls := openAt(t, path)
	if ls.Held != 2 {
		t.Errorf("LoadStats.Held = %d, want 2", ls.Held)
	}
	got, ok := r.Held("urlhaus")
	if !ok {
		t.Fatal("the held fetch did not survive the restart")
	}
	if !got.Started.Equal(h.Started) || !got.HeldAt.Equal(h.HeldAt) {
		t.Errorf("held times = %v / %v, want %v / %v", got.Started, got.HeldAt, h.Started, h.HeldAt)
	}
	gotMeta, wantMeta := got, h
	gotMeta.Rows, wantMeta.Rows = nil, nil
	gotMeta.Started, wantMeta.Started = time.Time{}, time.Time{}
	gotMeta.HeldAt, wantMeta.HeldAt = time.Time{}, time.Time{}
	if !reflect.DeepEqual(gotMeta, wantMeta) {
		t.Errorf("held description after restart = %+v, want %+v", gotMeta, wantMeta)
	}
	if v := heldValues(got); !reflect.DeepEqual(v, []string{"203.0.113.9", "c2.evil.example"}) {
		t.Fatalf("held rows after restart = %v", v)
	}
	for _, row := range got.Rows {
		if row.Value != c2.Value {
			continue
		}
		if row.Threat != c2.Threat || row.Confidence != c2.Confidence || row.Source != c2.Source ||
			row.Reference != c2.Reference || !reflect.DeepEqual(row.Tags, c2.Tags) ||
			!row.FirstSeen.Equal(c2.FirstSeen) || !row.LastSeen.Equal(c2.LastSeen) {
			t.Errorf("held row lost data: %+v, want %+v", row, c2)
		}
	}
	if r.Len() != 1 || r.Contains(key(TypeDomain, "c2.evil.example")) ||
		!r.Contains(key(TypeDomain, "served.evil.example")) {
		t.Errorf("a held row is being served: %v", r.All())
	}

	if err := r.Hold(HeldSet{Feed: "urlhaus", ID: "sha256:new",
		Rows: []Indicator{{Type: TypeDomain, Value: "only.evil.example"}}}); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r, _ = openAt(t, path)
	defer r.Close()
	got, _ = r.Held("urlhaus")
	if got.ID != "sha256:new" || got.Reason != "" || !reflect.DeepEqual(heldValues(got), []string{"only.evil.example"}) {
		t.Errorf("replacing hold left %+v (rows %v); want only the new fetch", got, heldValues(got))
	}
	if tf, ok := r.Held("threatfox"); !ok || tf.ID != "sha256:def" {
		t.Errorf("replacing one feed's hold touched another's: %+v, %v", tf, ok)
	}
}

// TestReleaseAndDiscardLeaveTheStoreConsistent drives the store the way
// guard.Manager does: a release applies the held rows and drops the hold, a
// discard only drops it. After a restart nothing is held, nothing is left
// in the quarantine tables, the released rows are served and the discarded
// ones are not.
func TestReleaseAndDiscardLeaveTheStoreConsistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path, gclock())
	s.UpsertFeed("threatfox", []Indicator{{Type: TypeDomain, Value: "kept.evil.example"}})
	if err := s.Hold(HeldSet{Feed: "threatfox", ID: "a", Rows: []Indicator{
		{Type: TypeDomain, Value: "released.evil.example", Source: "threatfox"},
		{Type: TypeDomain, Value: "kept.evil.example", Source: "threatfox"},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Hold(HeldSet{Feed: "urlhaus", ID: "b",
		Rows: []Indicator{{Type: TypeDomain, Value: "discarded.evil.example"}}}); err != nil {
		t.Fatal(err)
	}

	h, ok := s.Held("threatfox")
	if !ok {
		t.Fatal("not held")
	}
	if st := s.Apply(s.Prepare("threatfox", h.Rows)); st.Accepted != 2 || st.Err != nil {
		t.Fatalf("release: %+v", st)
	}
	if err := s.DropHeld("threatfox"); err != nil {
		t.Fatal(err)
	}
	if err := s.DropHeld("urlhaus"); err != nil {
		t.Fatal(err)
	}
	if err := s.DropHeld("never-held"); err != nil {
		t.Errorf("dropping a feed that holds nothing: %v", err)
	}
	if n := len(s.HeldSets()); n != 0 {
		t.Errorf("%d fetches still held in memory", n)
	}
	s.Close()

	r, ls := openAt(t, path)
	if ls.Held != 0 || len(r.HeldSets()) != 0 {
		t.Errorf("a released or discarded fetch is held again after restart: %+v", r.HeldSets())
	}
	if r.Len() != 2 || !has(r, "released.evil.example") || !has(r, "kept.evil.example") || has(r, "discarded.evil.example") {
		t.Errorf("served after restart: %v", r.All())
	}
	r.Close()
	for _, table := range []string{"quarantine", "quarantine_rows"} {
		if n := rawCount(t, path, "SELECT count(*) FROM "+table); n != 0 {
			t.Errorf("%d rows left in %s", n, table)
		}
	}
}

// TestLoadHeldRevalidatesRows: a held row is validated again on load, like
// an assertion, so releasing an old held set can never bypass rules that
// tightened since — a host that joined the never-block list, a value now
// refused. A description this build cannot read is ignored rather than
// refusing to start, rows without a description are ignored, and the
// table's key, not the description, names the feed a release addresses.
func TestLoadHeldRevalidatesRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path)
	if err := s.Hold(HeldSet{Feed: "urlhaus", ID: "x",
		Rows: []Indicator{{Type: TypeDomain, Value: "c2.evil.example"}}}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	rawExec(t, path,
		`INSERT INTO quarantine_rows (feed, type, value) VALUES
			('urlhaus', 'domain', 'docs.google.com'),
			('urlhaus', 'ip', '8.8.8.8'),
			('urlhaus', 'domain', '*.*.*'),
			('urlhaus', 'domain', 'Mixed.Evil.Example.'),
			('urlhaus', 'ip', '203.0.113.5'),
			('orphan', 'domain', 'orphan.evil.example')`,
		`INSERT INTO quarantine (feed, meta) VALUES
			('garbled', 'not json'),
			('renamed', '{"source": "someone-else", "id": "r"}')`)

	r, ls := openAt(t, path)
	defer r.Close()
	if ls.Held != 2 {
		t.Errorf("LoadStats.Held = %d, want 2 (urlhaus, renamed)", ls.Held)
	}
	h, ok := r.Held("urlhaus")
	if want := []string{"203.0.113.5", "c2.evil.example", "mixed.evil.example"}; !ok || !reflect.DeepEqual(heldValues(h), want) {
		t.Errorf("held rows after load = %v, want %v", heldValues(h), want)
	}
	for _, feed := range []string{"garbled", "orphan"} {
		if got, ok := r.Held(feed); ok {
			t.Errorf("%s is held: %+v", feed, got)
		}
	}
	if rn, ok := r.Held("renamed"); !ok || rn.Feed != "renamed" || rn.ID != "r" {
		t.Errorf("Held(renamed) = %+v, %v", rn, ok)
	}
}

// TestRetainFeedsForgetsDisabledFeedsGuardState: a feed disabled since the
// last run (COMMERCIAL_MODE) loses its history and its held fetch too, on
// disk as well, so re-enabling it later starts clean and its old hold can
// never be released into the set. The store-wide history stays.
func TestRetainFeedsForgetsDisabledFeedsGuardState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path)
	s.UpsertFeed("threatfox", []Indicator{{Type: TypeDomain, Value: "tf.evil.example"}})
	s.UpsertFeed("spamhaus", []Indicator{{Type: TypeIP, Value: "198.51.100.0/24"}})
	for feed, sizes := range map[string][]int{"threatfox": {10}, "spamhaus": {20}, TotalHistoryKey: {30}} {
		if err := s.SetVolumeHistory(feed, sizes); err != nil {
			t.Fatal(err)
		}
	}
	for _, feed := range []string{"threatfox", "spamhaus"} {
		if err := s.Hold(HeldSet{Feed: feed, ID: feed,
			Rows: []Indicator{{Type: TypeDomain, Value: feed + ".held.example"}}}); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.RetainFeeds([]string{"spamhaus"}); n != 1 {
		t.Errorf("RetainFeeds removed %d indicators, want 1", n)
	}

	check := func(when string, st *Store) {
		t.Helper()
		if got := st.VolumeHistory("threatfox"); len(got) != 0 {
			t.Errorf("%s: disabled feed's history kept: %v", when, got)
		}
		if _, ok := st.Held("threatfox"); ok {
			t.Errorf("%s: disabled feed's held fetch kept", when)
		}
		if got := st.VolumeHistory("spamhaus"); !reflect.DeepEqual(got, []int{20}) {
			t.Errorf("%s: enabled feed's history = %v", when, got)
		}
		if _, ok := st.Held("spamhaus"); !ok {
			t.Errorf("%s: enabled feed's held fetch lost", when)
		}
		if got := st.VolumeHistory(TotalHistoryKey); !reflect.DeepEqual(got, []int{30}) {
			t.Errorf("%s: store-wide history = %v, want it kept", when, got)
		}
	}
	check("in memory", s)
	s.Close()
	r, _ := openAt(t, path)
	check("after restart", r)
	r.Close()
	if n := rawCount(t, path, `SELECT count(*) FROM quarantine_rows WHERE feed = 'threatfox'`); n != 0 {
		t.Errorf("%d held rows of the disabled feed left on disk", n)
	}
}

// TestFullDiskLeavesNoHalfWrittenState: when the disk fills, the write
// fails and says so, the in-memory state is still updated (the set keeps
// being served), and the transaction leaves the file as it was: no part of
// the batch, and the earlier held fetch intact with its rows.
func TestFullDiskLeavesNoHalfWrittenState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path, gclock())
	if err := s.Hold(HeldSet{Feed: "urlhaus", ID: "old",
		Rows: []Indicator{{Type: TypeDomain, Value: "old.evil.example"}}}); err != nil {
		t.Fatal(err)
	}
	// Cap the file at its current size: the next page it needs is a full
	// disk. The store has a single connection, so the pragma sticks.
	var pages int
	if err := s.db.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.db.Exec(fmt.Sprintf("PRAGMA max_page_count = %d", pages)); err != nil {
		t.Fatal(err)
	}

	big := domains("flood", 2000)
	st := s.UpsertFeed("threatfox", big)
	if st.Err == nil || !strings.Contains(st.Err.Error(), "full") {
		t.Fatalf("Apply on a full disk: err = %v, want a full-disk error", st.Err)
	}
	if st.Accepted != len(big) || s.Len() != len(big) {
		t.Errorf("accepted %d, len %d: the in-memory set must still be updated", st.Accepted, s.Len())
	}
	err := s.Hold(HeldSet{Feed: "urlhaus", ID: "new", Rows: big})
	if err == nil || !strings.Contains(err.Error(), "full") {
		t.Fatalf("Hold on a full disk: err = %v, want a full-disk error", err)
	}
	if h, _ := s.Held("urlhaus"); h.ID != "new" {
		t.Errorf("Hold on a full disk: in memory %q is held, want the new fetch", h.ID)
	}
	s.Close()

	r, _ := openAt(t, path)
	defer r.Close()
	if r.Len() != 0 {
		t.Errorf("%d rows of the failed batch reached the disk", r.Len())
	}
	h, ok := r.Held("urlhaus")
	if !ok || h.ID != "old" || !reflect.DeepEqual(heldValues(h), []string{"old.evil.example"}) {
		t.Errorf("after a failed hold the disk holds %+v (rows %v), want the earlier fetch intact", h, heldValues(h))
	}
}

// TestClosedDatabaseReportsEveryWrite: a database that can no longer be
// written makes every write report the error instead of swallowing it,
// while the in-memory state still changes — the guard serves from memory
// and raises the persistence error.
func TestClosedDatabaseReportsEveryWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path, gclock())
	s.Close()

	if st := s.UpsertFeed("threatfox", []Indicator{{Type: TypeDomain, Value: "c2.evil.example"}}); st.Err == nil || st.Accepted != 1 || !has(s, "c2.evil.example") {
		t.Errorf("Apply: %+v", st)
	}
	if err := s.MarkFeedSuccess("threatfox", gt0); err == nil || !s.FeedSuccess()["threatfox"].Equal(gt0) {
		t.Errorf("MarkFeedSuccess: err %v, success %v", err, s.FeedSuccess())
	}
	if err := s.SetVolumeHistory("threatfox", []int{3}); err == nil || !reflect.DeepEqual(s.VolumeHistory("threatfox"), []int{3}) {
		t.Errorf("SetVolumeHistory: err %v, history %v", err, s.VolumeHistory("threatfox"))
	}
	if err := s.SetVolumeHistory("threatfox", nil); err == nil || len(s.VolumeHistory("threatfox")) != 0 {
		t.Errorf("SetVolumeHistory(nil): err %v, history %v", err, s.VolumeHistory("threatfox"))
	}
	if err := s.Hold(HeldSet{Feed: "urlhaus", ID: "x"}); err == nil {
		t.Error("Hold: no error")
	}
	if _, ok := s.Held("urlhaus"); !ok {
		t.Error("Hold: not held in memory")
	}
	if err := s.DropHeld("urlhaus"); err == nil {
		t.Error("DropHeld: no error")
	}
	if _, ok := s.Held("urlhaus"); ok {
		t.Error("DropHeld: still held in memory")
	}
}

// TestCorruptDatabaseIsRefusedNotReplaced: a file that is not a database is
// an error at start-up, and the file is left as it was for the operator —
// never silently replaced by an empty store that would export nothing.
func TestCorruptDatabaseIsRefusedNotReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	garbage := bytes.Repeat([]byte("this is not an SQLite database\n"), 512)
	if err := os.WriteFile(path, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if s, _, err := OpenStore(path); err == nil {
		s.Close()
		t.Fatal("a corrupt database was opened")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, garbage) {
		t.Error("refusing a corrupt database changed the file")
	}
}

// TestPrepareLeavesPersistentStoreUntouched: Prepare is what the guard
// judges before anything changes, so neither memory nor disk may move until
// Apply. The batch reports what validation made of the delivery, merges
// duplicates in delivery order, and names the feed on rows that did not.
func TestPrepareLeavesPersistentStoreUntouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path, gclock())
	defer s.Close()
	s.UpsertFeed("urlhaus", []Indicator{{Type: TypeDomain, Value: "known.evil.example", Source: "urlhaus"}})

	b := s.Prepare("urlhaus", []Indicator{
		{Type: TypeDomain, Value: "New.Evil.Example"},
		{Type: TypeDomain, Value: "known.evil.example", Source: "urlhaus"},
		{Type: TypeDomain, Value: "new.evil.example", Source: "urlhaus", Confidence: 70},
		{Type: TypeDomain, Value: "docs.google.com"},
		{Type: TypeIP, Value: "8.8.8.8"},
		{Type: TypeDomain, Value: "*.*.*"},
	})
	newKey, knownKey := key(TypeDomain, "new.evil.example"), key(TypeDomain, "known.evil.example")

	if b.Feed() != "urlhaus" || b.Len() != 2 {
		t.Errorf("batch feed %q, len %d", b.Feed(), b.Len())
	}
	keys := b.Keys()
	if !reflect.DeepEqual(keys, []string{newKey, knownKey}) {
		t.Errorf("keys = %v, want delivery order", keys)
	}
	keys[0] = "mutated"
	if b.Keys()[0] != newKey {
		t.Error("Keys shares the batch's slice")
	}
	inds := b.Indicators()
	if len(inds) != 2 || inds[0].Value != "new.evil.example" || inds[0].Source != "urlhaus" || inds[0].Confidence != 70 {
		t.Errorf("indicators = %+v", inds)
	}
	if b.Stats.Rows != 6 || b.Stats.Rejected != 1 || b.Stats.NeverBlocked() != 2 ||
		b.Stats.NeverBlock[indicator.ReasonPopular] != 1 || b.Stats.NeverBlock[indicator.ReasonPublicResolver] != 1 {
		t.Errorf("stats = %+v", b.Stats)
	}

	if s.Len() != 1 || s.Contains(newKey) || !s.Contains(knownKey) || s.CountNew(b) != 1 {
		t.Errorf("Prepare changed the store: len %d, %v", s.Len(), s.All())
	}
	if n := rawCount(t, path, "SELECT count(*) FROM assertions"); n != 1 {
		t.Errorf("Prepare wrote %d assertions to disk, want the 1 there before", n)
	}

	st := s.Apply(b)
	if st.Accepted != 3 || st.Rejected != 1 || st.Err != nil || !s.Contains(newKey) {
		t.Errorf("apply: %+v", st)
	}
	st.NeverBlock[indicator.ReasonPopular] = 99
	if b.Stats.NeverBlock[indicator.ReasonPopular] != 1 {
		t.Error("Apply's stats share the batch's never-block counts")
	}
	if n := rawCount(t, path, "SELECT count(*) FROM assertions"); n != 2 {
		t.Errorf("after Apply %d assertions on disk, want 2", n)
	}
}

// TestFullStoreDoesNotPersistRefusedRows: rows refused by the store cap are
// not written either, so the disk matches what is served and lifting the
// cap does not resurrect what a flood delivered.
func TestFullStoreDoesNotPersistRefusedRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _ := openAt(t, path, WithMaxIndicators(2), gclock())
	st := s.UpsertFeed("hostile", domains("flood", 5))
	if st.Accepted != 2 || st.Dropped != 3 || st.Err != nil {
		t.Fatalf("stats = %+v", st)
	}
	s.Close()

	r, ls := openAt(t, path)
	defer r.Close()
	if ls.Loaded != 2 || ls.Dropped != 0 || r.Len() != 2 {
		t.Errorf("after lifting the cap: %+v, len %d", ls, r.Len())
	}
}
