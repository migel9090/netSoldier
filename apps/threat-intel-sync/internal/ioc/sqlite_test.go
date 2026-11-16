package ioc

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// TestAuditRestartServesPersistedSet (TI-5): the store was memory-only, so a
// restart during a feed outage came up empty. With INDICATOR_DB_PATH the
// last good set — values, metadata, last-asserted stamps and each feed's
// last success — is back the moment the store is opened.
func TestAuditRestartServesPersistedSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	asserted := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)

	s, ls, err := OpenStore(path, WithClock(func() time.Time { return asserted }))
	if err != nil {
		t.Fatal(err)
	}
	if ls.Loaded != 0 || s.Len() != 0 {
		t.Fatalf("fresh database not empty: %+v", ls)
	}
	st := s.UpsertFeed("threatfox", []Indicator{
		{Type: TypeDomain, Value: "c2.evil.example", Source: "threatfox", Confidence: 90,
			Threat: "Mozi", Tags: []string{"c2"}, Reference: "https://threatfox.abuse.ch/ioc/1/",
			FirstSeen: asserted.Add(-time.Hour)},
		{Type: TypeIP, Value: "203.0.113.7:443", Source: "threatfox", Confidence: 75},
	})
	if st.Err != nil || st.Accepted != 2 {
		t.Fatalf("upsert: %+v", st)
	}
	s.UpsertFeed("spamhaus", []Indicator{{Type: TypeIP, Value: "198.51.100.0/24", Source: "spamhaus-drop", Confidence: 95}})
	if err := s.MarkFeedSuccess("threatfox", asserted); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	r, ls, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ls.Loaded != 3 || r.Len() != 3 {
		t.Fatalf("after restart: loaded=%d len=%d, want 3", ls.Loaded, r.Len())
	}
	var got Indicator
	for _, ind := range r.All() {
		if ind.Value == "c2.evil.example" {
			got = ind
		}
	}
	if got.Threat != "Mozi" || got.Confidence != 90 || len(got.Tags) != 1 ||
		got.Reference == "" || !got.LastAsserted.Equal(asserted) || !got.FirstSeen.Equal(asserted.Add(-time.Hour)) {
		t.Errorf("round trip lost data: %+v", got)
	}
	if !r.FeedSuccess()["threatfox"].Equal(asserted) {
		t.Errorf("feed success not persisted: %v", r.FeedSuccess())
	}
	if !r.Persistent() {
		t.Error("Persistent() = false")
	}
}

// TestOpenStoreRevalidatesRows: a row on disk does not bypass the current
// rules. Rows written by an older, laxer build are deleted on load, and a
// row whose canonical spelling changed is re-keyed.
func TestOpenStoreRevalidatesRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.UpsertFeed("misp", []Indicator{{Type: TypeDomain, Value: "ok.example", Source: "misp"}})
	s.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixNano()
	for _, row := range [][2]string{
		{"domain", "*.*.*"},
		{"ip", "0.0.0.0/1"},
		{"ip", "192.168.1.1"},
		{"domain", "OLD-SPELLING.example."},
	} {
		if _, err := db.Exec(`INSERT INTO assertions (type, value, feed, threat, last_asserted)
			VALUES (?, ?, 'legacy', ?, ?)`, row[0], row[1], "x\ty", now); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	r, ls, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Invalid != 3 || r.Len() != 2 || !has(r, "old-spelling.example") {
		t.Fatalf("load stats %+v, len %d, values %v", ls, r.Len(), r.All())
	}
	r.Close()

	r, ls, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ls.Invalid != 0 || ls.Loaded != 2 {
		t.Errorf("invalid or stale rows were not removed from disk: %+v", ls)
	}
}

func TestOpenStoreAppliesCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	clock := time.Now().UTC()
	s, _, err := OpenStore(path, WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	s.UpsertFeed("a", []Indicator{{Type: TypeDomain, Value: "old.example"}})
	clock = clock.Add(time.Hour)
	s.UpsertFeed("a", []Indicator{{Type: TypeDomain, Value: "new.example"}})
	s.Close()

	r, ls, err := OpenStore(path, WithMaxIndicators(1))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Len() != 1 || ls.Dropped != 1 || !has(r, "new.example") {
		t.Errorf("cap on load kept %v (%+v); want only the most recently asserted", r.All(), ls)
	}
}

// TestRetainFeedsDropsDisabledSources: after COMMERCIAL_MODE is switched
// on, the persisted abuse.ch rows must not be served.
func TestRetainFeedsDropsDisabledSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	s, _, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.UpsertFeed("threatfox", []Indicator{
		{Type: TypeDomain, Value: "both.example"}, {Type: TypeDomain, Value: "tf-only.example"}})
	s.UpsertFeed("spamhaus", []Indicator{{Type: TypeDomain, Value: "both.example"}})
	s.MarkFeedSuccess("threatfox", time.Now())
	if n := s.RetainFeeds([]string{"spamhaus", "misp"}); n != 1 {
		t.Errorf("RetainFeeds removed %d indicators, want 1", n)
	}
	s.Close()

	r, _, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Len() != 1 || !has(r, "both.example") || r.All()[0].Source != "spamhaus" {
		t.Errorf("after restart: %+v", r.All())
	}
	if _, ok := r.FeedSuccess()["threatfox"]; ok {
		t.Error("disabled feed's success time survived")
	}
}

func TestOpenStoreRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, _, err := OpenStore(path); err == nil {
		t.Fatal("a database from a newer schema must be refused, not guessed at")
	}
}

func TestOpenStoreUnwritablePath(t *testing.T) {
	if _, _, err := OpenStore(filepath.Join(t.TempDir(), "missing-dir", "x.db")); err == nil {
		t.Fatal("expected an error for a path that cannot be created")
	}
}

func TestPersistentPruneAndClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	clock := time.Now().UTC().Add(-48 * time.Hour)
	s, _, err := OpenStore(path, WithClock(func() time.Time { return clock }))
	if err != nil {
		t.Fatal(err)
	}
	s.UpsertFeed("a", []Indicator{{Type: TypeDomain, Value: "gone.example"}})
	clock = time.Now().UTC()
	s.UpsertFeed("a", []Indicator{{Type: TypeDomain, Value: "kept.example"}})
	if n := s.PruneBefore(clock.Add(-time.Hour)); n != 1 {
		t.Fatalf("pruned %d", n)
	}
	s.Close()

	r, ls, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Loaded != 1 || !has(r, "kept.example") {
		t.Fatalf("prune not persisted: %+v", r.All())
	}
	r.Clear()
	r.Close()
	r, ls, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ls.Loaded != 0 || r.Len() != 0 {
		t.Errorf("Clear not persisted: %+v", ls)
	}
}
