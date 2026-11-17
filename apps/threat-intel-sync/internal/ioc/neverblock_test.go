package ioc

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/indicator"
)

// TestNeverBlockAtIngest (step 134): a feed row naming a popular or shared
// host, or a public resolver, is dropped at ingest and counted by reason —
// apart from malformed rows — while the rest of the delivery is applied. A
// URL on the same host is kept: it names one resource, not the host.
func TestNeverBlockAtIngest(t *testing.T) {
	s := NewStore()
	st := s.UpsertFeed("urlhaus", []Indicator{
		{Type: TypeURL, Value: "https://docs.google.com/uc?id=malware", Source: "urlhaus"},
		{Type: TypeDomain, Value: "docs.google.com", Source: "urlhaus"},
		{Type: TypeDomain, Value: "raw.githubusercontent.com", Source: "urlhaus"},
		{Type: TypeIP, Value: "8.8.8.8", Source: "threatfox"},
		{Type: TypeIP, Value: "8.8.8.0/24", Source: "threatfox"},
		{Type: TypeDomain, Value: "c2.evil.example", Source: "urlhaus"},
		{Type: TypeDomain, Value: "*.*.*", Source: "urlhaus"},
	})
	if st.Accepted != 2 || st.Rejected != 1 {
		t.Errorf("accepted=%d rejected=%d, want 2/1", st.Accepted, st.Rejected)
	}
	want := map[string]int{indicator.ReasonPopular: 1, indicator.ReasonSharedHosting: 1, indicator.ReasonPublicResolver: 2}
	for r, n := range want {
		if st.NeverBlock[r] != n {
			t.Errorf("never-block %s = %d, want %d (%v)", r, st.NeverBlock[r], n, st.NeverBlock)
		}
	}
	if has(s, "docs.google.com") || has(s, "8.8.8.8") || !has(s, "https://docs.google.com/uc?id=malware") || !has(s, "c2.evil.example") {
		t.Errorf("store = %v", s.All())
	}

	_, err := Validate(Indicator{Type: TypeDomain, Value: "WWW.Google.COM"})
	var nb *indicator.NeverBlockError
	if !errors.As(err, &nb) || nb.Reason != indicator.ReasonPopular || nb.Entry != "google.com" {
		t.Errorf("Validate(www.google.com) = %v", err)
	}
}

// TestOpenStoreDropsNeverBlockRows: a row persisted before its host joined
// the never-block list is deleted on load, so a list update takes effect on
// the next start without waiting for the feed to withdraw it.
func TestOpenStoreDropsNeverBlockRows(t *testing.T) {
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
	if _, err := db.Exec(`INSERT INTO assertions (type, value, feed, last_asserted)
		VALUES ('domain', 'drive.google.com', 'misp', ?), ('ip', '1.1.1.1', 'misp', ?)`,
		time.Now().UnixNano(), time.Now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	db.Close()

	r, ls, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if ls.NeverBlock != 2 || ls.Invalid != 0 || r.Len() != 1 {
		t.Fatalf("load stats %+v, values %v", ls, r.All())
	}
	r.Close()
	r, ls, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if ls.NeverBlock != 0 || ls.Loaded != 1 {
		t.Errorf("protected rows were not removed from disk: %+v", ls)
	}
}

// TestPrepareDoesNotChangeTheStore: the guard judges a prepared batch
// before anything is applied.
func TestPrepareDoesNotChangeTheStore(t *testing.T) {
	s := NewStore()
	s.UpsertFeed("f", []Indicator{{Type: TypeDomain, Value: "a.evil.example"}})
	b := s.Prepare("f", []Indicator{
		{Type: TypeDomain, Value: "a.evil.example"}, {Type: TypeDomain, Value: "b.evil.example"},
		{Type: TypeDomain, Value: "B.evil.example"},
	})
	if s.Len() != 1 || b.Len() != 2 || b.Stats.Rows != 3 || s.CountNew(b) != 1 {
		t.Errorf("len %d, batch %d, rows %d, new %d", s.Len(), b.Len(), b.Stats.Rows, s.CountNew(b))
	}
	if st := s.Apply(b); st.Accepted != 3 || s.Len() != 2 {
		t.Errorf("apply: %+v, len %d", st, s.Len())
	}
}
