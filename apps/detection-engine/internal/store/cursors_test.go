package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestCursorsSurviveReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "de.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	c := st.Cursors()
	if _, _, ok, err := c.Load("zeek_intel"); ok || err != nil {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	now := time.UnixMilli(1_800_000_000_123).UTC()
	c.now = func() time.Time { return now }
	if err := c.Save("zeek_intel", []byte(`{"at_ms":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.Save("zeek_intel", []byte(`{"at_ms":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.Save("adguard_querylog", []byte(`x`)); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	pos, updated, ok, err := st.Cursors().Load("zeek_intel")
	if err != nil || !ok || string(pos) != `{"at_ms":2}` || !updated.Equal(now) {
		t.Errorf("after reopen: %q %v ok=%v err=%v", pos, updated, ok, err)
	}
	if pos, _, ok, _ := st.Cursors().Load("adguard_querylog"); !ok || string(pos) != "x" {
		t.Errorf("second source: %q %v", pos, ok)
	}
}

// TestSchemaUpgradeKeepsExistingData: a file written by the previous
// release (schema step 1) gains the cursor table and keeps its alerts.
func TestSchemaUpgradeKeepsExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO alerts (id, recorded_at, sev_rank, body) VALUES ('DET-a-1', 1, 0, '{"id":"DET-a-1"}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, ok := st.Alerts(0, 0).ByID("DET-a-1"); !ok {
		t.Error("existing alert lost in the upgrade")
	}
	if err := st.Cursors().Save("s", []byte("p")); err != nil {
		t.Errorf("cursor table missing after upgrade: %v", err)
	}
	st.Records(0).Remember("r")
	if !st.Records(0).Seen("r") {
		t.Error("record table missing after upgrade")
	}
}

// TestRecordsRememberAndExpire: the ledger survives a restart (that is when
// records are read again) and forgets what can no longer be re-read.
func TestRecordsRememberAndExpire(t *testing.T) {
	path := filepath.Join(t.TempDir(), "de.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r := st.Records(time.Hour)
	now := time.Unix(1_800_000_000, 0)
	r.now = func() time.Time { return now }
	r.Remember("adguard\x00entry-1")
	r.Remember("adguard\x00entry-1") // twice is once
	if !r.Seen("adguard\x00entry-1") || r.Seen("adguard\x00entry-2") || r.Seen("zeek_intel\x00entry-1") {
		t.Fatal("Seen does not match what was remembered")
	}
	st.Close()

	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r = st.Records(time.Hour)
	if !r.Seen("adguard\x00entry-1") {
		t.Fatal("ledger lost on restart")
	}
	r.now = func() time.Time { return now.Add(30 * time.Minute) }
	r.Remember("adguard\x00entry-3")
	r.now = func() time.Time { return now.Add(61 * time.Minute) }
	if n, err := r.Prune(); err != nil || n != 1 {
		t.Errorf("Prune = %d, %v; want the one older than an hour", n, err)
	}
	if r.Seen("adguard\x00entry-1") || !r.Seen("adguard\x00entry-3") {
		t.Error("retention dropped the wrong record")
	}
}
