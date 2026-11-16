package store

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/libs/events"
)

func memStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func alert(n int, sev string) detection.Alert {
	return detection.Alert{
		ID: fmt.Sprintf("DET-t-%d", n), Timestamp: time.Now().UTC(), Summary: "s",
		Domain: "x.example", ClientIP: "192.168.1.5", MatchedIoC: "x.example",
		Severity: sev, SignalClass: detection.SignalIoC,
	}
}

func ids(as []detection.Alert) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}

func TestRecentIsNewestFirstWithLimit(t *testing.T) {
	a := memStore(t).Alerts(0, 0)
	for i := 1; i <= 5; i++ {
		if err := a.Add(alert(i, events.SeverityLow)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := a.Recent(3)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(ids(got)) != "[DET-t-5 DET-t-4 DET-t-3]" {
		t.Errorf("Recent(3) = %v, want the three newest, newest first", ids(got))
	}
	if al, ok := a.ByID("DET-t-2"); !ok || al.ClientIP != "192.168.1.5" {
		t.Errorf("ByID = %+v, %v", al, ok)
	}
	if _, ok := a.ByID("DET-t-99"); ok {
		t.Error("ByID found an alert that was never stored")
	}
}

// TestRecentIsBoundedForEveryCaller: only HandleList bounded the limit. A
// negative one panicked in make, and reached SQLite as "no limit"; a huge
// one was passed through.
func TestRecentIsBoundedForEveryCaller(t *testing.T) {
	a := memStore(t).Alerts(0, MaxListLimit+100)
	tx, err := a.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxListLimit+10; i++ {
		body, _ := json.Marshal(alert(i, events.SeverityLow))
		if _, err := tx.Exec(`INSERT INTO alerts (id, recorded_at, sev_rank, body) VALUES (?, ?, ?, ?)`,
			fmt.Sprintf("DET-t-%d", i), time.Now().UnixMilli(), 1, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{-1, 0, MaxListLimit + 1, 1 << 40} {
		got, err := a.Recent(limit)
		if err != nil {
			t.Fatalf("Recent(%d): %v", limit, err)
		}
		want := MaxListLimit
		if limit < 1 {
			want = 0
		}
		if len(got) != want || got == nil {
			t.Errorf("Recent(%d) returned %d alerts (nil=%v), want %d", limit, len(got), got == nil, want)
		}
	}
}

// TestHandleListSaysSuppressed: an alert recorded under an analyst's verdict
// carries "suppressed": true in GET /alerts; every other alert has no such
// key, so readers of the old shape see nothing new.
func TestHandleListSaysSuppressed(t *testing.T) {
	a := memStore(t).Alerts(0, 0)
	silenced := alert(1, events.SeverityHigh)
	silenced.Suppressed = true
	for _, al := range []detection.Alert{silenced, alert(2, events.SeverityHigh)} {
		if err := a.Add(al); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	a.HandleList(rec, httptest.NewRequest(http.MethodGet, "/alerts", nil))
	var raw []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil || len(raw) != 2 {
		t.Fatalf("GET /alerts = %q (%v)", rec.Body.String(), err)
	}
	byID := map[string]map[string]any{}
	for _, r := range raw {
		byID[r["id"].(string)] = r
	}
	if v, ok := byID["DET-t-1"]["suppressed"]; !ok || v != true {
		t.Errorf("suppressed alert: %v, want \"suppressed\": true", byID["DET-t-1"])
	}
	if v, ok := byID["DET-t-2"]["suppressed"]; ok {
		t.Errorf("an alert recorded without a verdict carries suppressed=%v", v)
	}
	if got, ok := a.ByID("DET-t-1"); !ok || !got.Suppressed {
		t.Errorf("ByID lost the mark: %+v", got)
	}
}

// TestHandleList: GET /alerts stays a JSON array of the alert shape — `[]`
// when empty, never null — with ?limit= validated and capped.
func TestHandleList(t *testing.T) {
	a := memStore(t).Alerts(0, 0)
	get := func(q string) (*httptest.ResponseRecorder, []detection.Alert) {
		rec := httptest.NewRecorder()
		a.HandleList(rec, httptest.NewRequest(http.MethodGet, "/alerts"+q, nil))
		var out []detection.Alert
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatalf("body %q: %v", rec.Body.String(), err)
			}
		}
		return rec, out
	}

	if rec, _ := get(""); rec.Body.String() != "[]\n" {
		t.Errorf("empty history = %q, want []", rec.Body.String())
	}
	for i := 1; i <= 3; i++ {
		_ = a.Add(alert(i, events.SeverityHigh))
	}
	if _, out := get(""); len(out) != 3 || out[0].ID != "DET-t-3" {
		t.Errorf("default list = %v", ids(out))
	}
	if _, out := get("?limit=1"); len(out) != 1 || out[0].ID != "DET-t-3" {
		t.Errorf("limit=1 = %v", ids(out))
	}
	if _, out := get(fmt.Sprintf("?limit=%d", MaxListLimit*10)); len(out) != 3 {
		t.Errorf("an oversized limit is capped, not refused: got %d", len(out))
	}
	for _, bad := range []string{"0", "-1", "x", "1e3"} {
		if rec, _ := get("?limit=" + bad); rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%s: status %d, want 400", bad, rec.Code)
		}
	}
}

// TestCompositesAreListed: composites never reached GET /alerts; they are
// detections in their own right and the actions they drive point at them.
func TestCompositesAreListed(t *testing.T) {
	a := memStore(t).Alerts(0, 0)
	_ = a.Add(alert(1, events.SeverityMedium))
	comp := alert(2, events.SeverityCritical)
	comp.SignalClass, comp.Source = detection.SignalComposite, "composite"
	_ = a.Add(comp)
	got, _ := a.Recent(10)
	if len(got) != 2 || got[0].SignalClass != detection.SignalComposite {
		t.Errorf("history = %+v, want the composite listed first", got)
	}
}

// TestFloodDoesNotEvictCriticalAlert: the 1000-entry ring let a burst of
// noise push real detections out of the UI. Over the cap, the least severe
// and oldest go first.
func TestFloodDoesNotEvictCriticalAlert(t *testing.T) {
	a := memStore(t).Alerts(0, 50)
	_ = a.Add(alert(0, events.SeverityCritical))
	for i := 1; i <= 500; i++ {
		_ = a.Add(alert(i, events.SeverityLow))
	}
	if _, err := a.Prune(); err != nil {
		t.Fatal(err)
	}
	all, _ := a.Recent(MaxListLimit)
	if len(all) > 50 {
		t.Errorf("history holds %d alerts, cap is 50", len(all))
	}
	if _, ok := a.ByID("DET-t-0"); !ok {
		t.Fatal("the critical alert was evicted by a flood of low-severity ones")
	}
	if all[0].ID != "DET-t-500" {
		t.Errorf("the newest low alerts should be the ones kept, newest = %s", all[0].ID)
	}
}

// TestRetentionUsesRecordedTime: the alert's own timestamp comes from a
// sensor; a row dated far in the future must still age out.
func TestRetentionUsesRecordedTime(t *testing.T) {
	a := memStore(t).Alerts(time.Hour, 0)
	now := time.Now()
	a.now = func() time.Time { return now }
	future := alert(1, events.SeverityHigh)
	future.Timestamp = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	_ = a.Add(future)
	_ = a.Add(alert(2, events.SeverityHigh))

	a.now = func() time.Time { return now.Add(2 * time.Hour) }
	n, err := a.Prune()
	if err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v; want both alerts aged out", n, err)
	}
}

// TestAlertsSurviveRestart: the history used to be lost on every restart.
func TestAlertsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "de.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Durable() || st.Path() != path {
		t.Errorf("Durable=%v Path=%q", st.Durable(), st.Path())
	}
	_ = st.Alerts(0, 0).Add(alert(7, events.SeverityHigh))
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if _, ok := st2.Alerts(0, 0).ByID("DET-t-7"); !ok {
		t.Fatal("alert lost across a restart")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("store file mode %v, want 0600: it lists what each device resolved", perm)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := Open(filepath.Join(t.TempDir(), "de.db?mode=ro")); err == nil {
		t.Error("a path that would be read as URI parameters was accepted")
	}
	// A regular file where the directory should be.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(blocker, "de.db")); err == nil {
		t.Error("unusable path accepted")
	}
}

func TestNewerSchemaIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "de.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(schema)+1)); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := Open(path); err == nil {
		t.Fatal("a store written by a newer binary must not be opened and misread")
	}
}
