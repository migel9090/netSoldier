package feedback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
)

const ioc = detection.SignalIoC

// diskStore opens a local store file that outlives the Store using it, as
// the service's volume outlives a process.
func diskStore(t *testing.T, path string) *store.Store {
	t.Helper()
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func journalFile(t *testing.T) string {
	return filepath.Join(t.TempDir(), "de.db")
}

func fp(matched, client, class string) Verdict {
	return Verdict{MatchedIoC: matched, ClientIP: client, SignalClass: class,
		Verdict: VerdictFalsePositive, Analyst: "tester"}
}

func confirmed(matched, client, class string) Verdict {
	v := fp(matched, client, class)
	v.Verdict = VerdictConfirmed
	return v
}

func alertOf(matched, client, class string) detection.Alert {
	return detection.Alert{MatchedIoC: matched, ClientIP: client, SignalClass: class}
}

func mustRecord(t *testing.T, s *Store, v Verdict) {
	t.Helper()
	if err := s.Record(v); err != nil {
		t.Fatal(err)
	}
}

func post(s *Store, body string, actor string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/feedback", strings.NewReader(body))
	if actor != "" {
		req.Header.Set("X-Netsoldier-Actor", actor)
	}
	rec := httptest.NewRecorder()
	s.HandleFeedback(rec, req)
	return rec
}

func TestRecordValidation(t *testing.T) {
	s := New(nil)
	for name, v := range map[string]Verdict{
		"no matched_ioc": {Verdict: VerdictFalsePositive, SignalClass: ioc, Analyst: "a"},
		"bad verdict":    {MatchedIoC: "x", Verdict: "bogus", SignalClass: ioc, Analyst: "a"},
		"no class":       {MatchedIoC: "x", Verdict: VerdictFalsePositive, Analyst: "a"},
		"unknown class":  {MatchedIoC: "x", Verdict: VerdictFalsePositive, SignalClass: "dga2", Analyst: "a"},
		"bad client":     {MatchedIoC: "x", ClientIP: "router", Verdict: VerdictFalsePositive, SignalClass: ioc, Analyst: "a"},
	} {
		if err := s.Record(v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFalsePositiveSuppressesScopedToClient(t *testing.T) {
	s := New(nil)
	mustRecord(t, s, fp("cdn.example", "192.168.1.5", ioc))
	if !s.Suppressed(alertOf("cdn.example", "192.168.1.5", ioc)) {
		t.Error("verdict should suppress the same (ioc, client, class)")
	}
	if s.Suppressed(alertOf("cdn.example", "192.168.1.9", ioc)) {
		t.Error("client-scoped verdict must not suppress a different client")
	}
}

func TestIndicatorWideSuppression(t *testing.T) {
	s := New(nil)
	mustRecord(t, s, fp("benign.example", "", ioc))
	if !s.Suppressed(alertOf("benign.example", "10.0.0.2", ioc)) {
		t.Error("indicator-wide verdict should suppress any client")
	}
}

func TestMatchIsCaseInsensitive(t *testing.T) {
	s := New(nil)
	mustRecord(t, s, fp("Evil.Example", "", ioc))
	if !s.Suppressed(alertOf("evil.example", "", ioc)) {
		t.Error("suppression match should be case-insensitive")
	}
	if s.Suppressed(alertOf("", "", ioc)) {
		t.Error("an alert without an indicator matched a suppression")
	}
}

// TestKeyIncludesSignalClass: the key was the bare indicator, so marking a
// beacon to a vendor's telemetry host benign also silenced a feed listing
// the same host.
func TestKeyIncludesSignalClass(t *testing.T) {
	s := New(nil)
	mustRecord(t, s, fp("telemetry.vendor.example", "192.168.1.50", detection.SignalBeacon))
	if !s.Suppressed(alertOf("telemetry.vendor.example", "192.168.1.50", detection.SignalBeacon)) {
		t.Fatal("the beacon verdict should suppress the beacon")
	}
	if s.Suppressed(alertOf("telemetry.vendor.example", "192.168.1.50", ioc)) {
		t.Error("a beacon verdict silenced a feed match on the same name")
	}
}

func TestConfirmedClearsSuppression(t *testing.T) {
	s := New(nil)
	a := alertOf("x", "192.168.1.5", ioc)
	mustRecord(t, s, fp("x", "192.168.1.5", ioc))
	if !s.Suppressed(a) {
		t.Fatal("should be suppressed after FP")
	}
	mustRecord(t, s, confirmed("x", "192.168.1.5", ioc))
	if s.Suppressed(a) {
		t.Error("confirmed verdict should clear the suppression")
	}
}

// TestConfirmedForOneClientLiftsIndicatorWideSuppression: "confirmed for
// this device" left the device silenced by an indicator-wide verdict.
func TestConfirmedForOneClientLiftsIndicatorWideSuppression(t *testing.T) {
	s := New(nil)
	mustRecord(t, s, fp("c2.example", "", ioc))
	mustRecord(t, s, confirmed("c2.example", "192.168.1.77", ioc))
	if s.Suppressed(alertOf("c2.example", "192.168.1.77", ioc)) {
		t.Fatal("a confirmed verdict did not end the suppression for its client")
	}

	// Confirmed with no client ends client-scoped verdicts everywhere, for
	// that class only.
	mustRecord(t, s, fp("c3.example", "192.168.1.5", ioc))
	mustRecord(t, s, fp("c3.example", "192.168.1.6", ioc))
	mustRecord(t, s, fp("c3.example", "192.168.1.6", detection.SignalTLS))
	mustRecord(t, s, confirmed("C3.example", "", ioc))
	for _, a := range []detection.Alert{alertOf("c3.example", "192.168.1.5", ioc), alertOf("c3.example", "192.168.1.6", ioc)} {
		if s.Suppressed(a) {
			t.Errorf("still suppressed after an indicator-wide confirm: %+v", a)
		}
	}
	if !s.Suppressed(alertOf("c3.example", "192.168.1.6", detection.SignalTLS)) {
		t.Error("confirming the ioc class lifted a TLS-class verdict")
	}
}

func TestRecordWritesTheJournal(t *testing.T) {
	st := diskStore(t, journalFile(t))
	s := New(st.Feedback())
	mustRecord(t, s, fp("x", "", ioc))
	var rows []store.FeedbackRow
	if err := st.Feedback().Replay(time.Time{}, func(r store.FeedbackRow) error {
		rows = append(rows, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].RecordedAt.IsZero() || rows[0].SignalClass != ioc || rows[0].Analyst != "tester" {
		t.Fatalf("journal holds %+v, want the one verdict", rows)
	}
}

func TestActiveSnapshot(t *testing.T) {
	s := New(nil)
	mustRecord(t, s, fp("a", "", ioc))
	mustRecord(t, s, fp("b", "10.0.0.1", ioc))
	if got := len(s.Active()); got != 2 {
		t.Errorf("active suppressions = %d, want 2", got)
	}
}

func TestRecordRequiresAnalyst(t *testing.T) {
	s := New(nil)
	v := fp("x", "", ioc)
	v.Analyst = ""
	if err := s.Record(v); err == nil {
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

	mustRecord(t, s, fp("cdn.example", "", ioc))
	alert := alertOf("cdn.example", "", ioc)
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

// TestClientTimestampIsIgnored: POST /feedback took the verdict's time from
// the body, so a verdict dated 2099 never aged out — indicator-wide, for
// every client, for good.
func TestClientTimestampIsIgnored(t *testing.T) {
	s := NewWithOptions(nil, Options{TTL: 30 * 24 * time.Hour})
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }

	body := `{"matched_ioc":"c2.real-threat.example","signal_class":"ioc","verdict":"false_positive","timestamp":"2099-01-01T00:00:00Z"}`
	if rec := post(s, body, "analyst@ui"); rec.Code != http.StatusAccepted {
		t.Fatalf("POST /feedback = %d %s", rec.Code, rec.Body)
	}
	if got := s.Active()[0].Timestamp; !got.Equal(now) {
		t.Fatalf("recorded timestamp = %v, want the server's %v", got, now)
	}
	// Record itself ignores a caller's timestamp too.
	v := fp("other.example", "", ioc)
	v.Timestamp = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	mustRecord(t, s, v)

	alert := alertOf("c2.real-threat.example", "192.168.1.77", ioc)
	s.now = func() time.Time { return now.Add(31 * 24 * time.Hour) }
	if s.Suppressed(alert) || s.Suppressed(alertOf("other.example", "", ioc)) {
		t.Fatal("a verdict outlived the 30-day TTL")
	}
}

func TestExpiredVerdictNotReplayedOnStartup(t *testing.T) {
	s := NewWithOptions(nil, Options{TTL: time.Hour})
	now := time.Now()
	s.now = func() time.Time { return now }

	// ClickHouse handing back a verdict from last year.
	v := fp("old.example", "", ioc)
	v.Timestamp = now.Add(-365 * 24 * time.Hour)
	if err := s.applyLoaded(v); err != nil {
		t.Fatal(err)
	}
	if s.Suppressed(alertOf("old.example", "", ioc)) {
		t.Fatal("a stale persisted verdict must not re-blind the pipeline on restart")
	}
}

func TestSuppressionCapRejectsOverflow(t *testing.T) {
	s := NewWithOptions(nil, Options{MaxSuppressions: 2})
	mustRecord(t, s, fp("a.example", "", ioc))
	mustRecord(t, s, fp("b.example", "", ioc))
	if err := s.Record(fp("c.example", "", ioc)); err == nil {
		t.Fatal("exceeding the suppression cap must be rejected, not grow the map " +
			"without bound")
	}
	// Updating an existing suppression is still allowed at the cap.
	v := fp("a.example", "", ioc)
	v.Analyst = "tester2"
	if err := s.Record(v); err != nil {
		t.Errorf("updating an existing suppression at the cap should succeed: %v", err)
	}
	// Replay obeys the cap as well.
	r := fp("d.example", "", ioc)
	r.Timestamp = time.Now()
	_ = s.applyLoaded(r)
	if len(s.Active()) != 2 {
		t.Errorf("replay exceeded the cap: %d", len(s.Active()))
	}
}

// TestFieldLimitsMakeTheCapASizeCap: each verdict could carry the whole
// 64 KiB body (2000 verdicts retained 126 MiB, ~629 MiB at the cap).
func TestFieldLimitsMakeTheCapASizeCap(t *testing.T) {
	s := New(nil)
	pad := strings.Repeat("A", 63<<10)
	for i := 0; i < 20; i++ {
		body := fmt.Sprintf(`{"matched_ioc":"x%d.example","signal_class":"ioc","verdict":"false_positive","reason":%q}`, i, pad)
		if rec := post(s, body, "lan-guest"); rec.Code != http.StatusBadRequest {
			t.Fatalf("a 63 KiB reason was answered %d", rec.Code)
		}
	}
	if len(s.Active()) != 0 {
		t.Fatal("oversized verdicts were stored")
	}

	for name, v := range map[string]Verdict{
		"indicator": {MatchedIoC: strings.Repeat("a", MaxIndicatorLen+1)},
		"alert_id":  {AlertID: strings.Repeat("1", MaxAlertIDLen+1)},
		"reason":    {Reason: strings.Repeat("r", MaxReasonLen+1)},
		"analyst":   {Analyst: strings.Repeat("n", MaxAnalystLen+1)},
	} {
		base := fp("x.example", "", ioc)
		if v.MatchedIoC != "" {
			base.MatchedIoC = v.MatchedIoC
		}
		if v.AlertID != "" {
			base.AlertID = v.AlertID
		}
		if v.Reason != "" {
			base.Reason = v.Reason
		}
		if v.Analyst != "" {
			base.Analyst = v.Analyst
		}
		if err := s.Record(base); err == nil {
			t.Errorf("%s over its limit was accepted", name)
		}
	}

	// At the limits a verdict stays small, so the count cap bounds memory.
	const perVerdict = MaxIndicatorLen + 45 + MaxAlertIDLen + MaxReasonLen + MaxAnalystLen
	if total := perVerdict * DefaultMaxSuppressions; total > 16<<20 {
		t.Errorf("caller data at the cap can reach %d MiB", total>>20)
	}
}

func TestHandleFeedbackUsesAuthenticatedActor(t *testing.T) {
	s := New(nil)
	body := `{"matched_ioc":"cdn.example","signal_class":"ioc","verdict":"false_positive","analyst":"spoofed"}`
	if rec := post(s, body, "real-operator"); rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
	active := s.Active()
	if len(active) != 1 {
		t.Fatalf("expected 1 suppression, got %d", len(active))
	}
	if active[0].Analyst != "real-operator" {
		t.Errorf("analyst should come from the authenticated identity, got %q", active[0].Analyst)
	}
}

// TestAlertIDScopesTheVerdict: the web UI posts alert_id, matched_ioc and
// client_ip. The class comes from the alert the analyst looked at.
func TestAlertIDScopesTheVerdict(t *testing.T) {
	stored := map[string]detection.Alert{
		"DET-x-1": {ID: "DET-x-1", MatchedIoC: "cdn.example", SignalClass: detection.SignalTLS},
	}
	s := NewWithOptions(nil, Options{AlertLookup: func(id string) (detection.Alert, bool) {
		a, ok := stored[id]
		return a, ok
	}})
	rec := post(s, `{"alert_id":"DET-x-1","matched_ioc":"cdn.example","client_ip":"192.168.1.5","verdict":"false_positive"}`, "op")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if !s.Suppressed(alertOf("cdn.example", "192.168.1.5", detection.SignalTLS)) ||
		s.Suppressed(alertOf("cdn.example", "192.168.1.5", ioc)) {
		t.Error("the verdict is not scoped to the stored alert's class")
	}
	rec = post(s, `{"alert_id":"DET-x-404","matched_ioc":"cdn.example","verdict":"false_positive"}`, "op")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "signal_class") {
		t.Errorf("unknown alert and no class: %d %s", rec.Code, rec.Body)
	}
}

func persistedFlag(t *testing.T, rec *httptest.ResponseRecorder) any {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response %d %q: %v", rec.Code, rec.Body, err)
	}
	return resp["persisted"]
}

// TestPersistedMeansOnDisk: without ClickHouse, POST /feedback answered
// persisted=true while the verdict existed only in memory, so in the lite
// profile a suppression vanished at the next restart with the analyst told
// it was saved. persisted is true only when the local store has the verdict
// on disk.
func TestPersistedMeansOnDisk(t *testing.T) {
	const body = `{"matched_ioc":"x.example","signal_class":"ioc","verdict":"false_positive"}`

	if rec := post(New(nil), body, "op"); rec.Code != http.StatusAccepted || persistedFlag(t, rec) != false {
		t.Errorf("no local store: %d persisted=%v, want 202 and false", rec.Code, persistedFlag(t, rec))
	}

	mem, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer mem.Close()
	if rec := post(New(mem.Feedback()), body, "op"); persistedFlag(t, rec) != false {
		t.Errorf("an in-memory store is not durable: persisted=%v", persistedFlag(t, rec))
	}

	st := diskStore(t, journalFile(t))
	if rec := post(New(st.Feedback()), body, "op"); persistedFlag(t, rec) != true {
		t.Errorf("on disk: persisted=%v, want true", persistedFlag(t, rec))
	}

	// The store failing: the verdict still applies, and the analyst is told
	// it will not survive a restart.
	broken := diskStore(t, journalFile(t))
	s := New(broken.Feedback())
	broken.Close()
	rec := post(s, body, "op")
	if rec.Code != http.StatusAccepted || persistedFlag(t, rec) != false {
		t.Errorf("store failure: %d persisted=%v, want 202 and false", rec.Code, persistedFlag(t, rec))
	}
	if !s.Suppressed(alertOf("x.example", "", ioc)) {
		t.Error("a verdict the store could not take must still apply")
	}
}

func TestHandleFeedbackRejectsOversizedBody(t *testing.T) {
	s := New(nil)
	huge := `{"matched_ioc":"` + strings.Repeat("a", maxFeedbackBody) + `"}`
	if rec := post(s, huge, ""); rec.Code == http.StatusAccepted {
		t.Fatal("an oversized body should not be accepted")
	}
}

func getList(t *testing.T, s *Store) []map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	s.HandleList(rec, httptest.NewRequest(http.MethodGet, "/feedback", nil))
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET /feedback = %s (%v)", rec.Body, err)
	}
	return got
}

// TestHandleListSaysWhenEachSuppressionExpires: the UI had to assume the
// default TTL to tell the analyst when a suppression ends.
func TestHandleListSaysWhenEachSuppressionExpires(t *testing.T) {
	s := NewWithOptions(nil, Options{TTL: 48 * time.Hour})
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	mustRecord(t, s, fp("old.example", "", ioc))
	now = now.Add(time.Hour)
	mustRecord(t, s, fp("new.example", "192.168.1.5", ioc))

	got := getList(t, s)
	if len(got) != 2 {
		t.Fatalf("GET /feedback = %v", got)
	}
	// Most recent first.
	for i, want := range []struct {
		ioc     string
		expires time.Time
	}{
		{"new.example", now.Add(48 * time.Hour)},
		{"old.example", now.Add(-time.Hour).Add(48 * time.Hour)},
	} {
		exp, err := time.Parse(time.RFC3339Nano, fmt.Sprint(got[i]["expires_at"]))
		if got[i]["matched_ioc"] != want.ioc || err != nil || !exp.Equal(want.expires) {
			t.Errorf("entry %d: %v, want %s expiring at %v", i, got[i], want.ioc, want.expires)
		}
		if got[i]["signal_class"] != ioc || got[i]["verdict"] != VerdictFalsePositive || got[i]["timestamp"] == nil {
			t.Errorf("entry %d lost a verdict field: %v", i, got[i])
		}
	}
}

// fakeQuerier hands back rows in the order ClickHouse would, given the
// query's ORDER BY.
type fakeQuerier struct {
	rows  []string
	query string
	err   error
}

func (f *fakeQuerier) QueryJSONEachRow(_ context.Context, q string, fn func(json.RawMessage) error) error {
	f.query = q
	for _, r := range f.rows {
		if err := fn(json.RawMessage(r)); err != nil {
			return err
		}
	}
	return f.err
}

func row(ioc, client, class, verdict string, ts time.Time) string {
	b, _ := json.Marshal(map[string]any{"matched_ioc": ioc, "client_ip": client, "signal_class": class,
		"verdict": verdict, "analyst": "a", "reason": "", "ts": fmt.Sprint(ts.Unix())})
	return string(b)
}

// TestReplayLetsTheLaterVerdictWin: replay used argMax(verdict, timestamp),
// so a false positive dated 2099 beat a "confirmed" made today. Now the
// replay is in server-recorded order, future-dated rows are ignored, and a
// same-second tie goes to whatever ends the suppression ("confirmed", or a
// lift).
func TestReplayLetsTheLaterVerdictWin(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewWithOptions(nil, Options{TTL: 30 * 24 * time.Hour})
	s.now = func() time.Time { return now }

	q := &fakeQuerier{rows: []string{
		row("c2.real-threat.example", "", ioc, VerdictFalsePositive, now.Add(-time.Hour)),
		row("c2.real-threat.example", "", ioc, VerdictConfirmed, now.Add(-time.Minute)),
		row("tie.example", "", ioc, VerdictFalsePositive, now.Add(-time.Minute)),
		row("tie.example", "", ioc, VerdictConfirmed, now.Add(-time.Minute)),
		row("lifted.example", "", ioc, VerdictFalsePositive, now.Add(-time.Minute)),
		row("lifted.example", "", ioc, VerdictLifted, now.Add(-time.Minute)),
		row("benign.example", "192.168.1.5", ioc, VerdictFalsePositive, now.Add(-time.Minute)),
		row("forged.example", "", ioc, VerdictFalsePositive, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)),
		row("legacy.example", "", "", VerdictFalsePositive, now.Add(-time.Minute)),
		`{"matched_ioc":"bad-ts","ts":"x"}`,
		`not json`,
	}}
	n, err := LoadInto(context.Background(), q, s)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Errorf("loaded %d verdicts, want 7", n)
	}
	if !strings.Contains(q.query, "ORDER BY timestamp ASC, verdict = 'false_positive' DESC") {
		t.Errorf("replay must be ordered by recorded time with false positives first on ties:\n%s", q.query)
	}
	if s.Suppressed(alertOf("lifted.example", "192.168.1.77", ioc)) {
		t.Error("a lift in the same second as its false positive did not end it")
	}
	if !strings.Contains(q.query, fmt.Sprintf("INTERVAL %d SECOND", int((30*24*time.Hour).Seconds()))) {
		t.Errorf("replay should only read verdicts inside the TTL:\n%s", q.query)
	}
	for ind, want := range map[string]bool{
		"c2.real-threat.example": false, "tie.example": false, "forged.example": false,
		"legacy.example": false,
	} {
		if got := s.Suppressed(alertOf(ind, "192.168.1.77", ioc)); got != want {
			t.Errorf("%s suppressed = %v after replay, want %v", ind, got, want)
		}
	}
	if !s.Suppressed(alertOf("benign.example", "192.168.1.5", ioc)) {
		t.Error("a valid verdict was not replayed")
	}

	q.err = errors.New("clickhouse 516")
	if _, err := LoadInto(context.Background(), q, NewWithOptions(nil, Options{})); err == nil {
		t.Error("a failed replay must be reported")
	}
}

type fakeInserter struct {
	table string
	rows  []any
}

func (f *fakeInserter) Insert(_ context.Context, table string, rows ...any) error {
	f.table, f.rows = table, rows
	return nil
}

// TestVerdictSurvivesARestartWithoutClickHouse is the lite profile: no
// ClickHouse at all. A false positive recorded before a restart still
// suppresses after it, with the semantics a live process has — server
// timestamps, the TTL, the signal class in the key, a later "confirmed"
// ending a suppression, replay in the order the server recorded.
func TestVerdictSurvivesARestartWithoutClickHouse(t *testing.T) {
	path := journalFile(t)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	st := diskStore(t, path)
	s := NewWithOptions(st.Feedback(), Options{TTL: 24 * time.Hour})
	s.now = clock
	mustRecord(t, s, fp("stale.example", "", ioc))
	now = now.Add(23 * time.Hour)
	mustRecord(t, s, fp("telemetry.vendor.example", "192.168.1.50", detection.SignalBeacon))
	// Within one millisecond the order they were made in decides.
	mustRecord(t, s, fp("c2.example", "", ioc))
	mustRecord(t, s, confirmed("c2.example", "192.168.1.77", ioc))
	mustRecord(t, s, confirmed("reborn.example", "", ioc))
	mustRecord(t, s, fp("reborn.example", "", ioc))
	st.Close()

	now = now.Add(2 * time.Hour) // stale.example is past its TTL, the others are not
	st2 := diskStore(t, path)
	s2 := NewWithOptions(st2.Feedback(), Options{TTL: 24 * time.Hour})
	s2.now = clock
	res, err := s2.Restore(context.Background(), nil)
	if err != nil || res.Replayed != 5 || res.Imported != 0 {
		t.Fatalf("Restore = %+v, %v", res, err)
	}
	for _, c := range []struct {
		alert detection.Alert
		want  bool
	}{
		{alertOf("telemetry.vendor.example", "192.168.1.50", detection.SignalBeacon), true},
		{alertOf("telemetry.vendor.example", "192.168.1.50", ioc), false}, // another class
		{alertOf("telemetry.vendor.example", "192.168.1.51", detection.SignalBeacon), false},
		{alertOf("stale.example", "192.168.1.9", ioc), false}, // past its TTL
		{alertOf("c2.example", "192.168.1.77", ioc), false},   // the confirmed ended it
		{alertOf("reborn.example", "192.168.1.9", ioc), true}, // the later word
	} {
		if got := s2.Suppressed(c.alert); got != c.want {
			t.Errorf("%s/%s on %s: suppressed=%v after restart, want %v",
				c.alert.MatchedIoC, c.alert.SignalClass, c.alert.ClientIP, got, c.want)
		}
	}
	for _, v := range s2.Active() {
		if !v.Timestamp.Equal(now.Add(-2*time.Hour)) || v.Analyst != "tester" {
			t.Errorf("restored %+v, want it as it was recorded", v)
		}
	}
}

// TestRestoreCapsAndValidates: replay keeps the cap and refuses what is not
// valid or dated in the future.
func TestRestoreCapsAndValidates(t *testing.T) {
	path := journalFile(t)
	now := time.Now().UTC()
	st := diskStore(t, path)
	j := st.Feedback()
	for _, r := range []store.FeedbackRow{
		{RecordedAt: now, MatchedIoC: "a.example", SignalClass: ioc, Verdict: VerdictFalsePositive, Analyst: "x"},
		{RecordedAt: now, MatchedIoC: "b.example", SignalClass: ioc, Verdict: VerdictFalsePositive, Analyst: "x"},
		{RecordedAt: now, MatchedIoC: "c.example", SignalClass: ioc, Verdict: VerdictFalsePositive, Analyst: "x"},
		{RecordedAt: now.Add(time.Hour), MatchedIoC: "future.example", SignalClass: ioc, Verdict: VerdictFalsePositive, Analyst: "x"},
		{RecordedAt: now, MatchedIoC: "bad.example", SignalClass: "dga2", Verdict: VerdictFalsePositive, Analyst: "x"},
	} {
		if _, err := j.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	s := NewWithOptions(j, Options{MaxSuppressions: 2})
	if _, err := s.Restore(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := len(s.Active()); got != 2 {
		t.Errorf("restored %d suppressions, cap 2", got)
	}
	if s.Suppressed(alertOf("future.example", "", ioc)) {
		t.Error("a verdict dated in the future was restored")
	}
}

// TestRestoreImportsClickHouseHistoryOnce: verdicts used to be kept in
// ClickHouse only. The first start with a local journal seeds it from
// there, once; from then on the journal is the record.
func TestRestoreImportsClickHouseHistoryOnce(t *testing.T) {
	path := journalFile(t)
	now := time.Now().UTC().Truncate(time.Second)
	q := &fakeQuerier{rows: []string{
		row("benign.example", "192.168.1.5", ioc, VerdictFalsePositive, now.Add(-2*time.Hour)),
		row("ended.example", "", ioc, VerdictFalsePositive, now.Add(-2*time.Hour)),
		row("ended.example", "", ioc, VerdictConfirmed, now.Add(-time.Hour)),
	}}

	st := diskStore(t, path)
	s := New(st.Feedback())
	res, err := s.Restore(context.Background(), q)
	if err != nil || res.Imported != 3 {
		t.Fatalf("first start: %+v %v", res, err)
	}
	if !s.Suppressed(alertOf("benign.example", "192.168.1.5", ioc)) || s.Suppressed(alertOf("ended.example", "", ioc)) {
		t.Fatal("the imported history was not applied")
	}
	// Already in ClickHouse: not copied there again.
	if n, _ := st.Feedback().Unforwarded(); n != 0 {
		t.Errorf("%d imported verdicts queued for ClickHouse", n)
	}
	st.Close()

	q.query = ""
	st2 := diskStore(t, path)
	s2 := New(st2.Feedback())
	res, err = s2.Restore(context.Background(), q)
	if err != nil || res.Imported != 0 || res.Replayed != 1 || q.query != "" {
		t.Fatalf("second start: %+v %v, ClickHouse asked %q", res, err, q.query)
	}
	if !s2.Suppressed(alertOf("benign.example", "192.168.1.5", ioc)) {
		t.Error("the imported suppression did not survive the next restart")
	}

	// A failed import is retried by the next start, not taken for "nothing".
	st3 := diskStore(t, journalFile(t))
	down := &fakeQuerier{err: errors.New("clickhouse 516")}
	if _, err := New(st3.Feedback()).Restore(context.Background(), down); err == nil {
		t.Error("a failed import must be reported")
	}
	if fresh, _ := st3.Feedback().Fresh(); !fresh {
		t.Error("a failed import must leave the journal to be seeded again")
	}
}

func lift(s *Store, body, actor string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/feedback/lift", strings.NewReader(body))
	if actor != "" {
		req.Header.Set("X-Netsoldier-Actor", actor)
	}
	rec := httptest.NewRecorder()
	s.HandleLift(rec, req)
	return rec
}

// TestLiftEndsExactlyOneSuppression: the UI lifted a suppression by sending
// "confirmed", which records the indicator as a true positive and ends the
// indicator's suppressions on every device. A lift ends the one it names,
// says nothing about the indicator, and survives a restart.
func TestLiftEndsExactlyOneSuppression(t *testing.T) {
	path := journalFile(t)
	st := diskStore(t, path)
	s := New(st.Feedback())
	mustRecord(t, s, fp("cdn.example", "", ioc))
	mustRecord(t, s, fp("cdn.example", "192.168.1.5", ioc))
	mustRecord(t, s, fp("cdn.example", "192.168.1.5", detection.SignalTLS))

	rec := lift(s, `{"matched_ioc":"CDN.example","client_ip":"192.168.1.5","signal_class":"ioc","reason":"wrong device","analyst":"spoofed"}`, "carol")
	if rec.Code != http.StatusOK || persistedFlag(t, rec) != true {
		t.Fatalf("lift = %d %s", rec.Code, rec.Body)
	}
	got := map[string]bool{}
	for _, v := range s.Active() {
		got[v.ClientIP+"/"+v.SignalClass] = true
	}
	if len(got) != 2 || !got["/ioc"] || !got["192.168.1.5/tls"] {
		t.Errorf("after the lift %v remain, want the indicator-wide ioc and the client's tls ones", got)
	}

	// Nothing in force under that key any more: 404, nothing recorded.
	if rec := lift(s, `{"matched_ioc":"cdn.example","client_ip":"192.168.1.5","signal_class":"ioc"}`, "carol"); rec.Code != http.StatusNotFound {
		t.Errorf("lifting what is not suppressed: %d %s", rec.Code, rec.Body)
	}
	for body, want := range map[string]int{
		`{"matched_ioc":"cdn.example","signal_class":"ioc"}`:                      http.StatusBadRequest, // no actor
		`{"matched_ioc":"cdn.example"}`:                                           http.StatusBadRequest,
		`{"matched_ioc":"cdn.example","signal_class":"x"}`:                        http.StatusBadRequest,
		`{"matched_ioc":"cdn.example","client_ip":"router","signal_class":"ioc"}`: http.StatusBadRequest,
		`not json`: http.StatusBadRequest,
	} {
		if rec := lift(s, body, ""); rec.Code != want {
			t.Errorf("lift %s = %d, want %d", body, rec.Code, want)
		}
	}
	// POST /feedback does not take "lifted" as a verdict.
	if rec := post(s, `{"matched_ioc":"cdn.example","signal_class":"ioc","verdict":"lifted"}`, "carol"); rec.Code != http.StatusBadRequest {
		t.Errorf(`POST /feedback with verdict "lifted" = %d`, rec.Code)
	}

	var rows []store.FeedbackRow
	_ = st.Feedback().Replay(time.Time{}, func(r store.FeedbackRow) error { rows = append(rows, r); return nil })
	if last := rows[len(rows)-1]; last.Verdict != VerdictLifted || last.Analyst != "carol" ||
		last.Reason != "wrong device" || last.ClientIP != "192.168.1.5" {
		t.Errorf("the lift was journaled as %+v", last)
	}

	st.Close()
	s2 := New(diskStore(t, path).Feedback())
	if _, err := s2.Restore(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if s2.Suppressed(alertOf("cdn.example", "192.168.1.5", detection.SignalTLS)) != true ||
		len(s2.Active()) != 2 {
		t.Errorf("after a restart: %+v, want the two suppressions the lift left", s2.Active())
	}
	for _, v := range s2.Active() {
		if v.ClientIP == "192.168.1.5" && v.SignalClass == ioc {
			t.Error("the lifted suppression came back after a restart")
		}
	}
}

// TestJournalIsBounded: repeating a verdict adds a journal row but no
// suppression. Past MaxJournal the journal is compacted to the verdicts in
// force, and replaying it still gives exactly those.
func TestJournalIsBounded(t *testing.T) {
	path := journalFile(t)
	st := diskStore(t, path)
	s := NewWithOptions(st.Feedback(), Options{MaxJournal: 20})
	for i := 0; i < 50; i++ {
		mustRecord(t, s, fp("noisy.example", "", ioc))
		if i%10 == 0 {
			mustRecord(t, s, confirmed("noisy.example", "", ioc))
		}
	}
	mustRecord(t, s, fp("other.example", "192.168.1.5", ioc))
	mustRecord(t, s, fp("ended.example", "", ioc))
	mustRecord(t, s, confirmed("ended.example", "", ioc))
	before := s.Active()

	s.Maintain()
	if n, _ := st.Feedback().Count(); n != len(before) {
		t.Errorf("journal holds %d rows after compaction, want the %d in force", n, len(before))
	}
	st.Close()
	s2 := New(diskStore(t, path).Feedback())
	if _, err := s2.Restore(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := s2.Active(); len(got) != len(before) || !s2.Suppressed(alertOf("noisy.example", "", ioc)) ||
		!s2.Suppressed(alertOf("other.example", "192.168.1.5", ioc)) || s2.Suppressed(alertOf("ended.example", "", ioc)) {
		t.Errorf("after compaction and a restart: %+v, want %+v", got, before)
	}
}

// TestJournalKeepsWhatClickHouseLacks: with forwarding, nothing is forgotten
// before ClickHouse has it — neither by age nor by compaction.
func TestJournalKeepsWhatClickHouseLacks(t *testing.T) {
	st := diskStore(t, journalFile(t))
	s := NewWithOptions(st.Feedback(), Options{TTL: time.Hour, MaxJournal: 1, Forwarding: true})
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	mustRecord(t, s, fp("a.example", "", ioc))
	mustRecord(t, s, confirmed("a.example", "", ioc))
	now = now.Add(2 * time.Hour)
	s.Maintain()
	if n, _ := st.Feedback().Count(); n != 2 {
		t.Fatalf("journal holds %d rows, want both verdicts ClickHouse has not got", n)
	}
	ins := &fakeInserter{}
	f := NewForwarder(st.Feedback(), NewCHSink(ins))
	for f.step(context.Background()) {
	}
	s.Maintain()
	if n, _ := st.Feedback().Count(); n != 0 {
		t.Errorf("journal holds %d rows once copied and past the TTL", n)
	}
}

// flakySink fails its first writes.
type flakySink struct {
	fail int
	got  []Verdict
}

func (f *flakySink) Write(_ context.Context, v Verdict) error {
	if f.fail > 0 {
		f.fail--
		return errors.New("clickhouse 516")
	}
	f.got = append(f.got, v)
	return nil
}

// TestForwarderCopiesInOrderAndRetries: a verdict is marked copied only
// once ClickHouse accepted it, failures back off, and nothing overtakes the
// verdict being retried.
func TestForwarderCopiesInOrderAndRetries(t *testing.T) {
	st := diskStore(t, journalFile(t))
	s := New(st.Feedback())
	mustRecord(t, s, fp("first.example", "", ioc))
	mustRecord(t, s, fp("second.example", "", ioc))

	sink := &flakySink{fail: 1}
	f := NewForwarder(st.Feedback(), sink)
	now := time.Now()
	f.now = func() time.Time { return now }
	if f.step(context.Background()) {
		t.Fatal("a failed copy reported success")
	}
	if f.step(context.Background()) || len(sink.got) != 0 {
		t.Fatalf("a verdict overtook the one backing off: %+v", sink.got)
	}
	now = now.Add(forwardBase)
	for f.step(context.Background()) {
	}
	if len(sink.got) != 2 || sink.got[0].MatchedIoC != "first.example" || sink.got[1].MatchedIoC != "second.example" {
		t.Fatalf("copied %+v, want both in order", sink.got)
	}
	if n, _ := st.Feedback().Unforwarded(); n != 0 {
		t.Errorf("%d verdicts still queued", n)
	}
	if backoff(forwardBase, forwardMax, 1) != forwardBase || backoff(forwardBase, forwardMax, 30) != forwardMax {
		t.Error("backoff schedule")
	}

	// Run wakes on Notify and stops with its context.
	sink2 := &flakySink{}
	f2 := NewForwarder(st.Feedback(), sink2)
	f2.idle = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); f2.Run(ctx) }()
	s2 := NewWithOptions(st.Feedback(), Options{Notify: f2.Notify})
	mustRecord(t, s2, fp("third.example", "", ioc))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n, _ := st.Feedback().Unforwarded(); n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Notify did not wake the forwarder")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestCHSinkWritesServerTimeAndClass(t *testing.T) {
	ins := &fakeInserter{}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	st := diskStore(t, journalFile(t))
	s := New(st.Feedback())
	s.now = func() time.Time { return now }
	mustRecord(t, s, fp("x.example", "192.168.1.5", detection.SignalBeacon))
	f := NewForwarder(st.Feedback(), NewCHSink(ins))
	if !f.step(context.Background()) {
		t.Fatal("nothing was copied")
	}

	b, _ := json.Marshal(ins.rows[0])
	if ins.table != "detection_feedback" ||
		!bytes.Contains(b, []byte(`"signal_class":"beacon"`)) ||
		!bytes.Contains(b, []byte(fmt.Sprintf(`"timestamp":%d`, now.Unix()))) {
		t.Errorf("inserted %s into %s", b, ins.table)
	}
}
