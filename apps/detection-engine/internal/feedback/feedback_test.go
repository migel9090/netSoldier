package feedback

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
)

type recordingSink struct {
	writes []Verdict
	err    error
}

func (r *recordingSink) Write(v Verdict) error {
	r.writes = append(r.writes, v)
	return r.err
}

const ioc = detection.SignalIoC

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

func TestRecordPersistsToSink(t *testing.T) {
	sink := &recordingSink{}
	s := New(sink)
	mustRecord(t, s, fp("x", "", ioc))
	if len(sink.writes) != 1 {
		t.Fatalf("expected 1 persisted verdict, got %d", len(sink.writes))
	}
	if sink.writes[0].Timestamp.IsZero() || sink.writes[0].SignalClass != ioc {
		t.Errorf("persisted %+v", sink.writes[0])
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

// TestPersistFailureIsReported: the verdict still applies, and the analyst
// is told it will not survive a restart.
func TestPersistFailureIsReported(t *testing.T) {
	s := New(&recordingSink{err: errors.New("clickhouse 516")})
	rec := post(s, `{"matched_ioc":"x.example","signal_class":"ioc","verdict":"false_positive"}`, "op")
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusAccepted || resp["persisted"] != false {
		t.Errorf("response %d %v, want 202 with persisted=false", rec.Code, resp)
	}
}

func TestHandleFeedbackRejectsOversizedBody(t *testing.T) {
	s := New(nil)
	huge := `{"matched_ioc":"` + strings.Repeat("a", maxFeedbackBody) + `"}`
	if rec := post(s, huge, ""); rec.Code == http.StatusAccepted {
		t.Fatal("an oversized body should not be accepted")
	}
}

func TestHandleList(t *testing.T) {
	s := New(nil)
	mustRecord(t, s, fp("x.example", "", ioc))
	rec := httptest.NewRecorder()
	s.HandleList(rec, httptest.NewRequest(http.MethodGet, "/feedback", nil))
	var got []Verdict
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 1 || got[0].SignalClass != ioc {
		t.Errorf("GET /feedback = %s (%v)", rec.Body, err)
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
// same-second tie goes to "confirmed".
func TestReplayLetsTheLaterVerdictWin(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	s := NewWithOptions(nil, Options{TTL: 30 * 24 * time.Hour})
	s.now = func() time.Time { return now }

	q := &fakeQuerier{rows: []string{
		row("c2.real-threat.example", "", ioc, VerdictFalsePositive, now.Add(-time.Hour)),
		row("c2.real-threat.example", "", ioc, VerdictConfirmed, now.Add(-time.Minute)),
		row("tie.example", "", ioc, VerdictFalsePositive, now.Add(-time.Minute)),
		row("tie.example", "", ioc, VerdictConfirmed, now.Add(-time.Minute)),
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
	if n != 5 {
		t.Errorf("loaded %d verdicts, want 5", n)
	}
	if !strings.Contains(q.query, "ORDER BY timestamp ASC, verdict = 'confirmed' ASC") {
		t.Errorf("replay must be ordered by recorded time with confirmed last on ties:\n%s", q.query)
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

func TestCHSinkWritesServerTimeAndClass(t *testing.T) {
	ins := &fakeInserter{}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	s := New(NewCHSink(ins))
	s.now = func() time.Time { return now }
	mustRecord(t, s, fp("x.example", "192.168.1.5", detection.SignalBeacon))

	b, _ := json.Marshal(ins.rows[0])
	if ins.table != "detection_feedback" ||
		!bytes.Contains(b, []byte(`"signal_class":"beacon"`)) ||
		!bytes.Contains(b, []byte(fmt.Sprintf(`"timestamp":%d`, now.Unix()))) {
		t.Errorf("inserted %s into %s", b, ins.table)
	}
}
