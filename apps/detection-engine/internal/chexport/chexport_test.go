package chexport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// fakeCH records inserts; fail makes the next n inserts fail.
type fakeCH struct {
	mu    sync.Mutex
	rows  map[string][]any
	calls int
	fail  int
	block chan struct{} // when set, an insert waits for it
}

func (f *fakeCH) Insert(ctx context.Context, table string, rows ...any) error {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.fail > 0 {
		f.fail--
		return errors.New("clickhouse 503: unavailable")
	}
	if f.rows == nil {
		f.rows = map[string][]any{}
	}
	f.rows[table] = append(f.rows[table], rows...)
	return nil
}

func (f *fakeCH) table(name string) []any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]any(nil), f.rows[name]...)
}

func counter(t *testing.T, c prometheus.Collector) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.(prometheus.Metric).Write(m); err != nil {
		t.Fatal(err)
	}
	if m.Counter != nil {
		return m.GetCounter().GetValue()
	}
	return m.GetGauge().GetValue()
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func alert(id string) detection.Alert {
	return detection.Alert{
		ID: id, Timestamp: time.Now().Add(-time.Minute), Summary: "DNS query for x matches y",
		Domain: "c2.example", ClientIP: "192.168.1.50", ClientMAC: "02:00:00:00:00:50",
		MatchedIoC: "c2.example", IoCType: events.IndicatorDomain, Severity: events.SeverityHigh,
		Source: "threatfox", Confidence: 120, SignalClass: events.SignalIoC,
		Target: &events.Target{Type: events.TargetDomain, Value: "c2.example"},
	}
}

// TestAlertCopierCopiesInOrderAndResumes: every alert of the local history
// reaches ClickHouse once, in order, also across a restart, and a failed
// insert is retried rather than skipped.
func TestAlertCopierCopiesInOrderAndResumes(t *testing.T) {
	st := openStore(t)
	alerts := st.Alerts(0, 0)
	for i := 1; i <= alertBatch+3; i++ {
		if err := alerts.Add(alert(fmt.Sprintf("DET-a-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	ch := &fakeCH{fail: 1}
	c := NewAlertCopier(alerts, st.Cursors(), ch)
	c.load()
	if _, err := c.step(context.Background()); err == nil {
		t.Fatal("a refused insert must be an error, so the batch is tried again")
	}
	for more := true; more; {
		var err error
		if more, err = c.step(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	got := ch.table(AlertsTable)
	if len(got) != alertBatch+3 {
		t.Fatalf("%d rows copied, want %d", len(got), alertBatch+3)
	}
	for i, r := range got {
		if want := fmt.Sprintf("DET-a-%d", i+1); r.(alertRecord).ID != want {
			t.Fatalf("row %d is %s, want %s: copied out of order", i, r.(alertRecord).ID, want)
		}
	}
	first := got[0].(alertRecord)
	if first.Confidence != 100 || first.TargetType != "domain" || first.TargetValue != "c2.example" ||
		first.ClientMAC != "02:00:00:00:00:50" || first.SignalClass != "ioc" || first.Summary == "" {
		t.Errorf("row %+v does not carry the alert", first)
	}
	if !strings.Contains(first.ObservedAt, ".") || first.Timestamp < time.Now().Add(-time.Minute).Unix() {
		t.Errorf("times: timestamp %d (want the recording time), observed_at %q", first.Timestamp, first.ObservedAt)
	}

	// A new copier on the same store resumes after the last copied alert.
	if err := alerts.Add(alert("DET-a-new")); err != nil {
		t.Fatal(err)
	}
	ch2 := &fakeCH{}
	c2 := NewAlertCopier(alerts, st.Cursors(), ch2)
	c2.load()
	if _, err := c2.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := ch2.table(AlertsTable); len(got) != 1 || got[0].(alertRecord).ID != "DET-a-new" {
		t.Fatalf("after a restart: %d rows (%v), want only the new alert", len(got), got)
	}
}

// TestAlertCopierCountsAlertsPrunedBeforeTheCopy: the local history is
// bounded; what its retention removed before ClickHouse got it is lost to
// the copy, and that must be a number, not silence.
func TestAlertCopierCountsAlertsPrunedBeforeTheCopy(t *testing.T) {
	st := openStore(t)
	alerts := st.Alerts(time.Hour, 3)
	ch := &fakeCH{}
	c := NewAlertCopier(alerts, st.Cursors(), ch)
	if err := alerts.Add(alert("DET-p-1")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := 2; i <= 7; i++ {
		_ = alerts.Add(alert(fmt.Sprintf("DET-p-%d", i)))
	}
	if _, err := alerts.Prune(); err != nil { // keeps the newest 3
		t.Fatal(err)
	}
	before := counter(t, alertsCopySkipped)
	if _, err := c.step(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d := counter(t, alertsCopySkipped) - before; d != 3 {
		t.Errorf("skipped = %v, want 3 (alerts 2-4 were pruned before the copy)", d)
	}
	if n := len(ch.table(AlertsTable)); n != 4 {
		t.Errorf("%d rows copied, want 1 + the 3 kept", n)
	}
}

// TestAlertCopierRunRetriesUntilAccepted drives Run: ClickHouse down, then
// back; the alert arrives without anyone noticing it had to wait.
func TestAlertCopierRunRetriesUntilAccepted(t *testing.T) {
	st := openStore(t)
	alerts := st.Alerts(0, 0)
	_ = alerts.Add(alert("DET-r-1"))
	ch := &fakeCH{fail: 2}
	c := NewAlertCopier(alerts, st.Cursors(), ch)
	c.base, c.idle = time.Millisecond, time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for (len(ch.table(AlertsTable)) == 0 || counter(t, alertsCopyBacklog) != 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if n := len(ch.table(AlertsTable)); n != 1 {
		t.Fatalf("%d rows after two refused inserts, want 1", n)
	}
	if b := counter(t, alertsCopyBacklog); b != 0 {
		t.Errorf("backlog %v after everything was copied", b)
	}
}

func query(domain, reason string) detection.Query {
	return detection.Query{Time: time.Now(), Client: "192.168.1.50", Domain: domain, QueryType: "A",
		Answers: []string{"93.184.216.34", "93.184.216.35"}, Status: "NOERROR", Reason: reason,
		Elapsed: 12500 * time.Microsecond}
}

// TestDNSLogRows: what dns_queries gets for a query-log entry.
func TestDNSLogRows(t *testing.T) {
	r := dnsRow(query("www.example.org", "NotFilteredNotFound"))
	if r.Domain != "www.example.org" || r.ClientIP != "192.168.1.50" || r.QueryType != "A" ||
		r.Answer != "93.184.216.34,93.184.216.35" || r.Status != "NOERROR" || r.ResponseMs != 12 ||
		r.Blocked != 0 || r.Reason != "NotFilteredNotFound" {
		t.Errorf("row %+v", r)
	}
	for reason, blocked := range map[string]uint8{"FilteredBlackList": 1, "FilteredBlockedService": 1,
		"FilteredSafeSearch": 0, "Rewrite": 0, "NotFilteredWhiteList": 0} {
		if got := dnsRow(query("x.example", reason)).Blocked; got != blocked {
			t.Errorf("%s: blocked = %d, want %d", reason, got, blocked)
		}
	}
	slow := query("x.example", "")
	slow.Elapsed = time.Hour
	if r := dnsRow(slow); r.ResponseMs != 65535 {
		t.Errorf("response_ms %d for an hour, want the column's maximum", r.ResponseMs)
	}
	long := query(strings.Repeat("é", 200), "")
	long.Answers = []string{strings.Repeat("a", 1000)}
	if r := dnsRow(long); len(r.Domain) > maxDomainLen || len(r.Answer) > maxAnswerLen ||
		!strings.HasPrefix(long.Domain, r.Domain) || strings.ContainsRune(r.Domain, '�') {
		t.Errorf("bounded domain %d bytes, answer %d bytes", len(r.Domain), len(r.Answer))
	}
}

// TestDNSLogNeverBlocksAndCountsDrops: a stalled ClickHouse costs dropped,
// counted rows, never a stalled poller or unbounded memory.
func TestDNSLogNeverBlocksAndCountsDrops(t *testing.T) {
	ch := &fakeCH{block: make(chan struct{})}
	l := NewDNSLog(ch, 10)
	l.batch, l.flushEvery = 5, time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { l.Run(ctx); close(done) }()

	full := dnsDropped.WithLabelValues("queue_full")
	before := counter(t, full)
	start := time.Now()
	for i := 0; i < 100; i++ {
		l.Add(query(fmt.Sprintf("q%d.example", i), ""))
	}
	if time.Since(start) > time.Second {
		t.Fatal("Add blocked while ClickHouse was stalled")
	}
	dropped := counter(t, full) - before
	if dropped < 100-10-5 {
		t.Errorf("%v rows counted as dropped; at most queue + batch may wait", dropped)
	}
	close(ch.block) // ClickHouse answers again
	cancel()
	<-done
	written := len(ch.table(DNSQueriesTable))
	if float64(written)+dropped != 100 {
		t.Errorf("written %d + dropped %v != 100: rows vanished uncounted", written, dropped)
	}
}

// TestDNSLogRetriesThenDrops: a refused batch is tried dnsAttempts times,
// then dropped and counted; the next batch is written.
func TestDNSLogRetriesThenDrops(t *testing.T) {
	ch := &fakeCH{fail: dnsAttempts}
	l := NewDNSLog(ch, 100)
	l.retryBase = time.Millisecond
	failed := dnsDropped.WithLabelValues("write_failed")
	before := counter(t, failed)
	rows := []any{dnsRow(query("a.example", "")), dnsRow(query("b.example", ""))}
	l.flush(context.Background(), rows)
	if d := counter(t, failed) - before; d != 2 {
		t.Errorf("write_failed = %v, want 2", d)
	}
	if ch.calls != dnsAttempts {
		t.Errorf("%d attempts, want %d", ch.calls, dnsAttempts)
	}
	l.flush(context.Background(), []any{dnsRow(query("c.example", ""))})
	if n := len(ch.table(DNSQueriesTable)); n != 1 {
		t.Errorf("%d rows written after ClickHouse recovered, want 1", n)
	}
}

// TestDNSLogDrainsAtShutdown: what is queued when the service stops is
// written, not lost.
func TestDNSLogDrainsAtShutdown(t *testing.T) {
	ch := &fakeCH{}
	l := NewDNSLog(ch, 100)
	l.flushEvery = time.Hour
	for i := 0; i < 7; i++ {
		l.Add(query(fmt.Sprintf("q%d.example", i), ""))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.Run(ctx)
	if n := len(ch.table(DNSQueriesTable)); n != 7 {
		t.Errorf("%d of 7 queued rows written at shutdown", n)
	}
}
