package actions

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// fakeClickHouse accepts JSONEachRow inserts the way ClickHouse's HTTP
// interface does, and can be told to fail.
type fakeClickHouse struct {
	mu      sync.Mutex
	rows    []map[string]any
	fail    int // fail this many requests first
	queries []string
	users   []string
	srv     *httptest.Server
}

func newFakeClickHouse(t *testing.T) *fakeClickHouse {
	f := &fakeClickHouse{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.queries = append(f.queries, r.URL.RawQuery)
		f.users = append(f.users, r.Header.Get("X-ClickHouse-User")+":"+r.Header.Get("X-ClickHouse-Key"))
		if f.fail > 0 {
			f.fail--
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("Code: 999. DB::Exception: unavailable"))
			return
		}
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			var row map[string]any
			if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.rows = append(f.rows, row)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeClickHouse) got() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.rows...)
}

// TestAuditOutboxRetriesUntilAccepted: audit writes were best-effort with
// no retry, so a ClickHouse outage lost the record of every transition
// made during it.
func TestAuditOutboxRetriesUntilAccepted(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	r := pending(t, s, event("192.168.1.50", "evil.example"))
	s.Approve(r.ID, "alice", "", c.Now())
	c.Advance(1234 * time.Millisecond)
	s.Activate(r.ID, "alice", "applied")

	ch := newFakeClickHouse(t)
	ch.fail = 2
	f := &Forwarder{Store: s, Sink: NewClickHouseSink(ch.srv.URL+"/", "netsoldier", "killswitch", "pw"), Batch: 2}

	for i := 0; i < 2; i++ {
		if _, err := f.Flush(context.Background()); err == nil {
			t.Fatalf("attempt %d: the outage must be reported", i)
		}
	}
	if n, oldest, _ := s.OutboxStats(); n != 3 || oldest.IsZero() {
		t.Fatalf("outbox after failures: %d entries (oldest %v), want all 3 kept", n, oldest)
	}
	sent, err := f.Flush(context.Background())
	if err != nil || sent != 3 {
		t.Fatalf("flush after recovery: %d %v", sent, err)
	}
	if n, _, _ := s.OutboxStats(); n != 0 {
		t.Fatalf("%d entries left in the outbox", n)
	}
	rows := ch.got()
	if len(rows) != 3 {
		t.Fatalf("clickhouse got %d rows", len(rows))
	}
	// DateTime64(3) text, milliseconds kept (migration 023).
	if rows[2]["timestamp"] != c.Now().Format("2006-01-02 15:04:05.000") || !strings.HasSuffix(rows[2]["timestamp"].(string), ".234") {
		t.Errorf("timestamp %v", rows[2]["timestamp"])
	}
	for k, want := range map[string]string{"action_id": r.ID, "from_state": "approved", "to_state": "active",
		"actor": "alice", "blocked_domain": "evil.example", "target_ip": "192.168.1.50",
		"action_type": events.ActionDNSSinkhole, "detection_id": r.DetectionID} {
		if rows[2][k] != want {
			t.Errorf("row %s = %v, want %q", k, rows[2][k], want)
		}
	}
	q := ch.queries[len(ch.queries)-1]
	for _, want := range []string{"input_format_skip_unknown_fields=1", "database=netsoldier", "insert_deduplication_token="} {
		if !strings.Contains(q, want) {
			t.Errorf("insert query %q lacks %s", q, want)
		}
	}
	if ch.users[0] != "killswitch:pw" {
		t.Errorf("credentials must go in headers, got %q", ch.users[0])
	}
	if sent, err := f.Flush(context.Background()); sent != 0 || err != nil {
		t.Errorf("an empty outbox: %d %v", sent, err)
	}
}

func TestForwarderRunDeliversInTheBackground(t *testing.T) {
	c := newClock()
	s := newStore(t, c)
	ch := newFakeClickHouse(t)
	ch.fail = 1
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&Forwarder{Store: s, Sink: NewClickHouseSink(ch.srv.URL, "netsoldier", "", ""),
			Interval: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond}).Run(ctx)
		close(done)
	}()
	pending(t, s, event("192.168.1.50", "evil.example"))
	deadline := time.Now().Add(5 * time.Second)
	for len(ch.got()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if len(ch.got()) != 1 {
		t.Fatalf("the entry was not delivered after the outage: %d rows", len(ch.got()))
	}
}

func TestClickHouseSinkReportsTransportErrors(t *testing.T) {
	sink := NewClickHouseSink("http://127.0.0.1:1", "netsoldier", "", "")
	err := sink.Send(context.Background(), []AuditEntry{{Seq: 1, Timestamp: time.Now()}})
	if err == nil {
		t.Fatal("an unreachable server must be an error")
	}
	if err := sink.Send(context.Background(), nil); err != nil {
		t.Errorf("nothing to send: %v", err)
	}
}
