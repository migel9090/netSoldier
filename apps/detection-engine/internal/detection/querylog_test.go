package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// agQueryLog behaves like AdGuard Home's /control/querylog: entries with a
// time before ?older_than (all of them without it), newest first, at most
// ?limit. Entries are kept in the order they were logged, which is not
// always time order: a slow lookup is logged when its answer comes back.
type agQueryLog struct {
	mu       sync.Mutex
	entries  []map[string]any
	requests int
}

func (f *agQueryLog) add(host, client string, ts time.Time, answers ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var ans []map[string]any
	for _, a := range answers {
		ans = append(ans, map[string]any{"value": a, "type": "A", "ttl": 60})
	}
	f.entries = append(f.entries, map[string]any{
		"question": map[string]string{"name": host, "type": "A"},
		"client":   client, "time": ts.UTC().Format(time.RFC3339Nano), "answer": ans,
	})
}

func (f *agQueryLog) handler(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	var olderThan time.Time
	if v := r.URL.Query().Get("older_than"); v != "" {
		olderThan, _ = time.Parse(time.RFC3339Nano, v)
	}
	f.mu.Lock()
	f.requests++
	var out []map[string]any
	for i := len(f.entries) - 1; i >= 0; i-- {
		ts, _ := time.Parse(time.RFC3339Nano, f.entries[i]["time"].(string))
		if olderThan.IsZero() || ts.Before(olderThan) {
			out = append(out, f.entries[i])
		}
	}
	f.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i]["time"].(string) > out[j]["time"].(string) })
	if len(out) > limit {
		out = out[:limit]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
}

type memCursors struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (c *memCursors) Load(source string) ([]byte, time.Time, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[source]
	return v, time.Time{}, ok, nil
}

func (c *memCursors) Save(source string, pos []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string][]byte{}
	}
	c.m[source] = pos
	return nil
}

func newPagedEngine(t *testing.T, f *agQueryLog, iocs ...iocmatch.IoC) (*Engine, *[]Alert) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	m := iocmatch.New()
	m.Add(iocs)
	e := New(adguard.NewClient(srv.URL, "u", "p"), m, time.Second)
	var got []Alert
	e.OnAlert = func(a Alert) { got = append(got, a) }
	return e, &got
}

var c2 = iocmatch.IoC{Value: "c2.evil-ioc.com", Type: "domain", Source: "threatfox", Confidence: 95}

func countMatched(alerts []Alert, ioc string) int {
	n := 0
	for _, a := range alerts {
		if a.MatchedIoC == ioc {
			n++
		}
	}
	return n
}

func value(t *testing.T, c prometheus.Metric) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatal(err)
	}
	return m.GetCounter().GetValue()
}

// TestQueryLogFloodIsPagedThrough is the audit's evasion: a C2 lookup
// followed by 300 junk queries inside one poll interval. One fixed request
// for the newest 300 entries never saw the lookup — a counter went up, and
// nothing could be done about it.
func TestQueryLogFloodIsPagedThrough(t *testing.T) {
	for _, junk := range []int{300, 3000} {
		t.Run(fmt.Sprint(junk), func(t *testing.T) {
			f := &agQueryLog{}
			e, got := newPagedEngine(t, f, c2)
			e.poll(context.Background()) // an earlier, quiet poll

			base := time.Now()
			f.add("c2.evil-ioc.com", "192.168.1.66", base)
			for i := 0; i < junk; i++ {
				f.add(fmt.Sprintf("junk%d.example.org", i), "192.168.1.66", base.Add(time.Duration(i+1)*time.Millisecond))
			}
			gapsBefore := value(t, queryLogGaps)
			e.poll(context.Background())
			e.poll(context.Background())

			if n := countMatched(*got, "c2.evil-ioc.com"); n != 1 {
				t.Fatalf("C2 lookup behind %d junk queries detected %d times, want 1", junk, n)
			}
			if g := value(t, queryLogGaps); g != gapsBefore {
				t.Errorf("gap counted (%v -> %v) although every entry was read", gapsBefore, g)
			}
		})
	}
}

// TestQueryLogGapIsCountedAndLogged: when the page bound is hit before the
// entries the previous poll checked, the stretch in between is a gap — a
// detection may have been missed, and that is a number someone can alert on.
func TestQueryLogGapIsCountedAndLogged(t *testing.T) {
	f := &agQueryLog{}
	e, got := newPagedEngine(t, f, c2)
	e.PageSize, e.MaxPages = 50, 3
	e.poll(context.Background())

	base := time.Now()
	f.add("c2.evil-ioc.com", "192.168.1.66", base)
	for i := 0; i < 1000; i++ {
		f.add(fmt.Sprintf("junk%d.example.org", i), "192.168.1.66", base.Add(time.Duration(i+1)*time.Millisecond))
	}
	gaps, sat, pages := value(t, queryLogGaps), value(t, pollBatchSaturated), value(t, queryLogPages)
	e.poll(context.Background())
	if value(t, queryLogGaps) != gaps+1 || value(t, pollBatchSaturated) != sat+1 {
		t.Errorf("gap not counted")
	}
	if p := value(t, queryLogPages) - pages; p != 3 {
		t.Errorf("pages read = %v, want the bound (3)", p)
	}
	if len(*got) != 0 {
		t.Errorf("the C2 lookup was in the gap but was reported")
	}
	// The next poll does not go back into the gap: it starts from the newest
	// entry the gapped poll checked.
	f.add("c2.evil-ioc.com", "192.168.1.67", base.Add(2*time.Second))
	e.poll(context.Background())
	if countMatched(*got, "c2.evil-ioc.com") != 1 {
		t.Errorf("a lookup after the gap was not detected")
	}
}

// TestQueryLogSlowLookupLoggedLateIsChecked: AdGuard stamps an entry with the
// time the query arrived and logs it when the answer is back. A C2 name whose
// own server answers slowly is logged after a poll has already moved past
// its time; stopping at the first entry not newer than the last one seen
// skipped it.
func TestQueryLogSlowLookupLoggedLateIsChecked(t *testing.T) {
	f := &agQueryLog{}
	e, got := newPagedEngine(t, f, c2)
	start := time.Now()
	for i := 0; i < 20; i++ {
		f.add(fmt.Sprintf("fast%d.example.org", i), "192.168.1.66", start.Add(time.Duration(i)*100*time.Millisecond))
	}
	e.poll(context.Background())
	f.add("c2.evil-ioc.com", "192.168.1.66", start.Add(500*time.Millisecond)) // took 9 s to answer
	e.poll(context.Background())
	e.poll(context.Background())
	if n := countMatched(*got, "c2.evil-ioc.com"); n != 1 {
		t.Fatalf("a lookup logged after a newer one was detected %d times, want 1", n)
	}
	if n := value(t, queriesChecked); n == 0 {
		t.Error("nothing counted as checked")
	}
}

// TestQueryLogResumesAfterRestart: the position used to start at "now" in
// memory, so a lookup logged while the pod was down was never checked. A new
// engine on the same store resumes where the old one stopped; the overlap it
// checks again names the same records, which the pipeline's ledger
// recognises.
func TestQueryLogResumesAfterRestart(t *testing.T) {
	f := &agQueryLog{}
	cur := &memCursors{}
	first, got1 := newPagedEngine(t, f, c2)
	first.Cursors = cur
	base := time.Now().Add(-10 * time.Minute)
	f.add("c2.evil-ioc.com", "192.168.1.66", base)
	first.poll(context.Background())
	if len(*got1) != 1 {
		t.Fatalf("first engine: %d alerts", len(*got1))
	}

	f.add("c2.evil-ioc.com", "192.168.1.77", base.Add(4*time.Minute)) // logged while down
	f.add("old.example.org", "192.168.1.66", base.Add(-time.Hour))    // long before the stored position
	second, got2 := newPagedEngine(t, f, c2)
	second.Cursors = cur
	second.poll(context.Background())

	down := 0
	for _, a := range *got2 {
		switch a.ClientIP {
		case "192.168.1.77":
			down++
		case "192.168.1.66":
			// The first lookup is inside the overlap behind the stored
			// position and is checked again — as the same record.
			if a.Record != (*got1)[0].Record {
				t.Errorf("a re-checked entry names record %q (was %q)", a.Record, (*got1)[0].Record)
			}
		}
	}
	if down != 1 {
		t.Fatalf("the lookup made while the engine was down was detected %d times, want 1", down)
	}
}

// TestQueryLogFirstStartLooksBack: without a stored position the engine
// looks back INGEST_LOOKBACK, not from "now"; a stored position older than
// that is not honoured.
func TestQueryLogFirstStartLooksBack(t *testing.T) {
	f := &agQueryLog{}
	f.add("c2.evil-ioc.com", "192.168.1.60", time.Now().Add(-3*time.Hour))
	f.add("c2.evil-ioc.com", "192.168.1.66", time.Now().Add(-5*time.Second))
	e, got := newPagedEngine(t, f, c2)
	e.Lookback = time.Hour
	e.poll(context.Background())
	if len(*got) != 1 || (*got)[0].ClientIP != "192.168.1.66" {
		t.Fatalf("first start: %+v, want only the lookup inside the look-back", *got)
	}

	stale := &memCursors{}
	_ = stale.Save(queryLogCursor, []byte(fmt.Sprintf(`{"last_seen":%q}`, time.Now().Add(-5*time.Hour).Format(time.RFC3339Nano))))
	e2, got2 := newPagedEngine(t, f, c2)
	e2.Cursors, e2.Lookback = stale, time.Hour
	clamped := value(t, cursorClamped.WithLabelValues("adguard"))
	e2.poll(context.Background())
	if len(*got2) != 1 {
		t.Errorf("stale position: %d alerts, want the look-back's one", len(*got2))
	}
	if value(t, cursorClamped.WithLabelValues("adguard")) != clamped+1 {
		t.Error("clamping a stale position was not counted")
	}
}

// TestQueryLogServerIgnoringOlderThanIsAGap: a server that keeps returning
// the same full page cannot be paged; that is reported, not looped on.
func TestQueryLogServerIgnoringOlderThanIsAGap(t *testing.T) {
	entries := make([]map[string]any, 10)
	now := time.Now()
	for i := range entries {
		entries[i] = map[string]any{"question": map[string]string{"name": fmt.Sprintf("n%d.example", i), "type": "A"},
			"client": "192.168.1.5", "time": now.Add(-time.Duration(i) * time.Millisecond)}
	}
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": entries})
	}))
	defer srv.Close()
	e := New(adguard.NewClient(srv.URL, "u", "p"), iocmatch.New(), time.Second)
	e.PageSize = 10
	gaps := value(t, queryLogGaps)
	e.poll(context.Background())
	if requests != 2 {
		t.Errorf("requests = %d, want 2 (the second shows no progress)", requests)
	}
	if value(t, queryLogGaps) != gaps+1 {
		t.Error("an unpageable log must count as a gap")
	}
}

// TestQueryLogFutureEntryDoesNotBlind: an entry stamped in the future (a
// clock that jumped) must not move the position past entries still to come.
func TestQueryLogFutureEntryDoesNotBlind(t *testing.T) {
	f := &agQueryLog{}
	e, got := newPagedEngine(t, f, c2)
	f.add("junk.example.org", "192.168.1.66", time.Now().Add(24*time.Hour))
	e.poll(context.Background())
	f.add("c2.evil-ioc.com", "192.168.1.66", time.Now())
	e.poll(context.Background())
	if len(*got) != 1 {
		t.Errorf("a lookup after a future-stamped entry: %d alerts", len(*got))
	}
}

// TestQueryLogRecordsNameTheEntry: each detection names the querylog entry
// (and answer) it came from, the same way in every process, while its id
// stays per process (contract §1).
func TestQueryLogRecordsNameTheEntry(t *testing.T) {
	f := &agQueryLog{}
	ts := time.Now().Add(-time.Second)
	f.add("c2.evil-ioc.com", "192.168.1.66", ts, "203.0.113.7")
	ipIoC := iocmatch.IoC{Value: "203.0.113.7", Type: "ip", Source: "feodo", Confidence: 90}
	e1, got1 := newPagedEngine(t, f, c2, ipIoC)
	e2, got2 := newPagedEngine(t, f, c2, ipIoC)
	e1.poll(context.Background())
	e2.poll(context.Background())
	if len(*got1) != 2 || len(*got2) != 2 {
		t.Fatalf("alerts %d / %d, want a name match and an answer match each", len(*got1), len(*got2))
	}
	if (*got1)[0].Record == "" || (*got1)[0].Record == (*got1)[1].Record {
		t.Errorf("records %q / %q: the name and the answer match are two detections", (*got1)[0].Record, (*got1)[1].Record)
	}
	for i := range *got1 {
		a, b := (*got1)[i], (*got2)[i]
		if a.Record != b.Record {
			t.Errorf("one entry, two records: %q / %q", a.Record, b.Record)
		}
		if a.ID == b.ID || !idRe.MatchString(a.ID) {
			t.Errorf("ids %q / %q: per detection, not per record", a.ID, b.ID)
		}
	}
}
