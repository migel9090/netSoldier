package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// fakeCH answers exactly what the poller asks ClickHouse for:
//
//	WHERE ingested_at >= lo AND ingested_at <= now64(3) [AND (_at, _h) > (a, h)]
//	ORDER BY _at, _h LIMIT n
//
// over an in-memory table whose rows carry the arrival time ClickHouse
// would stamp and a hash of their content standing in for cityHash64.
type fakeCH struct {
	mu      sync.Mutex
	rows    []fakeRow
	now     func() time.Time
	queries []string
	fail    error
}

type fakeRow struct {
	at   int64
	hash uint64
	body map[string]any
}

var (
	reLo    = regexp.MustCompile(`fromUnixTimestamp64Milli\(toInt64\((-?\d+)\)\)`)
	reAfter = regexp.MustCompile(`\(_at, _h\) > \(toInt64\((-?\d+)\), toUInt64\((\d+)\)\)`)
	reUpto  = regexp.MustCompile(`\(_at, _h\) <= \(toInt64\((-?\d+)\), toUInt64\((\d+)\)\)`)
	reLimit = regexp.MustCompile(`LIMIT (\d+)`)
)

func (f *fakeCH) insert(arrived time.Time, body map[string]any) {
	b, _ := json.Marshal(body) // map keys are sorted: a content hash
	h := fnv.New64a()
	h.Write(b)
	f.mu.Lock()
	f.rows = append(f.rows, fakeRow{at: arrived.UnixMilli(), hash: h.Sum64(), body: body})
	f.mu.Unlock()
}

func (f *fakeCH) QueryJSONEachRow(_ context.Context, q string, fn func(json.RawMessage) error) error {
	f.mu.Lock()
	f.queries = append(f.queries, q)
	if f.fail != nil {
		f.mu.Unlock()
		return f.fail
	}
	lo, _ := strconv.ParseInt(reLo.FindStringSubmatch(q)[1], 10, 64)
	limit, _ := strconv.Atoi(reLimit.FindStringSubmatch(q)[1])
	var afterAt int64 = -1 << 62
	var afterH uint64
	if m := reAfter.FindStringSubmatch(q); m != nil {
		afterAt, _ = strconv.ParseInt(m[1], 10, 64)
		afterH, _ = strconv.ParseUint(m[2], 10, 64)
	}
	var uptoAt int64 = 1 << 62
	var uptoH uint64 = 1<<64 - 1
	if m := reUpto.FindStringSubmatch(q); m != nil {
		uptoAt, _ = strconv.ParseInt(m[1], 10, 64)
		uptoH, _ = strconv.ParseUint(m[2], 10, 64)
	}
	now := f.now().UnixMilli()
	var sel []fakeRow
	for _, r := range f.rows {
		if r.at >= lo && r.at <= now &&
			(r.at > afterAt || r.at == afterAt && r.hash > afterH) &&
			(r.at < uptoAt || r.at == uptoAt && r.hash <= uptoH) {
			sel = append(sel, r)
		}
	}
	f.mu.Unlock()
	sort.Slice(sel, func(i, j int) bool {
		return sel[i].at < sel[j].at || sel[i].at == sel[j].at && sel[i].hash < sel[j].hash
	})
	if len(sel) > limit {
		sel = sel[:limit]
	}
	for _, r := range sel {
		out := map[string]any{"_at": strconv.FormatInt(r.at, 10), "_rk": strconv.FormatUint(r.hash, 10)}
		for k, v := range r.body {
			out[k] = v
		}
		b, _ := json.Marshal(out)
		if err := fn(b); err != nil {
			return err
		}
	}
	return nil
}

func intelRow(eventTime time.Time, uid, indicator string) map[string]any {
	return map[string]any{
		"ts": eventTime.Unix(), "uid": uid, "src_ip": "192.168.1.66", "src_port": 1,
		"dst_ip": "192.168.1.2", "dst_port": 53, "indicator": indicator,
		"indicator_type": "Intel::DOMAIN", "seen_where": "DNS::IN_REQUEST", "sources": []string{"threatfox"},
	}
}

// clock is a settable time source shared by the poller and the fake server.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	clk  *clock
	ch   *fakeCH
	got  []SensorEvent
	opts PollerOptions
}

func newHarness(opts PollerOptions) *harness {
	clk := &clock{t: time.Unix(1_800_000_000, 0).UTC()}
	return &harness{clk: clk, ch: &fakeCH{now: clk.now}, opts: opts}
}

func (h *harness) poller(src Source) *Poller {
	p := NewPoller(h.ch, src, time.Hour, func(ev SensorEvent) { h.got = append(h.got, ev) }, h.opts)
	p.now = h.clk.now
	return p
}

func (h *harness) count(indicator string) int {
	n := 0
	for _, ev := range h.got {
		if ev.Indicator == indicator {
			n++
		}
	}
	return n
}

func mustPoll(t *testing.T, p *Poller) {
	t.Helper()
	if err := p.poll(context.Background()); err != nil {
		t.Fatalf("poll: %v", err)
	}
}

func counterValue(t *testing.T, c prometheus.Collector) float64 {
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

// TestPollerBurstDoesNotStallSource: 1200 rows inserted together share one
// arrival millisecond (and one event second). The old cursor was that second
// with ">= ... LIMIT 1000": every later poll returned the same 1000 rows, the
// cursor never moved, and the source was off until a restart — with no error
// and no metric. A device making 1000 lookups of any listed domain in one
// second did that on purpose.
func TestPollerBurstDoesNotStallSource(t *testing.T) {
	h := newHarness(PollerOptions{})
	p := h.poller(ZeekIntel{})
	p.start()

	h.clk.add(time.Second)
	burst := h.clk.now()
	for i := 0; i < 1200; i++ {
		h.ch.insert(burst, intelRow(burst, fmt.Sprintf("F%d", i), "noise.listed.example"))
	}
	mustPoll(t, p)
	if n := h.count("noise.listed.example"); n != 1200 {
		t.Fatalf("one poll emitted %d of 1200 rows that arrived together", n)
	}

	h.clk.add(2 * time.Minute)
	h.ch.insert(h.clk.now(), intelRow(h.clk.now(), "REAL", "c2.real-threat.example"))
	for i := 0; i < 3; i++ {
		mustPoll(t, p)
	}
	if n := h.count("c2.real-threat.example"); n != 1 {
		t.Fatalf("the hit after the burst was emitted %d times, want 1", n)
	}
	if n := h.count("noise.listed.example"); n != 1200 {
		t.Errorf("burst rows emitted %d times in total, want each once (1200)", n)
	}
}

// TestPollerReadsRowThatArrivesLateWithOlderEventTime: the cursor used to be
// the newest EVENT time seen, so a row stamped earlier that reached
// ClickHouse after a poll — a retried Vector batch, a sensor whose clock is
// behind — was never read.
func TestPollerReadsRowThatArrivesLateWithOlderEventTime(t *testing.T) {
	h := newHarness(PollerOptions{})
	p := h.poller(ZeekIntel{})
	p.start()
	t0 := h.clk.now()

	h.clk.add(10 * time.Second)
	h.ch.insert(h.clk.now(), intelRow(t0.Add(10*time.Second), "A", "fast.example"))
	mustPoll(t, p)

	h.clk.add(30 * time.Second)
	h.ch.insert(h.clk.now(), intelRow(t0.Add(-5*time.Minute), "B", "c2.real-threat.example"))
	mustPoll(t, p)
	mustPoll(t, p)

	if h.count("fast.example") != 1 || h.count("c2.real-threat.example") != 1 {
		t.Fatalf("emitted %v; want both rows once", indicators(h.got))
	}
}

// TestPollerOverlapCatchesSlowCommitWithoutRepeats: a row stamped before the
// cursor (its INSERT started first, committed last) is read by the overlap;
// rows the overlap reads again are not emitted again.
func TestPollerOverlapCatchesSlowCommitWithoutRepeats(t *testing.T) {
	h := newHarness(PollerOptions{Overlap: 10 * time.Second})
	p := h.poller(ZeekIntel{})
	p.start()

	h.clk.add(20 * time.Second)
	for i := 0; i < 5; i++ {
		h.ch.insert(h.clk.now(), intelRow(h.clk.now(), fmt.Sprintf("N%d", i), "seen.example"))
	}
	mustPoll(t, p)
	// Visible only now, stamped 3 s before the rows the poll already read.
	h.ch.insert(h.clk.now().Add(-3*time.Second), intelRow(h.clk.now(), "SLOW", "slow-commit.example"))
	h.clk.add(time.Second)
	mustPoll(t, p)
	mustPoll(t, p)

	if n := h.count("slow-commit.example"); n != 1 {
		t.Errorf("slow commit emitted %d times, want 1", n)
	}
	if n := h.count("seen.example"); n != 5 {
		t.Errorf("rows in the overlap emitted %d times in total, want each once (5)", n)
	}
	// Outside the overlap a slow commit cannot be told from history; the
	// window is what bounds the guarantee.
	h.ch.insert(h.clk.now().Add(-time.Minute), intelRow(h.clk.now(), "ANCIENT", "too-late.example"))
	mustPoll(t, p)
	if n := h.count("too-late.example"); n != 0 {
		t.Errorf("a row stamped a minute behind the cursor was read (%d); the overlap is 10s", n)
	}
}

// TestPollerRetriedInsertIsOneDetection: a batch inserted twice (a Vector
// retry after a timeout that had in fact succeeded) arrives twice with the
// same content; it is one observation.
func TestPollerRetriedInsertIsOneDetection(t *testing.T) {
	h := newHarness(PollerOptions{})
	p := h.poller(ZeekIntel{})
	p.start()
	h.clk.add(time.Second)
	row := intelRow(h.clk.now(), "R1", "c2.real-threat.example")
	h.ch.insert(h.clk.now(), row)
	mustPoll(t, p)
	h.clk.add(2 * time.Second)
	h.ch.insert(h.clk.now(), row)
	mustPoll(t, p)
	if n := h.count("c2.real-threat.example"); n != 1 {
		t.Errorf("a row stored twice was emitted %d times", n)
	}
}

// TestPollerResumesFromStoredPositionAfterRestart: the cursor lived in
// memory and started at "now", so everything that landed while the pod was
// down was never read. A second poller on the same store picks up exactly
// where the first stopped, and the overlap it reads again names the same
// records, which the pipeline's ledger recognises.
func TestPollerResumesFromStoredPositionAfterRestart(t *testing.T) {
	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := newHarness(PollerOptions{Cursors: st.Cursors()})

	first := h.poller(ZeekIntel{})
	first.start()
	h.clk.add(time.Second)
	h.ch.insert(h.clk.now(), intelRow(h.clk.now(), "BEFORE", "before.example"))
	mustPoll(t, first)
	beforeRecord := h.got[0].Record()

	// The pod is down for ten minutes; a hit lands meanwhile.
	h.clk.add(5 * time.Minute)
	h.ch.insert(h.clk.now(), intelRow(h.clk.now(), "DOWN", "c2.real-threat.example"))
	h.clk.add(5 * time.Minute)

	second := h.poller(ZeekIntel{})
	mustPoll(t, second)
	if n := h.count("c2.real-threat.example"); n != 1 {
		t.Fatalf("the hit written while the engine was down was emitted %d times, want 1", n)
	}
	for _, ev := range h.got[1:] {
		if ev.Indicator == "before.example" && ev.Record() != beforeRecord {
			t.Errorf("a row read again after the restart names a different record")
		}
	}
}

// TestPollerFirstStartLooksBack: without a stored position reading starts
// INGEST_LOOKBACK back, not at "now" — a hit 20 s before the first start is
// read, one older than the look-back is not.
func TestPollerFirstStartLooksBack(t *testing.T) {
	h := newHarness(PollerOptions{Lookback: time.Hour})
	h.ch.insert(h.clk.now().Add(-2*time.Hour), intelRow(h.clk.now(), "OLD", "history.example"))
	h.ch.insert(h.clk.now().Add(-20*time.Second), intelRow(h.clk.now(), "PRE", "c2.real-threat.example"))
	mustPoll(t, h.poller(ZeekIntel{}))
	if h.count("c2.real-threat.example") != 1 || h.count("history.example") != 0 {
		t.Errorf("first start emitted %v; want the recent hit only", indicators(h.got))
	}
}

// TestPollerClampsStoredPositionOlderThanLookback: after a long outage the
// stored position is not honoured beyond the look-back; the skip is counted.
func TestPollerClampsStoredPositionOlderThanLookback(t *testing.T) {
	st, err := store.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := newHarness(PollerOptions{Cursors: st.Cursors(), Lookback: time.Hour})
	old, _ := json.Marshal(position{At: h.clk.now().Add(-3 * time.Hour).UnixMilli(), Hash: 7})
	if err := st.Cursors().Save("zeek_intel", old); err != nil {
		t.Fatal(err)
	}
	h.ch.insert(h.clk.now().Add(-2*time.Hour), intelRow(h.clk.now(), "STALE", "stale.example"))
	h.ch.insert(h.clk.now().Add(-time.Minute), intelRow(h.clk.now(), "RECENT", "recent.example"))

	before := gathered(t, "detection_engine_ingest_cursor_clamped_total", "zeek_intel")
	mustPoll(t, h.poller(ZeekIntel{}))
	if h.count("recent.example") != 1 || h.count("stale.example") != 0 {
		t.Errorf("emitted %v; want only what is inside the look-back", indicators(h.got))
	}
	if after := gathered(t, "detection_engine_ingest_cursor_clamped_total", "zeek_intel"); after != before+1 {
		t.Errorf("clamped counter %v -> %v, want +1", before, after)
	}
}

// gathered reads one sample with label source=... from the default registry
// (0 when absent).
func gathered(t *testing.T, name, source string) float64 {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "source" && l.GetValue() == source {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// TestPollerSaturationIsCountedAndResumes: a poll that reaches the page
// bound says so and leaves the rest for the next poll — nothing is skipped.
func TestPollerSaturationIsCountedAndResumes(t *testing.T) {
	h := newHarness(PollerOptions{PageSize: 10, MaxPages: 2})
	p := h.poller(ZeekIntel{})
	p.start()
	h.clk.add(time.Second)
	for i := 0; i < 45; i++ {
		h.ch.insert(h.clk.now(), intelRow(h.clk.now(), fmt.Sprintf("S%d", i), "flood.example"))
	}
	sat := pollSaturated.WithLabelValues("zeek_intel")
	before := counterValue(t, sat)
	mustPoll(t, p)
	if n := h.count("flood.example"); n != 20 {
		t.Fatalf("first poll emitted %d, want two pages of 10", n)
	}
	if got := counterValue(t, sat); got != before+1 {
		t.Errorf("saturation counter %v -> %v, want +1", before, got)
	}
	if lag := counterValue(t, cursorLag.WithLabelValues("zeek_intel")); lag < 0 {
		t.Errorf("lag gauge %v", lag)
	}
	mustPoll(t, p)
	mustPoll(t, p)
	if n := h.count("flood.example"); n != 45 {
		t.Errorf("after three polls emitted %d of 45", n)
	}
}

// TestPollerLagGrowsWhilePollsFail: the lag gauge is what tells an operator
// a source has stopped moving.
func TestPollerLagGrowsWhilePollsFail(t *testing.T) {
	h := newHarness(PollerOptions{})
	p := h.poller(ZeekIntel{})
	mustPoll(t, p)
	lag := cursorLag.WithLabelValues("zeek_intel")
	if v := counterValue(t, lag); v != 0 {
		t.Errorf("caught-up lag = %v, want 0", v)
	}
	h.ch.fail = errors.New("connection refused")
	h.clk.add(5 * time.Minute)
	if err := p.poll(context.Background()); err == nil {
		t.Fatal("a failing query must fail the poll")
	}
	if v := counterValue(t, lag); v < 300 {
		t.Errorf("lag after five failing minutes = %v, want >= 300", v)
	}
}

// TestPollerQueryShape pins the parts of the SELECT the guarantees rest on.
func TestPollerQueryShape(t *testing.T) {
	p := NewPoller(nil, ZeekSSL{}, time.Hour, nil, PollerOptions{})
	q := p.query(1000, &position{At: 2000, Hash: 42}, &position{At: 3000, Hash: 7}, 500)
	for _, want := range []string{
		"toUnixTimestamp64Milli(ingested_at) AS _at",
		"cityHash64(timestamp, uid, src_ip",
		"FROM zeek_ssl",
		"ingested_at >= fromUnixTimestamp64Milli(toInt64(1000))",
		"ingested_at <= now64(3)",
		"(_at, _h) > (toInt64(2000), toUInt64(42))",
		"(_at, _h) <= (toInt64(3000), toUInt64(7))",
		"AND established = 1",
		"ORDER BY _at, _h",
		"LIMIT 500",
		"FORMAT JSONEachRow",
	} {
		if !strings.Contains(q, want) {
			t.Errorf("query lacks %q:\n%s", want, q)
		}
	}
	for _, src := range []Source{NewSuricataAlerts(LocalNetworks{}), ZeekIntel{}, ZeekSSL{}, MLBeacons{}, MLAnomalies{}} {
		if strings.Contains(src.Identity(), "ingested_at") {
			t.Errorf("%s identity includes the arrival time: a retried insert would be a new row", src.Name())
		}
	}
	if !strings.Contains(MLBeacons{}.Identity(), "dst_domain") {
		t.Error("beacon identity must include dst_domain: SNI beacons have no address")
	}
}

// TestPollerRowWithoutPositionFailsThePoll: a page cannot continue after a
// row it cannot place, so that is an error, not a silent skip.
func TestPollerRowWithoutPositionFailsThePoll(t *testing.T) {
	q := querierFunc(func(_ context.Context, _ string, fn func(json.RawMessage) error) error {
		return fn(json.RawMessage(`{"ts":1}`))
	})
	p := NewPoller(q, ZeekIntel{}, time.Hour, func(SensorEvent) {}, PollerOptions{})
	if err := p.poll(context.Background()); err == nil {
		t.Fatal("want an error")
	}
}

type querierFunc func(context.Context, string, func(json.RawMessage) error) error

func (f querierFunc) QueryJSONEachRow(ctx context.Context, q string, fn func(json.RawMessage) error) error {
	return f(ctx, q, fn)
}

func indicators(evs []SensorEvent) []string {
	out := make([]string, len(evs))
	for i, ev := range evs {
		out[i] = ev.Indicator
	}
	return out
}
