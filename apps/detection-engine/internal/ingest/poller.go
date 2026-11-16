package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultPageSize is how many rows one query asks for.
	DefaultPageSize = 1000
	// DefaultMaxPages bounds one poll (SENSOR_POLL_MAX_PAGES). A source
	// with more waiting is not skipped: the next poll continues from the
	// cursor. Hitting the bound is counted as saturation.
	DefaultMaxPages = 20
	// DefaultOverlap is how far behind its cursor each poll looks again
	// (SENSOR_POLL_OVERLAP). ingested_at is taken when an INSERT starts and
	// the rows become visible when it commits, so a slow insert can surface
	// behind rows a faster one already made visible.
	DefaultOverlap = 10 * time.Second
	// maxSeenRows caps the de-duplication memory of the overlap window.
	maxSeenRows = 200000
)

var (
	rowsIngested = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "sensor_rows_ingested_total",
		Help:      "Sensor rows normalized into unified events.",
	}, []string{"source"})
	ingestErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "sensor_ingest_errors_total",
		Help:      "Sensor poll or parse errors.",
	}, []string{"source"})
	pagesRead = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "sensor_pages_total",
		Help:      "Sensor table pages read.",
	}, []string{"source"})
	pollSaturated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "sensor_poll_saturated_total",
		Help:      "Poll scans that stopped at the page bound: rows still waiting (read by the next poll) or a look-behind cut short.",
	}, []string{"source"})
	cursorLag = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "sensor_cursor_lag_seconds",
		Help:      "How far behind the source's arrivals reading is: about the poll interval when caught up, growing while polls fail or saturate.",
	}, []string{"source"})
)

func init() {
	prometheus.MustRegister(rowsIngested, ingestErrors, pagesRead, pollSaturated, cursorLag)
}

// Querier runs a JSONEachRow SELECT and hands back each row
// (*clickhouse.Client in production).
type Querier interface {
	QueryJSONEachRow(ctx context.Context, query string, fn func(json.RawMessage) error) error
}

// Source describes one ClickHouse sensor table. The table must have the
// ingested_at column (migration 026): rows are read in the order they
// arrived, not by the time the sensor says the event happened.
type Source interface {
	// Name is the table, the metric label and the cursor's name.
	Name() string
	// Columns is the SELECT list Parse reads.
	Columns() string
	// Identity lists the columns that make a row what it is. Their hash
	// orders rows that arrived in the same millisecond, recognises a row
	// stored twice (a retried insert), and names the row in the ledger of
	// handled records, so it must not include ingested_at.
	Identity() string
	// Filter is an extra WHERE condition, or "".
	Filter() string
	// Parse converts one row into a SensorEvent.
	Parse(row json.RawMessage) (SensorEvent, error)
}

// PollerOptions tunes a Poller; zero values take the defaults.
type PollerOptions struct {
	// Cursors keeps the read position across restarts; nil keeps it in
	// memory only.
	Cursors  detection.CursorStore
	PageSize int
	MaxPages int
	Overlap  time.Duration
	// Lookback is where reading starts without a stored position, and the
	// oldest stored position that is honoured.
	Lookback time.Duration
}

// position is a row's place in arrival order: ingested_at in milliseconds,
// then the identity hash. Every row has a distinct position (two rows
// sharing both are the same row stored twice), so a page that ends anywhere
// — even in the middle of thousands of rows inserted in one statement —
// says exactly where the next one starts.
type position struct {
	At   int64  `json:"at_ms"`
	Hash uint64 `json:"hash"`
}

func (p position) after(q position) bool {
	return p.At > q.At || p.At == q.At && p.Hash > q.Hash
}

// Poller tails one Source.
//
// The old cursor was the largest EVENT second seen, read with >= and a
// LIMIT. That lost data three ways: a burst of LIMIT rows in one second
// returned the same page forever and switched the source off without an
// error; a row whose event time was older than the cursor but that arrived
// later (a retried Vector batch, a sensor whose clock is behind) was never
// read; and the cursor started at "now" in memory, so a restart skipped
// everything logged while the pod was down. Now the cursor is a total order
// over arrival (see position), each poll pages until a short page, and the
// position is stored after every page.
type Poller struct {
	ch       Querier
	src      Source
	interval time.Duration
	emit     func(SensorEvent)
	opts     PollerOptions
	now      func() time.Time

	started bool
	cursor  position
	// seen holds the identity hashes read within the overlap window, with
	// their arrival, so rows read again are not emitted twice. It is not
	// stored: after a restart the window is read again, and the pipeline's
	// ledger of handled records (store.Records) recognises its detections.
	seen map[uint64]int64
	// readUpTo is the arrival time up to which everything has been read.
	readUpTo time.Time
}

func NewPoller(ch Querier, src Source, interval time.Duration, emit func(SensorEvent), opts PollerOptions) *Poller {
	return &Poller{
		ch:       ch,
		src:      src,
		interval: interval,
		emit:     emit,
		opts:     opts,
		now:      time.Now,
		seen:     make(map[uint64]int64),
	}
}

func (p *Poller) Run(ctx context.Context) {
	p.start()
	slog.Info("sensor ingest started", "source", p.src.Name(), "interval", p.interval,
		"from", time.UnixMilli(p.cursor.At).UTC())
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.poll(ctx); err != nil && ctx.Err() == nil {
				ingestErrors.WithLabelValues(p.src.Name()).Inc()
				slog.Warn("sensor poll failed", "source", p.src.Name(), "error", err)
			}
		}
	}
}

func (p *Poller) pageSize() int { return positiveOr(p.opts.PageSize, DefaultPageSize) }
func (p *Poller) maxPages() int { return positiveOr(p.opts.MaxPages, DefaultMaxPages) }
func (p *Poller) overlap() time.Duration {
	if p.opts.Overlap > 0 {
		return p.opts.Overlap
	}
	return DefaultOverlap
}
func (p *Poller) lookback() time.Duration {
	if p.opts.Lookback > 0 {
		return p.opts.Lookback
	}
	return detection.DefaultLookback
}

// start sets the cursor: the stored position, or the look-back when there is
// none or it is older than the look-back.
func (p *Poller) start() {
	if p.started {
		return
	}
	p.started = true
	name := p.src.Name()
	floor := position{At: p.now().Add(-p.lookback()).UnixMilli()}
	p.cursor = floor
	defer func() { p.readUpTo = time.UnixMilli(p.cursor.At) }()
	if p.opts.Cursors == nil {
		return
	}
	raw, _, ok, err := p.opts.Cursors.Load(name)
	switch {
	case err != nil:
		slog.Warn("sensor position unreadable: looking back instead", "source", name,
			"lookback", p.lookback(), "error", err)
		return
	case !ok:
		slog.Info("no stored sensor position: looking back", "source", name, "lookback", p.lookback())
		return
	}
	var pos position
	if err := json.Unmarshal(raw, &pos); err != nil || pos.At <= 0 {
		slog.Warn("stored sensor position is malformed: looking back instead", "source", name)
		return
	}
	if pos.At < floor.At {
		detection.NoteCursorClamped(name)
		slog.Warn("stored sensor position is older than INGEST_LOOKBACK: rows in between are not read",
			"source", name, "stored", time.UnixMilli(pos.At).UTC(), "resuming_at", time.UnixMilli(floor.At).UTC())
		return
	}
	p.cursor = pos
}

// poll reads everything that arrived since the previous poll, then looks
// behind the cursor for rows that became visible late.
//
// The two are separate scans with separate page budgets. Reading forward
// starts strictly after the cursor, so every page moves it and no amount of
// data can pin it in place. The look-behind re-reads the overlap window,
// which under a flood is thousands of rows already seen; had it come first
// in one budget, a big enough flood would have spent every page on it and
// stalled the source exactly as the old cursor did.
func (p *Poller) poll(ctx context.Context) error {
	p.start()
	began := p.now()
	defer func() {
		cursorLag.WithLabelValues(p.src.Name()).Set(p.now().Sub(p.readUpTo).Seconds())
	}()
	name := p.src.Name()
	from := p.cursor

	caughtUp, err := p.scan(ctx, from.At, &from, nil, func(last position) {
		p.cursor = last
		p.saveCursor()
	})
	if err != nil {
		return err
	}
	if caughtUp {
		p.readUpTo = began
	} else {
		p.readUpTo = time.UnixMilli(p.cursor.At)
		pollSaturated.WithLabelValues(name).Inc()
		slog.Warn("sensor poll saturated: more rows waiting, continuing next poll",
			"source", name, "pages", p.maxPages(), "page_size", p.pageSize(),
			"read_up_to", time.UnixMilli(p.cursor.At).UTC(),
			"hint", "raise SENSOR_POLL_MAX_PAGES or shorten SENSOR_POLL_INTERVAL")
	}

	behind, err := p.scan(ctx, from.At-p.overlap().Milliseconds(), nil, &from, nil)
	if err != nil {
		return err
	}
	if !behind {
		pollSaturated.WithLabelValues(name).Inc()
		slog.Warn("sensor look-behind saturated: rows that arrived late in the overlap window may be unread",
			"source", name, "overlap", p.overlap(), "pages", p.maxPages(),
			"hint", "raise SENSOR_POLL_MAX_PAGES or lower SENSOR_POLL_OVERLAP")
	}
	p.forget()
	return nil
}

// scan pages through rows from lo, strictly after `after` and up to `upto`
// (each optional), for at most maxPages pages. advanced, when set, receives
// the last position of every non-empty page. It reports whether it reached
// the end.
func (p *Poller) scan(ctx context.Context, lo int64, after, upto *position, advanced func(position)) (bool, error) {
	limit := p.pageSize()
	for pages := 0; pages < p.maxPages(); pages++ {
		n, last, err := p.page(ctx, p.query(lo, after, upto, limit))
		pagesRead.WithLabelValues(p.src.Name()).Inc()
		if err != nil {
			return false, err
		}
		if n > 0 {
			after, lo = &last, last.At
			if advanced != nil {
				advanced(last)
			}
		}
		if n < limit {
			return true, nil
		}
	}
	return false, nil
}

// page reads one page and emits the rows not read before. It returns how
// many rows the page held and the position of the last.
func (p *Poller) page(ctx context.Context, query string) (n int, last position, err error) {
	name := p.src.Name()
	err = p.ch.QueryJSONEachRow(ctx, query, func(row json.RawMessage) error {
		pos, err := parsePosition(row)
		if err != nil {
			// Without its position the next page cannot start after it.
			return fmt.Errorf("%s row without a position: %w", name, err)
		}
		n++
		last = pos
		if _, dup := p.seen[pos.Hash]; dup {
			return nil
		}
		p.seen[pos.Hash] = pos.At

		ev, err := p.src.Parse(row)
		if err != nil {
			ingestErrors.WithLabelValues(name).Inc()
			slog.Debug("sensor row skipped", "source", name, "error", err)
			return nil
		}
		ev.Origin, ev.RowKey = name, strconv.FormatUint(pos.Hash, 10)
		rowsIngested.WithLabelValues(name).Inc()
		p.emit(ev)
		return nil
	})
	return n, last, err
}

// query builds one page's SELECT. Rows are ordered by (arrival, identity
// hash) and the page starts strictly after the previous page's last row.
// ingested_at <= now64(3) keeps the cursor from passing the server's clock:
// a row stamped ahead of it is read when its time comes instead of hiding
// every row that arrives before then. The plain range on ingested_at is what
// the minmax index prunes on; the tuple comparisons are exact.
func (p *Poller) query(lo int64, after, upto *position, limit int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "SELECT toUnixTimestamp64Milli(ingested_at) AS _at, cityHash64(%s) AS _h, toString(_h) AS _rk,\n  %s\n",
		p.src.Identity(), p.src.Columns())
	fmt.Fprintf(&b, "FROM %s\nWHERE ingested_at >= fromUnixTimestamp64Milli(toInt64(%d)) AND ingested_at <= now64(3)", p.src.Name(), lo)
	if after != nil {
		fmt.Fprintf(&b, "\n  AND (_at, _h) > (toInt64(%d), toUInt64(%d))", after.At, after.Hash)
	}
	if upto != nil {
		fmt.Fprintf(&b, "\n  AND (_at, _h) <= (toInt64(%d), toUInt64(%d))", upto.At, upto.Hash)
	}
	if f := p.src.Filter(); f != "" {
		b.WriteString("\n  AND " + f)
	}
	fmt.Fprintf(&b, "\nORDER BY _at, _h\nLIMIT %d\nFORMAT JSONEachRow", limit)
	return b.String()
}

type rowPosition struct {
	At json.Number `json:"_at"`
	RK string      `json:"_rk"`
}

func parsePosition(row json.RawMessage) (position, error) {
	var r rowPosition
	if err := json.Unmarshal(row, &r); err != nil {
		return position{}, err
	}
	at, err := r.At.Int64()
	if err != nil {
		return position{}, fmt.Errorf("_at: %w", err)
	}
	h, err := strconv.ParseUint(r.RK, 10, 64)
	if err != nil {
		return position{}, fmt.Errorf("_rk: %w", err)
	}
	return position{At: at, Hash: h}, nil
}

// forget drops seen rows that have left the overlap window and caps the
// rest.
func (p *Poller) forget() {
	cutoff := p.cursor.At - p.overlap().Milliseconds()
	for h, at := range p.seen {
		if at < cutoff {
			delete(p.seen, h)
		}
	}
	if len(p.seen) <= maxSeenRows {
		return
	}
	ats := make([]int64, 0, len(p.seen))
	for _, at := range p.seen {
		ats = append(ats, at)
	}
	slices.Sort(ats)
	cut := ats[len(ats)-maxSeenRows]
	for h, at := range p.seen {
		if at < cut {
			delete(p.seen, h)
		}
	}
}

func (p *Poller) saveCursor() {
	if p.opts.Cursors == nil {
		return
	}
	raw, _ := json.Marshal(p.cursor)
	if err := p.opts.Cursors.Save(p.src.Name(), raw); err != nil {
		slog.Warn("sensor position not saved: a restart re-reads from the previous one",
			"source", p.src.Name(), "error", err)
	}
}

func positiveOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}
