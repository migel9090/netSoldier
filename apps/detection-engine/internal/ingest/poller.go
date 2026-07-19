package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const pollBatchLimit = 1000

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
)

func init() {
	prometheus.MustRegister(rowsIngested, ingestErrors)
}

// Source describes one ClickHouse-backed sensor stream.
type Source interface {
	Name() string
	// Query returns a JSONEachRow SELECT for rows at or after since.
	Query(since time.Time, limit int) string
	// Parse converts one row into a SensorEvent plus a dedupe key that is
	// unique within the row's timestamp second.
	Parse(row json.RawMessage) (SensorEvent, string, error)
}

// Poller tails one Source with a timestamp cursor. ClickHouse DateTime has
// second precision, so the query uses >= and rows in the cursor second are
// deduplicated by key across polls.
type Poller struct {
	ch       *CHClient
	src      Source
	interval time.Duration
	emit     func(SensorEvent)

	cursor time.Time
	seen   map[string]struct{}
}

func NewPoller(ch *CHClient, src Source, interval time.Duration, emit func(SensorEvent)) *Poller {
	return &Poller{
		ch:       ch,
		src:      src,
		interval: interval,
		emit:     emit,
		cursor:   time.Now().UTC().Truncate(time.Second),
		seen:     make(map[string]struct{}),
	}
}

func (p *Poller) Run(ctx context.Context) {
	slog.Info("sensor ingest started", "source", p.src.Name(), "interval", p.interval)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := p.poll(ctx); err != nil {
				ingestErrors.WithLabelValues(p.src.Name()).Inc()
				slog.Warn("sensor poll failed", "source", p.src.Name(), "error", err)
			}
		}
	}
}

func (p *Poller) poll(ctx context.Context) error {
	maxTS := p.cursor
	fresh := make(map[string]struct{})

	err := p.ch.QueryJSONEachRow(ctx, p.src.Query(p.cursor, pollBatchLimit), func(row json.RawMessage) error {
		ev, key, err := p.src.Parse(row)
		if err != nil {
			ingestErrors.WithLabelValues(p.src.Name()).Inc()
			slog.Debug("sensor row skipped", "source", p.src.Name(), "error", err)
			return nil
		}

		if ev.Timestamp.Equal(p.cursor) {
			if _, dup := p.seen[key]; dup {
				return nil
			}
		}

		if ev.Timestamp.After(maxTS) {
			maxTS = ev.Timestamp
			fresh = make(map[string]struct{})
		}
		if ev.Timestamp.Equal(maxTS) {
			fresh[key] = struct{}{}
		}

		rowsIngested.WithLabelValues(p.src.Name()).Inc()
		p.emit(ev)
		return nil
	})
	if err != nil {
		return err
	}

	if maxTS.After(p.cursor) {
		p.cursor = maxTS
		p.seen = fresh
	} else {
		for k := range fresh {
			p.seen[k] = struct{}{}
		}
	}
	return nil
}

// chTime formats a cursor for a ClickHouse DateTime comparison.
func chTime(t time.Time) string {
	return fmt.Sprintf("toDateTime(%d)", t.Unix())
}
