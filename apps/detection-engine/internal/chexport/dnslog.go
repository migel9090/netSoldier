package chexport

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/prometheus/client_golang/prometheus"
)

// DNSQueriesTable is netsoldier.dns_queries (migrations 004, 019, 020, 031).
const DNSQueriesTable = "dns_queries"

const (
	// DefaultDNSQueue is how many query-log rows wait for ClickHouse at most
	// (DNS_QUERY_EXPORT_QUEUE). A row is about 200 bytes, so the default
	// holds a few megabytes: a minute of a busy household, or a second of a
	// flood.
	DefaultDNSQueue = 20000
	// dnsBatch rows, or whatever dnsFlushEvery collected, go in one insert.
	dnsBatch      = 2000
	dnsFlushEvery = 5 * time.Second
	// dnsAttempts bounds how often one batch is tried before it is dropped:
	// the query log is history, and holding it back would only make the
	// queue drop newer rows instead.
	dnsAttempts  = 3
	dnsRetryBase = time.Second
	// dnsDrainTimeout bounds the final flush at shutdown.
	dnsDrainTimeout = 5 * time.Second

	// Bounds on what one row carries. AdGuard's own limits are larger; a
	// name longer than DNS allows or a list of hundreds of answers is not
	// worth storing whole.
	maxDomainLen = 255
	maxAnswerLen = 512
)

var (
	dnsExported = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "dns_queries_exported_total",
		Help:      "AdGuard query-log entries written to ClickHouse's dns_queries.",
	})
	dnsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "dns_queries_dropped_total",
		Help:      "Query-log entries not written to ClickHouse: queue_full (ClickHouse slower than the resolver) or write_failed (refused after retries).",
	}, []string{"reason"})
	dnsQueued = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "dns_export_queue",
		Help:      "Query-log entries waiting to be written to ClickHouse.",
	})
)

func init() {
	prometheus.MustRegister(dnsExported, dnsDropped, dnsQueued)
	for _, r := range []string{"queue_full", "write_failed"} {
		dnsDropped.WithLabelValues(r)
	}
}

// Filtering verdicts that stopped the answer. SafeSearch and the rewrite
// rules answer with something else, which is not blocking.
var blockedReasons = map[string]bool{
	"FilteredBlackList":      true,
	"FilteredSafeBrowsing":   true,
	"FilteredParental":       true,
	"FilteredInvalid":        true,
	"FilteredBlockedService": true,
}

// DNSLog writes the query-log entries the engine checks to dns_queries.
//
// It stores every DNS lookup of every device, so it is off with
// DNS_QUERY_EXPORT=off, and the table deletes rows after 30 days (migration
// 031). Add never blocks the poller: entries wait in a bounded queue, a full
// queue drops the newest with a count, and the writer sends batches. Memory
// is bounded by the queue and one batch.
type DNSLog struct {
	ch    Inserter
	queue chan dnsRecord

	batch      int
	flushEvery time.Duration
	retryBase  time.Duration
}

// NewDNSLog returns a query-log writer holding at most queue rows (the
// default when queue <= 0); start it with Run.
func NewDNSLog(ch Inserter, queue int) *DNSLog {
	if queue <= 0 {
		queue = DefaultDNSQueue
	}
	return &DNSLog{ch: ch, queue: make(chan dnsRecord, queue), batch: dnsBatch,
		flushEvery: dnsFlushEvery, retryBase: dnsRetryBase}
}

// dnsRecord is one row of netsoldier.dns_queries; every field is a column.
type dnsRecord struct {
	Timestamp    int64  `json:"timestamp"` // DateTime: when the query arrived
	ClientIP     string `json:"client_ip"`
	Domain       string `json:"domain"`
	QueryType    string `json:"query_type"`
	Answer       string `json:"answer"`
	Status       string `json:"status"`
	ResponseMs   uint16 `json:"response_ms"`
	Blocked      uint8  `json:"blocked"`
	Reason       string `json:"reason"`
	ThreatSource string `json:"threat_source"`
	ThreatName   string `json:"threat_name"`
}

// Add queues one checked entry. It never blocks.
func (l *DNSLog) Add(q detection.Query) {
	select {
	case l.queue <- dnsRow(q):
	default:
		dnsDropped.WithLabelValues("queue_full").Inc()
	}
}

func dnsRow(q detection.Query) dnsRecord {
	ts := q.Time
	if ts.IsZero() || ts.Unix() < 0 {
		ts = time.Now()
	}
	r := dnsRecord{
		Timestamp:    ts.Unix(),
		ClientIP:     q.Client,
		Domain:       truncate(q.Domain, maxDomainLen),
		QueryType:    q.QueryType,
		Answer:       truncate(strings.Join(q.Answers, ","), maxAnswerLen),
		Status:       q.Status,
		ResponseMs:   uint16(min(q.Elapsed.Milliseconds(), 65535)),
		Reason:       q.Reason,
		ThreatSource: q.ThreatSource,
		ThreatName:   q.ThreatName,
	}
	if blockedReasons[q.Reason] {
		r.Blocked = 1
	}
	return r
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary: ClickHouse keeps the bytes, but the JSON
	// output that reads them back must stay valid UTF-8.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// Run writes batches until ctx ends, then writes what is queued, for at most
// dnsDrainTimeout.
func (l *DNSLog) Run(ctx context.Context) {
	t := time.NewTicker(l.flushEvery)
	defer t.Stop()
	pending := make([]any, 0, l.batch)
	for {
		select {
		case <-ctx.Done():
			l.drain(pending)
			return
		case r := <-l.queue:
			pending = append(pending, r)
			if len(pending) >= l.batch {
				pending = l.flush(ctx, pending)
			}
		case <-t.C:
			pending = l.flush(ctx, pending)
		}
		dnsQueued.Set(float64(len(l.queue) + len(pending)))
	}
}

func (l *DNSLog) drain(pending []any) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsDrainTimeout)
	defer cancel()
	for {
		select {
		case r := <-l.queue:
			pending = append(pending, r)
			if len(pending) >= l.batch {
				pending = l.flush(ctx, pending)
			}
			continue
		default:
		}
		break
	}
	if left := l.flush(ctx, pending); len(left) > 0 {
		dnsDropped.WithLabelValues("write_failed").Add(float64(len(left)))
		slog.Warn("DNS query-log rows not written before shutdown", "rows", len(left))
	}
	dnsQueued.Set(float64(len(l.queue)))
}

// flush writes rows, retrying a failed insert, and returns the emptied
// slice for reuse. Rows ClickHouse still refuses are dropped and counted.
// When ctx ends first the rows are returned as they are, for the final
// flush at shutdown.
func (l *DNSLog) flush(ctx context.Context, rows []any) []any {
	if len(rows) == 0 {
		return rows
	}
	wait := l.retryBase
	for attempt := 1; ; attempt++ {
		ictx, cancel := context.WithTimeout(ctx, insertTimeout)
		err := l.ch.Insert(ictx, DNSQueriesTable, rows...)
		cancel()
		if err == nil {
			dnsExported.Add(float64(len(rows)))
			break
		}
		if ctx.Err() != nil {
			return rows
		}
		if attempt >= dnsAttempts {
			dnsDropped.WithLabelValues("write_failed").Add(float64(len(rows)))
			slog.Warn("DNS query-log rows dropped: ClickHouse did not accept them",
				"rows", len(rows), "attempts", attempt, "error", err)
			break
		}
		select {
		case <-ctx.Done():
			return rows
		case <-time.After(wait):
		}
		wait *= 2
	}
	clear(rows)
	return rows[:0]
}
