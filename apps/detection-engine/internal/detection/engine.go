package detection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultQueryLogPageSize is how many entries one querylog request asks
	// for.
	DefaultQueryLogPageSize = 500
	// DefaultQueryLogMaxPages bounds one poll (QUERYLOG_MAX_PAGES). A poll
	// pages back until it reaches what the previous poll already checked;
	// the bound only matters when a device floods the resolver, and hitting
	// it is reported as a gap.
	DefaultQueryLogMaxPages = 40
	// DefaultQueryLogOverlap is how far behind the newest checked entry a
	// poll keeps looking (QUERYLOG_OVERLAP). AdGuard stamps an entry with the
	// time the query arrived but logs it when the answer is back, so a slow
	// lookup — and a C2 domain's own name server can be made slow on purpose
	// — appears after entries that are newer than it. The overlap must cover
	// AdGuard's upstream timeout (10 s by default).
	DefaultQueryLogOverlap = 15 * time.Second
	// DefaultLookback is how far back reading starts when there is no stored
	// position, and the oldest stored position that is honoured
	// (INGEST_LOOKBACK). Older than that, a detection is history rather than
	// something to act on.
	DefaultLookback = time.Hour

	// queryLogCursor names the querylog's position in the cursor store.
	queryLogCursor = "adguard_querylog"
	// maxSeenEntries caps the de-duplication memory of the overlap window.
	maxSeenEntries = 200000
)

// CursorStore persists how far an input has been read (*store.Cursors).
type CursorStore interface {
	Load(source string) (position []byte, updated time.Time, ok bool, err error)
	Save(source string, position []byte) error
}

// Severity vocabulary shared with libs/events and the killswitch policy.
const (
	SeverityCritical = events.SeverityCritical
	SeverityHigh     = events.SeverityHigh
	SeverityMedium   = events.SeverityMedium
	SeverityLow      = events.SeverityLow
)

// SeverityForConfidence maps a 0-100 confidence to the severity vocabulary,
// matching iocmatch.DeriveSeverity so composite detections bucket the same
// way single-signal ones do.
func SeverityForConfidence(confidence int) string {
	switch {
	case confidence >= 90:
		return SeverityCritical
	case confidence >= 70:
		return SeverityHigh
	case confidence >= 50:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// Signal classes label where a detection came from, so composite-confidence
// (step 116) can tell corroborating signals apart from repeats of the same
// kind. Only distinct classes corroborate each other.
//
// These alias the shared contract in libs/events: the killswitch policy gates
// auto-enforcement on signal KIND (feed/signature vs. heuristic), so producer
// and consumer must not keep independent copies of these strings.
const (
	SignalIoC        = events.SignalIoC
	SignalIDS        = events.SignalIDS
	SignalTLS        = events.SignalTLS
	SignalBeacon     = events.SignalBeacon
	SignalVolumetric = events.SignalVolumetric
	SignalComposite  = events.SignalComposite
)

var (
	queriesChecked = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "queries_checked_total",
		Help:      "Total DNS queries checked against threat list.",
	})
	alertsGenerated = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "alerts_generated_total",
		Help:      "Total detection alerts generated.",
	}, []string{"severity"})
	threatlistDomains = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "threatlist_domains_total",
		Help:      "Number of domains in the active threat list.",
	})
	pollErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "poll_errors_total",
		Help:      "Total AdGuard querylog poll errors.",
	})
	queryLogPages = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "querylog_pages_total",
		Help:      "AdGuard querylog pages read.",
	})
	// A gap is a stretch of the querylog no poll checked: the page bound
	// was reached before the entries the previous poll had already seen.
	// Every query in it may have been a detection. Silent detection loss is
	// the worst failure mode a monitor has, so it is a number to alert on.
	queryLogGaps = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "querylog_gaps_total",
		Help:      "Polls that stopped at the page bound, leaving querylog entries unchecked.",
	})
	// The same event under the name the existing DetectionQueryLogSaturated
	// alert rule reads.
	pollBatchSaturated = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "poll_batch_saturated_total",
		Help:      "Same as querylog_gaps_total; kept for existing alert rules.",
	})
	cursorClamped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "ingest_cursor_clamped_total",
		Help:      "Starts whose stored read position was older than INGEST_LOOKBACK, so the records in between were skipped.",
	}, []string{"source"})
	macResolutionFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "mac_resolution_failures_total",
		Help:      "Detections emitted without a client MAC (allowlist can only match on IP).",
	})

	alertCounter atomic.Uint64
	idPrefix     atomic.Pointer[string]
)

func init() {
	prometheus.MustRegister(queriesChecked, alertsGenerated, threatlistDomains, pollErrors,
		queryLogPages, queryLogGaps, pollBatchSaturated, cursorClamped, macResolutionFailures)
	p := defaultIDPrefix()
	idPrefix.Store(&p)
}

// NewID returns the next detection id, DET-<instance prefix>-<n>.
//
// A bare counter restarted at DET-1 on every boot, so the same id named
// different detections over the service's lifetime and an action's
// detection_id could not be traced back. The per-process prefix makes ids
// unique across restarts; the counter keeps them ordered within one.
func NewID() string {
	return events.FormatDetectionID(*idPrefix.Load(), alertCounter.Add(1))
}

// Record names the input record a detection comes from: source is the input
// ("adguard", a sensor table), key the record within it — and, when one
// record can make several detections, which one. Inputs are re-read on
// purpose (the readers look a little behind where they stopped, so nothing
// that landed late is skipped); the pipeline uses this to recognise a record
// it has already turned into a detection.
func Record(source, key string) string { return source + "\x00" + key }

// SetIDPrefix replaces the per-process id prefix (DETECTION_ID_PREFIX). It
// must be alphanumeric so ids keep the contract's shape.
func SetIDPrefix(prefix string) error {
	if !events.ValidIDPrefix(prefix) {
		return fmt.Errorf("id prefix %q must be non-empty and alphanumeric", prefix)
	}
	idPrefix.Store(&prefix)
	return nil
}

// IDPrefix returns the current per-process id prefix.
func IDPrefix() string { return *idPrefix.Load() }

// defaultIDPrefix is the start time in base 36 plus 24 random bits: two
// processes collide only if they start in the same second AND draw the same
// random suffix. The hostname would read better but pod names carry dashes,
// which the id pattern reserves as the separator.
func defaultIDPrefix() string {
	var b [3]byte
	_, _ = rand.Read(b[:]) // never fails: crypto/rand aborts the process instead
	return strconv.FormatInt(time.Now().Unix(), 36) + hex.EncodeToString(b[:])
}

// ClampConfidence bounds a confidence to the contract's 0-100. Feed data is
// third-party input; an out-of-range value would make the whole event
// invalid and lose the detection.
func ClampConfidence(c int) int {
	switch {
	case c < 0:
		return 0
	case c > 100:
		return 100
	default:
		return c
	}
}

// Alert is the engine's record of one detection; eventmap turns it into the
// shared events.DetectionEvent. It is also what GET /alerts returns (the
// store persists it as this JSON).
type Alert struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	// Summary is the human-readable description and the only field meant
	// for display.
	Summary string `json:"summary"`
	// Domain is the DNS name actually observed (the queried name), or "".
	// Never rule text, an address, a fingerprint or a decorated string.
	Domain     string `json:"domain"`
	ClientIP   string `json:"client_ip"`
	ClientMAC  string `json:"client_mac,omitempty"`
	ClientName string `json:"client_name,omitempty"`
	QueryType  string `json:"query_type"`
	// MatchedIoC/IoCType are the indicator of the strongest signal: display
	// and the false-positive suppression key.
	MatchedIoC  string   `json:"matched_ioc"`
	IoCType     string   `json:"ioc_type,omitempty"`
	Severity    string   `json:"severity"`
	Source      string   `json:"source"`
	Confidence  int      `json:"confidence,omitempty"`
	MitreID     string   `json:"mitre_id,omitempty"`
	MitreName   string   `json:"mitre_name,omitempty"`
	Threat      string   `json:"threat,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	SignalClass string   `json:"signal_class,omitempty"`

	// Signals is the evidence, one entry per contributing signal with its
	// own confidence and attested indicator; a composite carries one per
	// distinct class.
	Signals []events.Signal `json:"signals,omitempty"`
	// Target is what enforcement may act on, or nil when the detection
	// names nothing concrete. Producers set it; nothing downstream may
	// derive it from Domain or Summary.
	Target *events.Target `json:"target,omitempty"`

	// Suppressed marks an alert recorded while an analyst's false-positive
	// verdict applied to it: kept in the history, but neither correlated nor
	// delivered. Without it the history showed such an alert as new, and the
	// analyst who silenced the indicator kept seeing it come back. Absent
	// from the JSON otherwise.
	Suppressed bool `json:"suppressed,omitempty"`

	// Record is the input record the detection came from (see Record), or
	// "" for one that has none (a composite). Internal only.
	Record string `json:"-"`
}

// NoteCursorClamped counts a start whose stored position for source was
// older than the look-back, i.e. records were skipped.
func NoteCursorClamped(source string) { cursorClamped.WithLabelValues(source).Inc() }

type Engine struct {
	adguard  *adguard.Client
	matcher  *iocmatch.Matcher
	interval time.Duration

	// Cursors keeps the querylog position across restarts; nil keeps it in
	// memory only. The settings below fall back to their defaults when <= 0.
	Cursors  CursorStore
	PageSize int
	MaxPages int
	Overlap  time.Duration
	Lookback time.Duration
	now      func() time.Time

	started bool
	// lastSeen is the newest entry time checked. Polls re-read Overlap
	// behind it; seen holds the entries in that window that were already
	// checked, so a re-read is not a second detection.
	lastSeen time.Time
	seen     map[string]time.Time

	// OnAlert receives every detection (the alert pipeline: store,
	// suppression, correlation, delivery).
	OnAlert func(Alert)
	// OnDNSAnswer receives every A/AAAA answer a client got, for the TLS
	// heuristics' per-client resolution cache.
	OnDNSAnswer func(client, ip, domain string, ttl int)

	// ResolveClient maps a client IP to its MAC and friendly name. The
	// killswitch allowlist checks MAC first and home DHCP leases move, so a
	// detection without a MAC can only ever be protected by its current IP
	// — which is how an allowlisted router ends up quarantined. nil leaves
	// ClientMAC empty and increments a counter.
	ResolveClient func(ip string) (mac, name string)
}

func New(ag *adguard.Client, m *iocmatch.Matcher, interval time.Duration) *Engine {
	threatlistDomains.Set(float64(m.Size()))
	return &Engine{
		adguard:  ag,
		matcher:  m,
		interval: interval,
		now:      time.Now,
		seen:     make(map[string]time.Time),
	}
}

func (e *Engine) Run(ctx context.Context) {
	e.start()
	slog.Info("detection engine started", "interval", e.interval, "threatlist_size", e.matcher.Size(),
		"querylog_from", e.lastSeen)
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.poll(ctx)
		}
	}
}

func (e *Engine) pageSize() int { return positiveOr(e.PageSize, DefaultQueryLogPageSize) }
func (e *Engine) maxPages() int { return positiveOr(e.MaxPages, DefaultQueryLogMaxPages) }
func (e *Engine) overlap() time.Duration {
	return positiveDurOr(e.Overlap, DefaultQueryLogOverlap)
}
func (e *Engine) lookback() time.Duration {
	return positiveDurOr(e.Lookback, DefaultLookback)
}

// start sets where reading begins: the stored position, or the look-back
// when there is none or it is older than the look-back. Starting at "now"
// meant every query logged while the pod was down, or not yet polled when it
// stopped, was never checked.
func (e *Engine) start() {
	if e.started {
		return
	}
	e.started = true
	floor := e.now().Add(-e.lookback())
	e.lastSeen = floor
	if e.Cursors == nil {
		return
	}
	raw, _, ok, err := e.Cursors.Load(queryLogCursor)
	if err != nil {
		slog.Warn("querylog position unreadable: looking back instead", "lookback", e.lookback(), "error", err)
		return
	}
	if !ok {
		slog.Info("no stored querylog position: looking back", "lookback", e.lookback())
		return
	}
	var pos queryLogPosition
	if err := json.Unmarshal(raw, &pos); err != nil || pos.LastSeen.IsZero() {
		slog.Warn("stored querylog position is malformed: looking back instead", "lookback", e.lookback())
		return
	}
	if pos.LastSeen.Before(floor) {
		NoteCursorClamped("adguard")
		slog.Warn("stored querylog position is older than INGEST_LOOKBACK: queries in between are not checked",
			"stored", pos.LastSeen, "resuming_at", floor)
		return
	}
	e.lastSeen = pos.LastSeen
}

type queryLogPosition struct {
	LastSeen time.Time `json:"last_seen"`
}

// poll checks every querylog entry logged since the previous poll.
//
// It pages back from the newest entry until it reaches entries older than
// the overlap behind the last checked one. Reading one fixed batch was a
// blind spot anyone could aim at: a C2 lookup followed by as many junk
// queries as the batch held was never checked. Paging is bounded so a flood
// cannot stall the poller; reaching the bound is a gap, which is counted and
// logged, because the queries in it are detections that may have been
// missed.
func (e *Engine) poll(ctx context.Context) {
	e.start()
	horizon := e.lastSeen.Add(-e.overlap())
	newest := e.lastSeen
	limit := e.pageSize()

	var olderThan, oldestRead time.Time
	pages, reached := 0, false
	for !reached && pages < e.maxPages() {
		page, err := e.adguard.QueryLog(ctx, olderThan, limit)
		if err != nil {
			// Nothing advances: the next poll reads this stretch again, and
			// what was already checked is skipped as seen.
			pollErrors.Inc()
			slog.Warn("adguard poll failed", "error", err, "pages_read", pages)
			return
		}
		pages++
		queryLogPages.Inc()
		for _, entry := range page.Entries {
			if entry.Time.Before(horizon) {
				reached = true
				continue
			}
			key := entryKey(entry)
			if _, dup := e.seen[key]; dup {
				continue
			}
			e.seen[key] = entry.Time
			e.check(entry, key)
			if entry.Time.After(newest) {
				newest = entry.Time
			}
		}
		if len(page.Entries) < limit {
			reached = true // nothing older left
			break
		}
		if !olderThan.IsZero() && !page.Oldest.Before(olderThan) {
			// The server did not move back (it ignores older_than): there is
			// no way to read further, which is a gap like the bound.
			break
		}
		olderThan, oldestRead = page.Oldest, page.Oldest
	}
	if !reached {
		queryLogGaps.Inc()
		pollBatchSaturated.Inc()
		slog.Warn("querylog gap: page limit reached before the last checked entry, queries in between were not checked",
			"pages", pages, "page_size", limit, "unchecked_after", horizon, "unchecked_before", oldestRead,
			"hint", "raise QUERYLOG_MAX_PAGES or shorten POLL_INTERVAL")
	}

	// An entry stamped in the future (a clock that jumped) must not move the
	// position past entries that are still to come.
	if now := e.now(); newest.After(now) {
		newest = now
	}
	if newest.After(e.lastSeen) {
		e.lastSeen = newest
		e.saveCursor()
	}
	e.forget()
}

// check matches one querylog entry against the indicators.
func (e *Engine) check(entry adguard.QueryLogEntry, key string) {
	queriesChecked.Inc()
	domain := strings.ToLower(strings.TrimSuffix(entry.Question.Host, "."))

	if e.OnDNSAnswer != nil {
		for _, ans := range entry.Answer {
			if ans.Type == "A" || ans.Type == "AAAA" {
				e.OnDNSAnswer(entry.Client, ans.Value, domain, ans.TTL)
			}
		}
	}

	if ioc, ok := e.matcher.MatchDomain(domain); ok {
		e.emitAlert(entry, key, domain, "", ioc)
	}

	for _, ans := range entry.Answer {
		if ans.Type == "A" || ans.Type == "AAAA" {
			if ioc, ok := e.matcher.MatchIP(ans.Value); ok {
				e.emitAlert(entry, key, domain, ans.Value, ioc)
			}
		}
	}
}

// entryKey identifies one querylog entry. AdGuard stamps entries with
// nanosecond precision, so the time plus who asked what is unique.
func entryKey(entry adguard.QueryLogEntry) string {
	return entry.Time.UTC().Format(time.RFC3339Nano) + "|" + entry.Client + "|" +
		entry.Question.Host + "|" + entry.Question.Type
}

// forget drops seen entries that have left the overlap window, and caps the
// rest: a flood must not grow it without bound.
func (e *Engine) forget() {
	cutoff := e.lastSeen.Add(-e.overlap())
	for k, t := range e.seen {
		if t.Before(cutoff) {
			delete(e.seen, k)
		}
	}
	if len(e.seen) <= maxSeenEntries {
		return
	}
	times := make([]time.Time, 0, len(e.seen))
	for _, t := range e.seen {
		times = append(times, t)
	}
	slices.SortFunc(times, func(a, b time.Time) int { return a.Compare(b) })
	cut := times[len(times)-maxSeenEntries]
	for k, t := range e.seen {
		if t.Before(cut) {
			delete(e.seen, k)
		}
	}
}

func (e *Engine) saveCursor() {
	if e.Cursors == nil {
		return
	}
	raw, _ := json.Marshal(queryLogPosition{LastSeen: e.lastSeen})
	if err := e.Cursors.Save(queryLogCursor, raw); err != nil {
		slog.Warn("querylog position not saved: a restart re-checks from the previous one", "error", err)
	}
}

func positiveOr(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func positiveDurOr(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

// emitAlert records a feed match on one querylog entry: on the queried name
// itself when answer is "", otherwise on that A/AAAA answer.
//
// The two cases enforce different things. A domain match targets the feed's
// indicator (the listed parent, not the queried FQDN, which may be one of
// thousands of subdomains). An answer match targets the ADDRESS: the queried
// name is often a shared CDN host, and blocking it would cut off every site
// behind it — so the name stays in Domain, where it is only context.
func (e *Engine) emitAlert(entry adguard.QueryLogEntry, key, queried, answer string, ioc iocmatch.IoC) {
	alert := Alert{
		ID:          NewID(),
		Record:      Record("adguard", key+"|"+answer),
		Timestamp:   entry.Time,
		Domain:      queried,
		ClientIP:    canonicalOrRaw(entry.Client),
		QueryType:   entry.Question.Type,
		MatchedIoC:  ioc.Value,
		IoCType:     ioc.Type,
		Severity:    ioc.Severity,
		Source:      ioc.Source,
		Confidence:  ClampConfidence(ioc.Confidence),
		MitreID:     ioc.MitreID,
		MitreName:   ioc.MitreName,
		Threat:      ioc.Threat,
		Tags:        ioc.Tags,
		SignalClass: SignalIoC,
	}
	alert.ClientMAC, alert.ClientName = e.resolveClient(alert.ClientIP)
	if alert.Severity == "" {
		alert.Severity = "high"
	}
	if alert.Source == "" {
		alert.Source = "local"
	}

	if answer == "" {
		alert.IoCType = events.IndicatorDomain
		if d, ok := events.CanonicalDomain(ioc.Value); ok {
			alert.MatchedIoC = d
			alert.Target = &events.Target{Type: events.TargetDomain, Value: d}
		}
		alert.Summary = fmt.Sprintf("DNS query for %s matches %s domain indicator %s",
			queried, alert.Source, alert.MatchedIoC)
	} else {
		// MatchIP returns the feed entry, which is a CIDR when the address
		// matched a listed range: the feed attests the range, the target is
		// the address that was actually answered.
		alert.IoCType = events.IndicatorIP
		if strings.Contains(ioc.Value, "/") {
			alert.IoCType = events.IndicatorCIDR
		}
		addr := canonicalOrRaw(answer)
		if _, ok := events.CanonicalIP(addr); ok {
			alert.Target = &events.Target{Type: events.TargetIP, Value: addr}
		}
		alert.Summary = fmt.Sprintf("DNS answer %s for %s matches %s %s indicator %s",
			addr, queried, alert.Source, alert.IoCType, ioc.Value)
	}
	if ioc.Threat != "" {
		alert.Summary += " (" + ioc.Threat + ")"
	}
	alert.Signals = []events.Signal{{
		Class:         SignalIoC,
		Confidence:    alert.Confidence,
		Indicator:     alert.MatchedIoC,
		IndicatorType: alert.IoCType,
		Source:        alert.Source,
	}}

	e.addAlert(alert)
	alertsGenerated.WithLabelValues(alert.Severity).Inc()
	slog.Warn("threat detected",
		"id", alert.ID, "domain", queried, "answer", answer, "client", entry.Client,
		"matched_ioc", ioc.Value, "severity", alert.Severity,
		"mitre", ioc.MitreID,
	)
}

// canonicalOrRaw returns the canonical form of an address, or the input
// unchanged when it does not parse (the event will then fail validation and
// be reported, rather than silently carry a guessed address).
func canonicalOrRaw(ip string) string {
	if c, ok := events.CanonicalIP(ip); ok {
		return c
	}
	return ip
}

// Ingest routes an externally-built alert (unified sensor events from
// Suricata/Zeek) through the same path as AdGuard-sourced detections:
// client resolution, metrics, and the OnAlert fan-out.
func (e *Engine) Ingest(a Alert) {
	if a.ID == "" {
		a.ID = NewID()
	}
	if a.Severity == "" {
		a.Severity = "medium"
	}
	if a.ClientMAC == "" {
		a.ClientMAC, a.ClientName = e.resolveClient(a.ClientIP)
	}
	e.addAlert(a)
	alertsGenerated.WithLabelValues(a.Severity).Inc()
	slog.Warn("sensor threat detected",
		"id", a.ID, "matched_ioc", a.MatchedIoC, "client", a.ClientIP,
		"severity", a.Severity, "source", a.Source,
	)
}

// resolveClient enriches a detection with the device identity the killswitch
// allowlist needs. Failure is counted, never fatal: enforcement still has the
// IP, and a missing MAC must not stop a detection from being reported.
func (e *Engine) resolveClient(ip string) (mac, name string) {
	if e.ResolveClient == nil || ip == "" {
		macResolutionFailures.Inc()
		return "", ""
	}
	mac, name = e.ResolveClient(ip)
	if mac == "" {
		macResolutionFailures.Inc()
	}
	return mac, name
}

// addAlert hands a detection to the alert pipeline, which persists it.
func (e *Engine) addAlert(a Alert) {
	if e.OnAlert != nil {
		e.OnAlert(a)
	}
}
