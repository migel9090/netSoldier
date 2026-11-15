package detection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
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
	// queryLogBatch is how many querylog entries one poll pulls. Entries
	// older than the batch are dropped by AdGuard's ring buffer before the
	// next poll, so a saturated batch means missed detections — tracked by
	// pollBatchSaturated and alerted on.
	queryLogBatch = 300
)

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
	// A poll that fills its batch means the querylog produced at least as
	// many entries as we asked for, so older unseen entries were left
	// behind and are gone by the next poll. Silent detection loss is the
	// worst failure mode a monitor has: make it a number someone can alert
	// on (step 124).
	pollBatchSaturated = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "poll_batch_saturated_total",
		Help:      "Polls that returned a full batch, meaning querylog entries were likely missed.",
	})
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
		pollBatchSaturated, macResolutionFailures)
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
}

type Engine struct {
	adguard  *adguard.Client
	matcher  *iocmatch.Matcher
	interval time.Duration
	lastSeen time.Time
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
		lastSeen: time.Now(),
	}
}

func (e *Engine) Run(ctx context.Context) {
	slog.Info("detection engine started", "interval", e.interval, "threatlist_size", e.matcher.Size())
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

func (e *Engine) poll(ctx context.Context) {
	entries, err := e.adguard.QueryLog(ctx, queryLogBatch)
	if err != nil {
		pollErrors.Inc()
		slog.Warn("adguard poll failed", "error", err)
		return
	}

	if len(entries) >= queryLogBatch {
		pollBatchSaturated.Inc()
		slog.Warn("querylog batch saturated, entries may have been missed",
			"batch", queryLogBatch, "interval", e.interval)
	}

	// Entries arrive newest-first; stop at the first already-seen timestamp
	for _, entry := range entries {
		if !entry.Time.After(e.lastSeen) {
			break
		}

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
			e.emitAlert(entry, domain, "", ioc)
		}

		for _, ans := range entry.Answer {
			if ans.Type == "A" || ans.Type == "AAAA" {
				if ioc, ok := e.matcher.MatchIP(ans.Value); ok {
					e.emitAlert(entry, domain, ans.Value, ioc)
				}
			}
		}
	}

	if len(entries) > 0 && entries[0].Time.After(e.lastSeen) {
		e.lastSeen = entries[0].Time
	}
}

// emitAlert records a feed match on one querylog entry: on the queried name
// itself when answer is "", otherwise on that A/AAAA answer.
//
// The two cases enforce different things. A domain match targets the feed's
// indicator (the listed parent, not the queried FQDN, which may be one of
// thousands of subdomains). An answer match targets the ADDRESS: the queried
// name is often a shared CDN host, and blocking it would cut off every site
// behind it — so the name stays in Domain, where it is only context.
func (e *Engine) emitAlert(entry adguard.QueryLogEntry, queried, answer string, ioc iocmatch.IoC) {
	alert := Alert{
		ID:          NewID(),
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
