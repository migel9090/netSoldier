package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/adguard"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	maxAlerts = 1000
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

	alertCounter atomic.Int64
)

func init() {
	prometheus.MustRegister(queriesChecked, alertsGenerated, threatlistDomains, pollErrors,
		pollBatchSaturated, macResolutionFailures)
}

type Alert struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Domain      string    `json:"domain"`
	ClientIP    string    `json:"client_ip"`
	ClientMAC   string    `json:"client_mac,omitempty"`
	ClientName  string    `json:"client_name,omitempty"`
	QueryType   string    `json:"query_type"`
	MatchedIoC  string    `json:"matched_ioc"`
	IoCType     string    `json:"ioc_type,omitempty"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Confidence  int       `json:"confidence,omitempty"`
	MitreID     string    `json:"mitre_id,omitempty"`
	MitreName   string    `json:"mitre_name,omitempty"`
	Threat      string    `json:"threat,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	SignalClass string    `json:"signal_class,omitempty"`

	// Composite-confidence output (step 116).
	Signals     []string `json:"signals,omitempty"`
	SignalCount int      `json:"signal_count,omitempty"`
}

type Engine struct {
	adguard     *adguard.Client
	matcher     *iocmatch.Matcher
	interval    time.Duration
	lastSeen    time.Time
	OnAlert     func(Alert)
	OnDNSAnswer func(ip, domain string, ttl int)

	// ResolveClient maps a client IP to its MAC and friendly name. The
	// killswitch allowlist checks MAC first and home DHCP leases move, so a
	// detection without a MAC can only ever be protected by its current IP
	// — which is how an allowlisted router ends up quarantined. Optional:
	// nil leaves ClientMAC empty and increments a counter.
	ResolveClient func(ip string) (mac, name string)

	mu     sync.RWMutex
	alerts []Alert
}

func New(ag *adguard.Client, m *iocmatch.Matcher, interval time.Duration) *Engine {
	threatlistDomains.Set(float64(m.Size()))
	return &Engine{
		adguard:  ag,
		matcher:  m,
		interval: interval,
		lastSeen: time.Now(),
		alerts:   make([]Alert, 0),
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
					e.OnDNSAnswer(ans.Value, domain, ans.TTL)
				}
			}
		}

		if ioc, ok := e.matcher.MatchDomain(domain); ok {
			e.emitAlert(entry, domain, ioc)
		}

		for _, ans := range entry.Answer {
			if ans.Type == "A" || ans.Type == "AAAA" {
				if ioc, ok := e.matcher.MatchIP(ans.Value); ok {
					e.emitAlert(entry, domain+" (→"+ans.Value+")", ioc)
				}
			}
		}
	}

	if len(entries) > 0 && entries[0].Time.After(e.lastSeen) {
		e.lastSeen = entries[0].Time
	}
}

func (e *Engine) emitAlert(entry adguard.QueryLogEntry, domain string, ioc iocmatch.IoC) {
	id := fmt.Sprintf("DET-%d", alertCounter.Add(1))
	alert := Alert{
		ID:          id,
		Timestamp:   entry.Time,
		Domain:      domain,
		ClientIP:    entry.Client,
		QueryType:   entry.Question.Type,
		MatchedIoC:  ioc.Value,
		IoCType:     ioc.Type,
		Severity:    ioc.Severity,
		Source:      ioc.Source,
		Confidence:  ioc.Confidence,
		MitreID:     ioc.MitreID,
		MitreName:   ioc.MitreName,
		Threat:      ioc.Threat,
		Tags:        ioc.Tags,
		SignalClass: SignalIoC,
	}
	alert.ClientMAC, alert.ClientName = e.resolveClient(entry.Client)
	if alert.IoCType == "" {
		alert.IoCType = "domain"
	}
	if alert.Severity == "" {
		alert.Severity = "high"
	}
	if alert.Source == "" {
		alert.Source = "local"
	}

	e.addAlert(alert)
	alertsGenerated.WithLabelValues(alert.Severity).Inc()
	slog.Warn("threat detected",
		"id", id, "domain", domain, "client", entry.Client,
		"matched_ioc", ioc.Value, "severity", alert.Severity,
		"mitre", ioc.MitreID,
	)
}

// Ingest routes an externally-built alert (unified sensor events from
// Suricata/Zeek) through the same path as AdGuard-sourced detections:
// ring buffer, metrics, and the OnAlert fan-out.
func (e *Engine) Ingest(a Alert) {
	if a.ID == "" {
		a.ID = fmt.Sprintf("DET-%d", alertCounter.Add(1))
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

func (e *Engine) addAlert(a Alert) {
	e.mu.Lock()
	e.alerts = append(e.alerts, a)
	if len(e.alerts) > maxAlerts {
		e.alerts = e.alerts[len(e.alerts)-maxAlerts:]
	}
	e.mu.Unlock()

	if e.OnAlert != nil {
		e.OnAlert(a)
	}
}

func (e *Engine) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	e.mu.RLock()
	alerts := make([]Alert, len(e.alerts))
	copy(alerts, e.alerts)
	e.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}
