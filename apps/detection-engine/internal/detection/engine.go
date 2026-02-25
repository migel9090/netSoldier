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
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/threatlist"
	"github.com/prometheus/client_golang/prometheus"
)

const maxAlerts = 1000

var (
	queriesChecked = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "queries_checked_total",
		Help:      "Total DNS queries checked against threat list.",
	})
	alertsGenerated = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "alerts_generated_total",
		Help:      "Total detection alerts generated.",
	})
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

	alertCounter atomic.Int64
)

func init() {
	prometheus.MustRegister(queriesChecked, alertsGenerated, threatlistDomains, pollErrors)
}

type Alert struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Domain     string    `json:"domain"`
	ClientIP   string    `json:"client_ip"`
	QueryType  string    `json:"query_type"`
	MatchedIoC string    `json:"matched_ioc"`
	Severity   string    `json:"severity"`
	Source     string    `json:"source"`
}

type Engine struct {
	adguard  *adguard.Client
	matcher  *threatlist.Matcher
	interval time.Duration
	lastSeen time.Time
	OnAlert  func(Alert)

	mu     sync.RWMutex
	alerts []Alert
}

func New(ag *adguard.Client, m *threatlist.Matcher, interval time.Duration) *Engine {
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
	entries, err := e.adguard.QueryLog(ctx, 300)
	if err != nil {
		pollErrors.Inc()
		slog.Warn("adguard poll failed", "error", err)
		return
	}

	// Entries arrive newest-first; stop at the first already-seen timestamp
	for _, entry := range entries {
		if !entry.Time.After(e.lastSeen) {
			break
		}

		queriesChecked.Inc()
		domain := strings.ToLower(strings.TrimSuffix(entry.Question.Host, "."))
		matched, ok := e.matcher.Match(domain)
		if !ok {
			continue
		}

		id := fmt.Sprintf("DET-%d", alertCounter.Add(1))
		alert := Alert{
			ID:         id,
			Timestamp:  entry.Time,
			Domain:     domain,
			ClientIP:   entry.Client,
			QueryType:  entry.Question.Type,
			MatchedIoC: matched,
			Severity:   "high",
			Source:     "threatfox-static",
		}

		e.addAlert(alert)
		alertsGenerated.Inc()
		slog.Warn("threat detected",
			"id", id,
			"domain", domain,
			"client", entry.Client,
			"matched_ioc", matched,
		)
	}

	if len(entries) > 0 && entries[0].Time.After(e.lastSeen) {
		e.lastSeen = entries[0].Time
	}
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
