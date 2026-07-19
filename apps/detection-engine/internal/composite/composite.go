// Package composite combines corroborating detection signals for one
// client into a single higher-confidence detection (roadmap step 116).
//
// The engine emits per-signal alerts (IoC feed match, Suricata signature,
// TLS heuristic, RITA beacon, Isolation-Forest volumetric anomaly), each
// with its own confidence. On their own most single signals are capped
// below the auto-enforce line by design (a lone beacon maxes at 75, a lone
// volumetric anomaly at 70, a lone SNI/DNS mismatch at 30). Composite
// confidence is what lets *several independent signals about the same
// client* escalate past that line — a beacon AND a volumetric anomaly AND
// a TLS oddity to the same destination is a very different thing than any
// one of them alone.
//
// Signals are combined with a noisy-OR (probabilistic OR): distinct
// signal classes reinforce, repeats of the same class do not. This is
// monotonic (more corroboration never lowers confidence) and saturating
// (never reaches 100 on heuristics alone), and it deliberately does not
// let three weak heuristics fabricate certainty — see combine().
package composite

import (
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// How long a signal about a client stays eligible to corroborate a
	// later one. C2 beaconing plus its volumetric burst can be minutes
	// apart, so the window is generous but bounded.
	defaultWindow = 15 * time.Minute
	// Emit a composite only once its combined confidence clears this; below
	// it the individual alerts already flowed through on their own.
	minEmitConfidence = 50
	maxTrackedClients = 4096
)

var (
	compositesEmitted = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "composites_emitted_total",
		Help:      "Composite detections emitted by number of signal classes.",
	}, []string{"signal_count"})
	compositeConfidence = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "detection_engine",
		Name:      "composite_confidence",
		Help:      "Combined confidence of emitted composite detections.",
		Buckets:   []float64{50, 60, 70, 80, 90, 95, 100},
	})
)

func init() {
	prometheus.MustRegister(compositesEmitted, compositeConfidence)
}

// signal is one contributing detection for a client, kept until it ages out.
type signal struct {
	class      string
	confidence int
	alert      detection.Alert
	seen       time.Time
}

// Correlator accumulates recent per-client signals and, whenever a new
// signal makes a client corroborated by >=2 distinct classes, emits a
// combined composite detection through Emit.
type Correlator struct {
	window time.Duration
	now    func() time.Time
	Emit   func(detection.Alert)

	mu      sync.Mutex
	clients map[string][]signal
}

func New(window time.Duration, emit func(detection.Alert)) *Correlator {
	if window <= 0 {
		window = defaultWindow
	}
	return &Correlator{
		window:  window,
		now:     time.Now,
		Emit:    emit,
		clients: make(map[string][]signal),
	}
}

// Observe records one per-signal alert. Alerts with no client or no signal
// class cannot be correlated and are ignored (they still flowed through the
// normal alert path already). Returns the composite it emitted, if any —
// handy for tests.
func (c *Correlator) Observe(a detection.Alert) *detection.Alert {
	client := a.ClientIP
	if client == "" || a.SignalClass == "" || a.SignalClass == detection.SignalComposite {
		return nil
	}

	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()

	sigs := c.prune(c.clients[client], now)
	sigs = upsert(sigs, signal{
		class:      a.SignalClass,
		confidence: a.Confidence,
		alert:      a,
		seen:       now,
	})
	c.clients[client] = sigs
	c.evict(now)

	classes := distinctClasses(sigs)
	if len(classes) < 2 {
		return nil
	}

	comp := c.build(client, sigs, classes, now)
	if comp.Confidence < minEmitConfidence {
		return nil
	}

	compositesEmitted.WithLabelValues(countLabel(len(classes))).Inc()
	compositeConfidence.Observe(float64(comp.Confidence))
	slog.Warn("composite detection",
		"client", client, "confidence", comp.Confidence,
		"signals", comp.Signals, "severity", comp.Severity,
	)
	if c.Emit != nil {
		c.Emit(comp)
	}
	return &comp
}

// build assembles the composite alert from the highest-confidence signal in
// each distinct class.
func (c *Correlator) build(client string, sigs []signal, classes []string, now time.Time) detection.Alert {
	best := bestPerClass(sigs)
	confs := make([]int, 0, len(classes))
	for _, cl := range classes {
		confs = append(confs, best[cl].confidence)
	}
	combined := combine(confs)

	// carry the richest single signal as the anchor for context
	anchor := best[classes[0]].alert
	for _, cl := range classes {
		if best[cl].confidence > anchor.Confidence {
			anchor = best[cl].alert
		}
	}

	tags := []string{"composite"}
	for _, cl := range classes {
		tags = append(tags, "signal:"+cl)
	}

	return detection.Alert{
		Timestamp:   now,
		Domain:      anchor.Domain,
		ClientIP:    client,
		ClientMAC:   anchor.ClientMAC,
		MatchedIoC:  anchor.MatchedIoC,
		IoCType:     anchor.IoCType,
		Severity:    detection.SeverityForConfidence(combined),
		Source:      "composite",
		Confidence:  combined,
		MitreID:     anchor.MitreID,
		MitreName:   anchor.MitreName,
		Threat:      anchor.Threat,
		Tags:        tags,
		SignalClass: detection.SignalComposite,
		Signals:     classes,
		SignalCount: len(classes),
	}
}

// combine folds independent per-class confidences with a noisy-OR:
//
//	P = 1 - Π(1 - p_i)
//
// Distinct signals reinforce (two 60s → 84), but the result is bounded by
// the strongest single signal's headroom, so many weak heuristics can't
// manufacture certainty: three 30% signals combine to 66, not 90. A single
// high-confidence IoC (90) stays 90 and does not need corroboration.
func combine(confidences []int) int {
	inv := 1.0
	for _, c := range confidences {
		p := clampProb(c)
		inv *= (1 - p)
	}
	combined := (1 - inv) * 100
	return int(combined + 0.5)
}

func clampProb(c int) float64 {
	if c < 0 {
		return 0
	}
	if c > 100 {
		return 1
	}
	return float64(c) / 100
}

// prune drops signals older than the window.
func (c *Correlator) prune(sigs []signal, now time.Time) []signal {
	kept := sigs[:0:0]
	for _, s := range sigs {
		if now.Sub(s.seen) <= c.window {
			kept = append(kept, s)
		}
	}
	return kept
}

// evict caps the number of tracked clients, dropping those whose newest
// signal is oldest. Bounds memory under a scan/flood.
func (c *Correlator) evict(now time.Time) {
	if len(c.clients) <= maxTrackedClients {
		return
	}
	type age struct {
		client string
		newest time.Time
	}
	ages := make([]age, 0, len(c.clients))
	for cl, sigs := range c.clients {
		var newest time.Time
		for _, s := range sigs {
			if s.seen.After(newest) {
				newest = s.seen
			}
		}
		ages = append(ages, age{cl, newest})
	}
	sort.Slice(ages, func(i, j int) bool { return ages[i].newest.Before(ages[j].newest) })
	for i := 0; i < len(ages)-maxTrackedClients; i++ {
		delete(c.clients, ages[i].client)
	}
}

// upsert replaces the existing signal of the same class if the new one is
// at least as confident, so each class keeps its strongest observation.
func upsert(sigs []signal, s signal) []signal {
	for i := range sigs {
		if sigs[i].class == s.class {
			if s.confidence >= sigs[i].confidence {
				sigs[i] = s
			} else {
				sigs[i].seen = s.seen // refresh recency even if weaker
			}
			return sigs
		}
	}
	return append(sigs, s)
}

func bestPerClass(sigs []signal) map[string]signal {
	best := make(map[string]signal)
	for _, s := range sigs {
		if cur, ok := best[s.class]; !ok || s.confidence > cur.confidence {
			best[s.class] = s
		}
	}
	return best
}

func distinctClasses(sigs []signal) []string {
	seen := make(map[string]struct{})
	var classes []string
	for _, s := range sigs {
		if _, ok := seen[s.class]; !ok {
			seen[s.class] = struct{}{}
			classes = append(classes, s.class)
		}
	}
	sort.Strings(classes)
	return classes
}

func countLabel(n int) string {
	switch {
	case n >= 4:
		return "4+"
	case n == 3:
		return "3"
	default:
		return "2"
	}
}
