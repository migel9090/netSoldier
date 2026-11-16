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
//
// Note what noisy-OR does NOT give you, and why the killswitch has a second
// gate (step 124): a beacon capped at 75 plus a volumetric anomaly capped at
// 70 combine to 93, which maps to severity "critical". Two purely local
// heuristics therefore DO clear a 90/critical auto-block bar on confidence
// alone. Escalating confidence is the correct job for this package; deciding
// that heuristics are not sufficient grounds to cut a device off without a
// human is the policy's job, and it keys off signal CLASS (see
// events.IsKnownBadSignal), not the combined number.
package composite

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/libs/events"
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

// correlationKey identifies the device a signal belongs to.
//
// MAC first, IP only as a fallback. Keying on IP alone meant that when a DHCP
// lease moved within the correlation window, signals from two different
// devices merged into one composite — which then inherited whichever device's
// MAC came from the strongest signal and drove enforcement against it. On a
// home network with short leases that is a realistic mis-attribution.
func correlationKey(a detection.Alert) string {
	if a.ClientMAC != "" {
		return "mac:" + strings.ToLower(a.ClientMAC)
	}
	if a.ClientIP != "" {
		return "ip:" + a.ClientIP
	}
	return ""
}

// Observe records one per-signal alert. Alerts with no client or no signal
// class cannot be correlated and are ignored (they still flowed through the
// normal alert path already). Returns the composite it emitted, if any —
// handy for tests.
func (c *Correlator) Observe(a detection.Alert) *detection.Alert {
	client := correlationKey(a)
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

	effective := onePerIndicator(sigs)
	classes := distinctClasses(effective)
	if len(classes) < 2 {
		return nil
	}

	comp := c.build(a, effective, classes, now)
	if comp.Confidence < minEmitConfidence {
		return nil
	}

	compositesEmitted.WithLabelValues(countLabel(len(classes))).Inc()
	compositeConfidence.Observe(float64(comp.Confidence))
	slog.Warn("composite detection",
		"id", comp.ID, "client", client, "confidence", comp.Confidence,
		"signals", classes, "severity", comp.Severity, "target", comp.Target,
	)
	if c.Emit != nil {
		c.Emit(comp)
	}
	return &comp
}

// build assembles the composite alert from the highest-confidence signal in
// each distinct class.
func (c *Correlator) build(trigger detection.Alert, sigs []signal, classes []string, now time.Time) detection.Alert {
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

	// Identity comes from the triggering alert, not from the anchor: the
	// anchor is only chosen for the richest THREAT context, and mixing the
	// two is how a composite ends up pointing at the wrong device.
	clientIP := trigger.ClientIP
	if clientIP == "" {
		clientIP = anchor.ClientIP
	}
	clientMAC := trigger.ClientMAC
	if clientMAC == "" {
		clientMAC = anchor.ClientMAC
	}

	// One signal per class, each with its OWN confidence and indicator, so
	// the receiver can see that a 93 was built from, say, a feed hit at 20
	// and two heuristics — the combined number alone hides that.
	signals := make([]events.Signal, 0, len(classes))
	for _, cl := range classes {
		signals = append(signals, signalOf(best[cl]))
	}

	return detection.Alert{
		// A composite is a detection in its own right: the action it drives
		// must be traceable to it, not to whichever signal triggered it.
		ID:          detection.NewID(),
		Timestamp:   now,
		Summary:     summarize(classes, best, anchor, clientIP),
		Domain:      anchor.Domain,
		ClientIP:    clientIP,
		ClientMAC:   clientMAC,
		ClientName:  trigger.ClientName,
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
		Signals:     signals,
		Target:      compositeTarget(classes, best),
	}
}

// signalOf is the contract signal one contributing alert stands for.
func signalOf(s signal) events.Signal {
	if len(s.alert.Signals) > 0 {
		out := s.alert.Signals[0]
		out.Class = s.class
		return out
	}
	return events.Signal{
		Class:      s.class,
		Confidence: detection.ClampConfidence(s.confidence),
		Source:     s.alert.Source,
	}
}

// compositeTarget picks what a composite may enforce on: the target of the
// strongest known-bad signal that has one, otherwise that of the strongest
// heuristic. The confidence-ranked anchor is deliberately NOT used — it is
// usually a heuristic, and taking its destination is how a weak feed hit on
// one name came to block whatever a beacon pointed at. Whether the chosen
// target is actually vouched for strongly enough is the policy's question
// (events.DetectionEvent.AttestedSignal); this only says what it would be.
//
// A known-bad signal whose indicator is not enforceable (an IDS rule id)
// has no target and so does not take part; the heuristics' destination is
// then the only candidate.
func compositeTarget(classes []string, best map[string]signal) *events.Target {
	var target *events.Target
	for _, knownBad := range []bool{true, false} {
		conf := -1
		for _, cl := range classes {
			s := best[cl]
			if events.IsKnownBadSignal(cl) != knownBad || s.alert.Target == nil || s.confidence <= conf {
				continue
			}
			t := *s.alert.Target
			target, conf = &t, s.confidence
		}
		if target != nil {
			return target
		}
	}
	return nil
}

func summarize(classes []string, best map[string]signal, anchor detection.Alert, client string) string {
	parts := make([]string, 0, len(classes))
	for _, cl := range classes {
		parts = append(parts, fmt.Sprintf("%s %d", cl, best[cl].confidence))
	}
	s := fmt.Sprintf("%d corroborating signals for %s (%s)", len(classes), client, strings.Join(parts, ", "))
	if anchor.Summary != "" {
		s += "; strongest: " + anchor.Summary
	}
	return s
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
//
// A weaker repeat does NOT refresh the stored signal's timestamp. It used to:
// that meant a client emitting a steady trickle of weak signals kept a single
// strong observation alive indefinitely, so the window stopped bounding how
// stale the confidence value driving enforcement could be. A signal's
// recency has to describe when THAT observation was made.
func upsert(sigs []signal, s signal) []signal {
	for i := range sigs {
		if sigs[i].class == s.class {
			if s.confidence >= sigs[i].confidence {
				sigs[i] = s
			}
			return sigs
		}
	}
	return append(sigs, s)
}

// onePerIndicator collapses known-bad signals (feed matches, signatures)
// that attest the same indicator into the strongest of them, whichever
// sensor reported each. noisy-OR assumes its inputs are independent; two
// sensors reporting one feed indicator are one piece of evidence seen twice,
// and counting it twice took a confidence-75 feed match that should wait for
// a human to 94/critical.
//
// Heuristic signals are never collapsed, not into a known-bad signal and not
// into each other, even when they name the same indicator. "A feed lists
// this domain" and "this device contacts it on a schedule" are independent
// kinds of evidence — reputation and behaviour — and their agreeing is
// exactly the corroboration a two-signal auto-block gate asks for. Signals
// without an indicator stand on their own.
func onePerIndicator(sigs []signal) []signal {
	out := make([]signal, 0, len(sigs))
	at := make(map[string]int, len(sigs))
	for _, s := range sigs {
		key := ""
		if events.IsKnownBadSignal(s.class) {
			key = indicatorKey(s.alert)
		}
		if key == "" {
			out = append(out, s)
			continue
		}
		i, dup := at[key]
		if !dup {
			at[key] = len(out)
			out = append(out, s)
			continue
		}
		if s.confidence > out[i].confidence {
			out[i] = s
		}
	}
	return out
}

// indicatorKey is the canonical "type:value" of the indicator an alert's
// signal attests, or "" when it attests none. An untyped value is not
// compared: "x" could be a name, an address or a rule.
func indicatorKey(a detection.Alert) string {
	value, typ := a.MatchedIoC, a.IoCType
	if len(a.Signals) > 0 {
		value, typ = a.Signals[0].Indicator, a.Signals[0].IndicatorType
	}
	value = strings.TrimSpace(value)
	if value == "" || typ == "" {
		return ""
	}
	switch typ {
	case events.IndicatorDomain:
		if d, ok := events.CanonicalDomain(value); ok {
			value = d
		}
	case events.IndicatorIP:
		if ip, ok := events.CanonicalIP(value); ok {
			value = ip
		}
	default:
		value = strings.ToLower(value)
	}
	return strings.ToLower(typ) + ":" + value
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
