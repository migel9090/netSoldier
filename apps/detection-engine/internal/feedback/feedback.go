// Package feedback is the false-positive feedback loop (roadmap step 118).
//
// Analysts mark detections from the UI as false positives; each verdict
// becomes a suppression that keeps matching future detections from
// re-firing (and, crucially, from reaching the killswitch). This closes
// the tuning loop: instead of editing thresholds by hand, operators teach
// the system which (indicator, client) pairs are benign in their network.
//
// Suppression is scoped, never global: a verdict for indicator X on client
// A does not silence X on client B, an empty client scopes to the
// indicator everywhere, and a verdict covers one signal class — a benign
// beacon to a vendor's telemetry host says nothing about a feed listing the
// same name. Confirmed (true-positive) verdicts never suppress; they end
// every suppression that would silence that indicator and class for the
// client they name.
//
// When a verdict was made is always this server's clock. A client-supplied
// timestamp was how a verdict dated 2099 outlived the TTL and, on replay,
// beat every later "confirmed".
package feedback

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	VerdictFalsePositive = "false_positive"
	VerdictConfirmed     = "confirmed"
)

const (
	// DefaultSuppressionTTL bounds how long a false-positive verdict keeps
	// silencing a detection.
	//
	// Suppressions used to be permanent and were replayed from ClickHouse on
	// every restart, so one verdict blinded the pipeline for that indicator
	// forever — and because the suppression is checked BEFORE the killswitch
	// webhook, "silenced" means the killswitch never even sees the
	// detection. An indicator that was a false positive in March may be a
	// live C2 domain in June; a tuning decision should expire and be
	// re-confirmed, not outlive the reason it was made.
	DefaultSuppressionTTL = 30 * 24 * time.Hour
	// DefaultMaxSuppressions bounds the in-memory map. Without a cap, the
	// (previously unauthenticated) endpoint could be driven to exhaust the
	// pod's memory with unique indicators.
	DefaultMaxSuppressions = 10000
)

// Per-field limits. With them the count cap is also a size cap: a verdict
// holds at most about 1.5 KiB of caller data, so DefaultMaxSuppressions of
// them stay around 15 MiB. Without them each verdict could carry the whole
// 64 KiB request body.
const (
	MaxIndicatorLen = 255 // a DNS name is at most 253
	MaxAlertIDLen   = 64
	MaxAnalystLen   = 64 // actor names are 1-64 printable ASCII (contract §7)
	MaxReasonLen    = 1024
)

// signalClasses a verdict can be scoped to: the contract's vocabulary.
var signalClasses = map[string]bool{
	events.SignalIoC: true, events.SignalIDS: true, events.SignalTLS: true,
	events.SignalBeacon: true, events.SignalVolumetric: true, events.SignalComposite: true,
}

var (
	feedbackTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "feedback_total",
		Help:      "Analyst feedback verdicts recorded.",
	}, []string{"verdict"})
	suppressedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "alerts_suppressed_total",
		Help:      "Detections suppressed by a false-positive verdict.",
	})
	activeSuppressions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "active_suppressions",
		Help:      "Active false-positive suppressions.",
	})
	suppressionsExpired = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "suppressions_expired_total",
		Help:      "False-positive suppressions that aged out and no longer silence detections.",
	})
	suppressionsRejected = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "suppressions_rejected_total",
		Help:      "Verdicts rejected because the suppression cap was reached.",
	})
)

func init() {
	prometheus.MustRegister(feedbackTotal, suppressedTotal, activeSuppressions,
		suppressionsExpired, suppressionsRejected)
}

// Verdict is one analyst decision about a detection.
type Verdict struct {
	AlertID     string `json:"alert_id,omitempty"`
	MatchedIoC  string `json:"matched_ioc"`
	ClientIP    string `json:"client_ip,omitempty"`
	SignalClass string `json:"signal_class"`
	Verdict     string `json:"verdict"`
	Reason      string `json:"reason,omitempty"`
	Analyst     string `json:"analyst,omitempty"`
	// Timestamp is when this server recorded the verdict. Record assigns
	// it; a caller cannot.
	Timestamp time.Time `json:"timestamp"`
}

// Sink persists verdicts (ClickHouse in production, nil in tests).
type Sink interface {
	Write(Verdict) error
}

// Options configures suppression lifetime and capacity.
type Options struct {
	TTL             time.Duration
	MaxSuppressions int
	// AlertLookup finds a stored alert by id, so a verdict posted with an
	// alert_id but no signal_class (what the web UI sends) is scoped to the
	// class of the alert the analyst actually looked at. Optional.
	AlertLookup func(id string) (detection.Alert, bool)
}

// Store holds active suppressions in memory, applied on the hot path.
type Store struct {
	mu           sync.RWMutex
	suppressions map[string]Verdict // key -> the verdict that created it
	sink         Sink
	now          func() time.Time
	opts         Options
}

func New(sink Sink) *Store {
	return NewWithOptions(sink, Options{})
}

func NewWithOptions(sink Sink, opts Options) *Store {
	if opts.TTL <= 0 {
		opts.TTL = DefaultSuppressionTTL
	}
	if opts.MaxSuppressions <= 0 {
		opts.MaxSuppressions = DefaultMaxSuppressions
	}
	return &Store{
		suppressions: make(map[string]Verdict),
		sink:         sink,
		now:          time.Now,
		opts:         opts,
	}
}

// TTL is how long a false-positive verdict suppresses.
func (s *Store) TTL() time.Duration { return s.opts.TTL }

func key(matchedIoC, clientIP, class string) string {
	return strings.ToLower(strings.TrimSpace(matchedIoC)) + "|" +
		strings.ToLower(strings.TrimSpace(clientIP)) + "|" + class
}

// Record validates and stores a verdict, persisting it and applying it to
// the active suppressions. Its timestamp is always now, on this server.
func (s *Store) Record(v Verdict) error {
	_, err := s.record(v)
	return err
}

// record is Record, also reporting whether the sink accepted the verdict.
func (s *Store) record(v Verdict) (persisted bool, err error) {
	v, err = normalize(v)
	if err != nil {
		return false, err
	}
	v.Timestamp = s.now().UTC()

	s.mu.Lock()
	if v.Verdict == VerdictFalsePositive {
		if _, exists := s.suppressions[key(v.MatchedIoC, v.ClientIP, v.SignalClass)]; !exists &&
			len(s.suppressions) >= s.opts.MaxSuppressions {
			s.mu.Unlock()
			suppressionsRejected.Inc()
			return false, fmt.Errorf("suppression limit reached (%d)", s.opts.MaxSuppressions)
		}
	}
	s.applyLocked(v)
	s.mu.Unlock()

	feedbackTotal.WithLabelValues(v.Verdict).Inc()

	persisted = true
	if s.sink != nil {
		// The sink reports its own failures (Warn + counter). The verdict
		// still applies now, but will not survive a restart.
		persisted = s.sink.Write(v) == nil
	}
	slog.Info("feedback recorded", "verdict", v.Verdict, "matched_ioc", v.MatchedIoC,
		"client", v.ClientIP, "signal_class", v.SignalClass, "analyst", v.Analyst,
		"persisted", persisted)
	return persisted, nil
}

// normalize validates a verdict and puts it in canonical form. Replayed
// verdicts go through it too, so history written before the limits existed
// cannot bring oversized entries back.
func normalize(v Verdict) (Verdict, error) {
	v.MatchedIoC = strings.TrimSpace(v.MatchedIoC)
	switch {
	case v.MatchedIoC == "":
		return v, errors.New("matched_ioc required")
	case len(v.MatchedIoC) > MaxIndicatorLen:
		return v, fmt.Errorf("matched_ioc longer than %d bytes", MaxIndicatorLen)
	case v.Verdict != VerdictFalsePositive && v.Verdict != VerdictConfirmed:
		return v, errors.New("verdict must be false_positive or confirmed")
	case v.SignalClass == "":
		return v, errors.New("signal_class required (or the alert_id of an alert this service still holds)")
	case !signalClasses[v.SignalClass]:
		return v, fmt.Errorf("signal_class %q is not a signal class", v.SignalClass)
	case v.Analyst == "":
		return v, errors.New("analyst required")
	case len(v.Analyst) > MaxAnalystLen:
		return v, fmt.Errorf("analyst longer than %d bytes", MaxAnalystLen)
	case len(v.AlertID) > MaxAlertIDLen:
		return v, fmt.Errorf("alert_id longer than %d bytes", MaxAlertIDLen)
	case len(v.Reason) > MaxReasonLen:
		return v, fmt.Errorf("reason longer than %d bytes", MaxReasonLen)
	}
	if v.ClientIP = strings.TrimSpace(v.ClientIP); v.ClientIP != "" {
		ip, ok := events.CanonicalIP(v.ClientIP)
		if !ok {
			return v, fmt.Errorf("client_ip %q is not an IP address", v.ClientIP)
		}
		v.ClientIP = ip
	}
	return v, nil
}

// applyLocked installs or lifts suppressions for one verdict; s.mu must be
// held.
//
// A confirmed verdict ends every suppression that would silence that
// indicator and class for the client it names — the client's own and the
// indicator-wide one, or "confirmed for this device" would leave the device
// silenced by a broader verdict. Confirmed with no client ends them for
// every client.
func (s *Store) applyLocked(v Verdict) {
	if v.Verdict == VerdictFalsePositive {
		s.suppressions[key(v.MatchedIoC, v.ClientIP, v.SignalClass)] = v
	} else {
		delete(s.suppressions, key(v.MatchedIoC, v.ClientIP, v.SignalClass))
		delete(s.suppressions, key(v.MatchedIoC, "", v.SignalClass))
		if v.ClientIP == "" {
			for k, sv := range s.suppressions {
				if sv.SignalClass == v.SignalClass && strings.EqualFold(sv.MatchedIoC, v.MatchedIoC) {
					delete(s.suppressions, k)
				}
			}
		}
	}
	activeSuppressions.Set(float64(len(s.suppressions)))
}

// expired reports whether a verdict has aged past the suppression TTL.
func (s *Store) expired(v Verdict) bool {
	return s.now().Sub(v.Timestamp) > s.opts.TTL
}

// applyLoaded replays one persisted verdict without re-persisting or
// re-counting it. LoadInto calls it in the order the server recorded them.
func (s *Store) applyLoaded(v Verdict) error {
	recorded := v.Timestamp
	v, err := normalize(v)
	if err != nil {
		return err
	}
	v.Timestamp = recorded

	s.mu.Lock()
	defer s.mu.Unlock()
	if v.Verdict == VerdictFalsePositive {
		// Never replay a verdict that has already aged out, and never
		// exceed the cap when replaying a long history.
		_, exists := s.suppressions[key(v.MatchedIoC, v.ClientIP, v.SignalClass)]
		if s.expired(v) || (!exists && len(s.suppressions) >= s.opts.MaxSuppressions) {
			return nil
		}
	}
	s.applyLocked(v)
	return nil
}

// Suppressed reports whether an alert matches an active, unexpired FP
// suppression for its signal class, checking the client-scoped key first,
// then the indicator-wide key. An expired suppression stops silencing
// immediately and is swept from the map so the gauge reflects reality.
func (s *Store) Suppressed(a detection.Alert) bool {
	if a.MatchedIoC == "" {
		return false
	}
	candidates := []string{
		key(a.MatchedIoC, a.ClientIP, a.SignalClass),
		key(a.MatchedIoC, "", a.SignalClass),
	}

	s.mu.RLock()
	var stale []string
	suppressed := false
	for _, k := range candidates {
		v, ok := s.suppressions[k]
		if !ok {
			continue
		}
		if s.expired(v) {
			stale = append(stale, k)
			continue
		}
		suppressed = true
		break
	}
	s.mu.RUnlock()

	if len(stale) > 0 {
		s.mu.Lock()
		for _, k := range stale {
			if v, ok := s.suppressions[k]; ok && s.expired(v) {
				delete(s.suppressions, k)
				suppressionsExpired.Inc()
				slog.Info("suppression expired, detections resume",
					"matched_ioc", v.MatchedIoC, "client", v.ClientIP,
					"signal_class", v.SignalClass, "age", s.now().Sub(v.Timestamp))
			}
		}
		activeSuppressions.Set(float64(len(s.suppressions)))
		s.mu.Unlock()
	}

	return suppressed
}

// CountSuppressed increments the suppressed-alert metric (called by the
// combiner when it drops a detection).
func (s *Store) CountSuppressed() { suppressedTotal.Inc() }

// Active returns a snapshot of current, unexpired suppressions.
func (s *Store) Active() []Verdict {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Verdict, 0, len(s.suppressions))
	for _, v := range s.suppressions {
		if !s.expired(v) {
			out = append(out, v)
		}
	}
	return out
}

// maxFeedbackBody caps the request body. A verdict is a few hundred bytes.
const maxFeedbackBody = 64 << 10

// feedbackRequest is what a caller may set. There is deliberately no
// timestamp: when a verdict was made is this server's business.
type feedbackRequest struct {
	AlertID     string `json:"alert_id"`
	MatchedIoC  string `json:"matched_ioc"`
	ClientIP    string `json:"client_ip"`
	SignalClass string `json:"signal_class"`
	Verdict     string `json:"verdict"`
	Reason      string `json:"reason"`
	Analyst     string `json:"analyst"`
}

// HandleFeedback records a verdict posted from the UI.
//
// The caller must already be authenticated (see the auth middleware in
// cmd/detection-engine): a suppression installed here stops a detection from
// ever reaching the killswitch, so this endpoint can disable the response
// pipeline. It needs at least the protection the killswitch's own POST
// endpoints have.
func (s *Store) HandleFeedback(w http.ResponseWriter, r *http.Request) {
	var req feedbackRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxFeedbackBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	v := Verdict{
		AlertID: req.AlertID, MatchedIoC: req.MatchedIoC, ClientIP: req.ClientIP,
		SignalClass: req.SignalClass, Verdict: req.Verdict, Reason: req.Reason, Analyst: req.Analyst,
	}
	// Attribute the verdict to the authenticated identity when the request
	// carries one, so "who silenced this detection" is answerable.
	if actor := r.Header.Get("X-Netsoldier-Actor"); actor != "" {
		v.Analyst = actor
	}
	if v.SignalClass == "" && v.AlertID != "" && s.opts.AlertLookup != nil {
		if a, ok := s.opts.AlertLookup(v.AlertID); ok {
			v.SignalClass = a.SignalClass
		}
	}
	persisted, err := s.record(v)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	// persisted=false: the verdict is in force now but will not survive a
	// restart. Say so rather than let the analyst find out after one.
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "recorded", "persisted": persisted})
}

// HandleList returns the active suppressions.
func (s *Store) HandleList(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Active())
}

// writeJSONError encodes the error so a message containing a quote cannot
// produce malformed JSON.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
