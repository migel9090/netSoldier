// Package feedback is the false-positive feedback loop (roadmap step 118).
//
// Analysts mark detections from the UI as false positives; each verdict
// becomes a suppression that keeps matching future detections from
// re-firing (and, crucially, from reaching the killswitch). This closes
// the tuning loop: instead of editing thresholds by hand, operators teach
// the system which (indicator, client) pairs are benign in their network.
//
// Suppression is scoped, never global: a verdict for indicator X on client
// A does not silence X on client B, and an empty client scopes to the
// indicator everywhere. Confirmed (true-positive) verdicts are recorded
// for the FP-rate metric but never suppress.
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
	AlertID    string    `json:"alert_id,omitempty"`
	MatchedIoC string    `json:"matched_ioc"`
	ClientIP   string    `json:"client_ip,omitempty"`
	Verdict    string    `json:"verdict"`
	Reason     string    `json:"reason,omitempty"`
	Analyst    string    `json:"analyst,omitempty"`
	Timestamp  time.Time `json:"timestamp"`
}

// Sink persists verdicts (ClickHouse in production, nil in tests).
type Sink interface {
	Write(Verdict) error
}

// Options configures suppression lifetime and capacity.
type Options struct {
	TTL             time.Duration
	MaxSuppressions int
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

func key(matchedIoC, clientIP string) string {
	return strings.ToLower(strings.TrimSpace(matchedIoC)) + "|" +
		strings.ToLower(strings.TrimSpace(clientIP))
}

// Record validates and stores a verdict, persisting it and (for FP
// verdicts) installing a suppression. Load replays persisted verdicts on
// startup through this same path.
func (s *Store) Record(v Verdict) error {
	if v.MatchedIoC == "" {
		return errors.New("matched_ioc required")
	}
	if v.Verdict != VerdictFalsePositive && v.Verdict != VerdictConfirmed {
		return errors.New("verdict must be false_positive or confirmed")
	}
	if v.Timestamp.IsZero() {
		v.Timestamp = s.now().UTC()
	}

	if v.Analyst == "" {
		return errors.New("analyst required")
	}

	k := key(v.MatchedIoC, v.ClientIP)

	s.mu.Lock()
	if v.Verdict == VerdictFalsePositive {
		if _, exists := s.suppressions[k]; !exists && len(s.suppressions) >= s.opts.MaxSuppressions {
			s.mu.Unlock()
			suppressionsRejected.Inc()
			return fmt.Errorf("suppression limit reached (%d)", s.opts.MaxSuppressions)
		}
		s.suppressions[k] = v
	} else {
		// a confirmed verdict clears any earlier FP suppression
		delete(s.suppressions, k)
	}
	activeSuppressions.Set(float64(len(s.suppressions)))
	s.mu.Unlock()

	feedbackTotal.WithLabelValues(v.Verdict).Inc()

	if s.sink != nil {
		if err := s.sink.Write(v); err != nil {
			slog.Warn("feedback persist failed", "error", err)
		}
	}
	slog.Info("feedback recorded", "verdict", v.Verdict,
		"matched_ioc", v.MatchedIoC, "client", v.ClientIP, "analyst", v.Analyst)
	return nil
}

// expired reports whether a verdict has aged past the suppression TTL.
func (s *Store) expired(v Verdict) bool {
	return s.now().Sub(v.Timestamp) > s.opts.TTL
}

// applyLoaded installs a persisted verdict into the in-memory state
// without re-persisting or re-counting (used by LoadInto on startup).
func (s *Store) applyLoaded(v Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v.Verdict == VerdictFalsePositive {
		// Never replay a verdict that has already aged out, and never
		// exceed the cap when replaying a long history.
		if s.expired(v) || len(s.suppressions) >= s.opts.MaxSuppressions {
			return
		}
		s.suppressions[key(v.MatchedIoC, v.ClientIP)] = v
	} else {
		delete(s.suppressions, key(v.MatchedIoC, v.ClientIP))
	}
	activeSuppressions.Set(float64(len(s.suppressions)))
}

// Suppressed reports whether an alert matches an active, unexpired FP
// suppression, checking the client-scoped key first, then the indicator-wide
// key. An expired suppression stops silencing immediately and is swept from
// the map so the gauge reflects reality.
func (s *Store) Suppressed(a detection.Alert) bool {
	candidates := []string{
		key(a.MatchedIoC, a.ClientIP),
		key(a.MatchedIoC, ""),
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
					"matched_ioc", v.MatchedIoC, "client", v.ClientIP, "age", s.now().Sub(v.Timestamp))
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

// HandleFeedback records a verdict posted from the UI.
//
// The caller must already be authenticated (see the auth middleware in
// cmd/detection-engine): a suppression installed here stops a detection from
// ever reaching the killswitch, so this endpoint can disable the response
// pipeline. It needs at least the protection the killswitch's own POST
// endpoints have.
func (s *Store) HandleFeedback(w http.ResponseWriter, r *http.Request) {
	var v Verdict
	if err := json.NewDecoder(io.LimitReader(r.Body, maxFeedbackBody)).Decode(&v); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	// Attribute the verdict to the authenticated identity when the request
	// carries one, so "who silenced this detection" is answerable.
	if actor := r.Header.Get("X-Netsoldier-Actor"); actor != "" {
		v.Analyst = actor
	}
	if err := s.Record(v); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "recorded"})
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
