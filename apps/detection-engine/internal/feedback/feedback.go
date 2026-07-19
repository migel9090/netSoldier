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
)

func init() {
	prometheus.MustRegister(feedbackTotal, suppressedTotal, activeSuppressions)
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

// Store holds active suppressions in memory, applied on the hot path.
type Store struct {
	mu           sync.RWMutex
	suppressions map[string]Verdict // key -> the verdict that created it
	sink         Sink
	now          func() time.Time
}

func New(sink Sink) *Store {
	return &Store{
		suppressions: make(map[string]Verdict),
		sink:         sink,
		now:          time.Now,
	}
}

func key(matchedIoC, clientIP string) string {
	return strings.ToLower(matchedIoC) + "|" + clientIP
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

	feedbackTotal.WithLabelValues(v.Verdict).Inc()

	s.mu.Lock()
	if v.Verdict == VerdictFalsePositive {
		s.suppressions[key(v.MatchedIoC, v.ClientIP)] = v
	} else {
		// a confirmed verdict clears any earlier FP suppression
		delete(s.suppressions, key(v.MatchedIoC, v.ClientIP))
	}
	activeSuppressions.Set(float64(len(s.suppressions)))
	s.mu.Unlock()

	if s.sink != nil {
		if err := s.sink.Write(v); err != nil {
			slog.Warn("feedback persist failed", "error", err)
		}
	}
	slog.Info("feedback recorded", "verdict", v.Verdict,
		"matched_ioc", v.MatchedIoC, "client", v.ClientIP)
	return nil
}

// applyLoaded installs a persisted verdict into the in-memory state
// without re-persisting or re-counting (used by LoadInto on startup).
func (s *Store) applyLoaded(v Verdict) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v.Verdict == VerdictFalsePositive {
		s.suppressions[key(v.MatchedIoC, v.ClientIP)] = v
	} else {
		delete(s.suppressions, key(v.MatchedIoC, v.ClientIP))
	}
	activeSuppressions.Set(float64(len(s.suppressions)))
}

// Suppressed reports whether an alert matches an active FP suppression,
// checking the client-scoped key first, then the indicator-wide key.
func (s *Store) Suppressed(a detection.Alert) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.suppressions[key(a.MatchedIoC, a.ClientIP)]; ok {
		return true
	}
	_, ok := s.suppressions[key(a.MatchedIoC, "")]
	return ok
}

// CountSuppressed increments the suppressed-alert metric (called by the
// combiner when it drops a detection).
func (s *Store) CountSuppressed() { suppressedTotal.Inc() }

// Active returns a snapshot of current suppressions.
func (s *Store) Active() []Verdict {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Verdict, 0, len(s.suppressions))
	for _, v := range s.suppressions {
		out = append(out, v)
	}
	return out
}

// HandleFeedback records a verdict posted from the UI.
func (s *Store) HandleFeedback(w http.ResponseWriter, r *http.Request) {
	var v Verdict
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		http.Error(w, `{"error":"invalid body"}`, http.StatusBadRequest)
		return
	}
	if err := s.Record(v); err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
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
