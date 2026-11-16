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
// client they name. Lifting a suppression ends that one suppression and
// says nothing about the indicator.
//
// When a verdict was made is always this server's clock. A client-supplied
// timestamp was how a verdict dated 2099 outlived the TTL and, on replay,
// beat every later "confirmed".
//
// The record of verdicts is the service's local store (store.Feedback):
// a verdict is committed there before it applies, and the suppressions are
// rebuilt from there at start-up. ClickHouse, when configured, gets a copy
// (see Forwarder); it is no longer needed for a verdict to survive a
// restart, which in the lite profile — no ClickHouse — it did not.
package feedback

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/store"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	VerdictFalsePositive = "false_positive"
	VerdictConfirmed     = "confirmed"
	// VerdictLifted is not a verdict about a detection but the end of one
	// suppression (POST /feedback/lift). It is recorded, replayed and copied
	// to ClickHouse like a verdict, so that who stopped a suppression, and
	// when, is on record next to who started it.
	VerdictLifted = "lifted"
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
	// DefaultMaxJournal is how many verdicts the local journal may hold
	// before it is compacted down to the ones replay needs. Repeating a
	// verdict for one indicator adds a row but no suppression, so the
	// suppression cap alone does not bound the file.
	DefaultMaxJournal = 2 * DefaultMaxSuppressions
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
		Help:      "Analyst feedback verdicts recorded (lifted: suppressions lifted).",
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
	notPersisted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "feedback_not_persisted_total",
		Help:      "Verdicts applied in memory only: the local store could not record them, or is not on disk. They are lost on restart.",
	})
)

func init() {
	prometheus.MustRegister(feedbackTotal, suppressedTotal, activeSuppressions,
		suppressionsExpired, suppressionsRejected, notPersisted)
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

	// seq is the verdict's place in the journal, 0 when it is not in it.
	seq int64
}

// Suppression is a suppression in force, as GET /feedback lists it: the
// verdict that created it and when it stops silencing detections.
type Suppression struct {
	Verdict
	ExpiresAt time.Time `json:"expires_at"`
}

// Options configures suppression lifetime and capacity.
type Options struct {
	TTL             time.Duration
	MaxSuppressions int
	// AlertLookup finds a stored alert by id, so a verdict posted with an
	// alert_id but no signal_class (what the web UI sends) is scoped to the
	// class of the alert the analyst actually looked at. Optional.
	AlertLookup func(id string) (detection.Alert, bool)
	// Forwarding says a Forwarder copies the journal to ClickHouse: a
	// verdict is then only forgotten locally once it has been copied.
	Forwarding bool
	// Notify is called after a verdict was recorded (Forwarder.Notify).
	Notify func()
	// MaxJournal bounds the journal (DefaultMaxJournal when <= 0).
	MaxJournal int
}

// Store holds the active suppressions in memory, applied on the hot path,
// over the journal that makes them durable.
type Store struct {
	// write serialises the recording of verdicts, so that the journal's
	// order is the order in which they were applied here.
	write        sync.Mutex
	mu           sync.RWMutex
	suppressions map[string]Verdict // key -> the verdict that created it
	journal      *store.Feedback
	// diverged is set once a verdict applied here could not be journaled:
	// from then on replaying the journal no longer gives the suppressions in
	// force, and compaction, which relies on that, waits for a restart.
	diverged bool
	now      func() time.Time
	opts     Options
}

// New returns a store over journal. Without a journal (nil) verdicts live
// in memory only and are reported as not persisted.
func New(journal *store.Feedback) *Store {
	return NewWithOptions(journal, Options{})
}

func NewWithOptions(journal *store.Feedback, opts Options) *Store {
	if opts.TTL <= 0 {
		opts.TTL = DefaultSuppressionTTL
	}
	if opts.MaxSuppressions <= 0 {
		opts.MaxSuppressions = DefaultMaxSuppressions
	}
	if opts.MaxJournal <= 0 {
		opts.MaxJournal = DefaultMaxJournal
	}
	return &Store{
		suppressions: make(map[string]Verdict),
		journal:      journal,
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

// record is Record, also reporting whether the verdict is durably recorded
// in the local store, i.e. survives a restart.
func (s *Store) record(v Verdict) (persisted bool, err error) {
	v, err = normalize(v, false)
	if err != nil {
		return false, err
	}

	s.write.Lock()
	defer s.write.Unlock()
	v.Timestamp = s.now().UTC()
	if v.Verdict == VerdictFalsePositive {
		s.mu.RLock()
		_, exists := s.suppressions[key(v.MatchedIoC, v.ClientIP, v.SignalClass)]
		full := !exists && len(s.suppressions) >= s.opts.MaxSuppressions
		s.mu.RUnlock()
		if full {
			suppressionsRejected.Inc()
			return false, fmt.Errorf("suppression limit reached (%d)", s.opts.MaxSuppressions)
		}
	}
	persisted = s.commit(&v)
	feedbackTotal.WithLabelValues(v.Verdict).Inc()
	slog.Info("feedback recorded", "verdict", v.Verdict, "matched_ioc", v.MatchedIoC,
		"client", v.ClientIP, "signal_class", v.SignalClass, "analyst", v.Analyst,
		"persisted", persisted)
	return persisted, nil
}

// ErrNotSuppressed is returned by Lift when no such suppression is in force.
var ErrNotSuppressed = errors.New("no such suppression is in force")

// Lift ends exactly one suppression — the one for v's indicator, client
// (empty: the indicator-wide one) and signal class — on behalf of v.Analyst.
// Unlike a "confirmed" verdict it says nothing about the indicator and ends
// no other suppression. It returns the suppression it ended and whether the
// lift is durably recorded.
func (s *Store) Lift(v Verdict) (lifted Verdict, persisted bool, err error) {
	v.Verdict, v.AlertID = VerdictLifted, ""
	if v, err = normalize(v, true); err != nil {
		return Verdict{}, false, err
	}

	s.write.Lock()
	defer s.write.Unlock()
	s.mu.RLock()
	cur, ok := s.suppressions[key(v.MatchedIoC, v.ClientIP, v.SignalClass)]
	s.mu.RUnlock()
	if !ok || s.expired(cur) {
		return Verdict{}, false, ErrNotSuppressed
	}
	v.Timestamp = s.now().UTC()
	persisted = s.commit(&v)
	feedbackTotal.WithLabelValues(VerdictLifted).Inc()
	slog.Info("suppression lifted", "matched_ioc", v.MatchedIoC, "client", v.ClientIP,
		"signal_class", v.SignalClass, "analyst", v.Analyst, "suppressed_by", cur.Analyst,
		"suppressed_since", cur.Timestamp, "persisted", persisted)
	return cur, persisted, nil
}

// commit records v in the journal, then applies it. s.write must be held.
//
// A verdict the journal could not take still applies — the analyst's
// decision holds for this process, as it always has — but it is reported as
// not persisted: it is lost on restart, and the analyst must know that.
func (s *Store) commit(v *Verdict) (persisted bool) {
	if s.journal != nil {
		seq, err := s.journal.Append(rowOf(*v))
		if err != nil {
			s.diverged = true
			slog.Error("verdict not recorded in the local store: it applies now but is LOST on restart",
				"verdict", v.Verdict, "matched_ioc", v.MatchedIoC, "error", err)
		} else {
			v.seq, persisted = seq, s.journal.Durable()
		}
	}
	if !persisted {
		notPersisted.Inc()
	}
	s.mu.Lock()
	s.applyLocked(*v)
	s.mu.Unlock()
	if v.seq != 0 && s.opts.Notify != nil {
		s.opts.Notify()
	}
	return persisted
}

// normalize validates a verdict and puts it in canonical form. Replayed
// verdicts go through it too, so history written before the limits existed
// cannot bring oversized entries back. A lift is only valid where lifted is
// set: it is not a verdict a caller of POST /feedback may send.
func normalize(v Verdict, lifted bool) (Verdict, error) {
	v.MatchedIoC = strings.TrimSpace(v.MatchedIoC)
	switch {
	case v.MatchedIoC == "":
		return v, errors.New("matched_ioc required")
	case len(v.MatchedIoC) > MaxIndicatorLen:
		return v, fmt.Errorf("matched_ioc longer than %d bytes", MaxIndicatorLen)
	case v.Verdict != VerdictFalsePositive && v.Verdict != VerdictConfirmed &&
		!(lifted && v.Verdict == VerdictLifted):
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
// every client. A lift ends exactly the suppression it names.
func (s *Store) applyLocked(v Verdict) {
	switch v.Verdict {
	case VerdictFalsePositive:
		s.suppressions[key(v.MatchedIoC, v.ClientIP, v.SignalClass)] = v
	case VerdictLifted:
		delete(s.suppressions, key(v.MatchedIoC, v.ClientIP, v.SignalClass))
	default:
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

// applyLoaded replays one recorded verdict without recording or counting it
// again. It is called in the order the server recorded them.
func (s *Store) applyLoaded(v Verdict) error {
	recorded, seq := v.Timestamp, v.seq
	v, err := normalize(v, true)
	if err != nil {
		return err
	}
	v.Timestamp, v.seq = recorded, seq

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

// Suppressions returns the suppressions in force with when each expires,
// most recent first.
func (s *Store) Suppressions() []Suppression {
	active := s.Active()
	sort.Slice(active, func(i, j int) bool {
		if !active[i].Timestamp.Equal(active[j].Timestamp) {
			return active[i].Timestamp.After(active[j].Timestamp)
		}
		return key(active[i].MatchedIoC, active[i].ClientIP, active[i].SignalClass) <
			key(active[j].MatchedIoC, active[j].ClientIP, active[j].SignalClass)
	})
	out := make([]Suppression, len(active))
	for i, v := range active {
		out[i] = Suppression{Verdict: v, ExpiresAt: v.Timestamp.Add(s.opts.TTL)}
	}
	return out
}

// Restored is what Restore rebuilt the suppressions from.
type Restored struct {
	// Replayed verdicts from the local journal.
	Replayed int
	// Imported: verdicts read from ClickHouse because the journal had never
	// held one — the first start after verdicts moved to the local store.
	Imported int
}

// Restore rebuilds the active suppressions at start-up, before any
// detection is judged, by replaying the journal: the verdicts recorded
// within the TTL, in the order the server recorded them, so the last word
// wins. A verdict dated in the future did not come from this server's
// clock as it is now and is ignored, as is one that is no longer valid.
//
// A journal that has never held a verdict is seeded once from history —
// ClickHouse, where verdicts were kept before — when there is one, so that
// suppressions made before an upgrade survive it. If that fails, the next
// start tries again.
func (s *Store) Restore(ctx context.Context, history Querier) (Restored, error) {
	if s.journal == nil {
		return Restored{}, nil
	}
	if history != nil {
		fresh, err := s.journal.Fresh()
		if err != nil {
			return Restored{}, err
		}
		if fresh {
			n, err := LoadInto(ctx, history, s)
			if err != nil {
				return Restored{}, fmt.Errorf("import verdicts from ClickHouse: %w", err)
			}
			if err := s.adopt(); err != nil {
				return Restored{Imported: n}, fmt.Errorf("record imported verdicts: %w", err)
			}
			return Restored{Imported: n}, nil
		}
	}

	horizon := s.now().Add(clockSkew)
	var res Restored
	var future, invalid int
	err := s.journal.Replay(s.now().Add(-s.opts.TTL), func(r store.FeedbackRow) error {
		if r.RecordedAt.After(horizon) {
			future++
			return nil
		}
		if err := s.applyLoaded(verdictOf(r)); err != nil {
			invalid++
			return nil
		}
		res.Replayed++
		return nil
	})
	if future > 0 {
		slog.Warn("ignored recorded verdicts dated in the future (the clock went back?)", "count", future)
	}
	if invalid > 0 {
		slog.Warn("ignored recorded verdicts that are not valid any more", "count", invalid)
	}
	return res, err
}

// adopt records the suppressions in force — rebuilt from ClickHouse — in
// the journal, as verdicts ClickHouse already has.
func (s *Store) adopt() error {
	s.write.Lock()
	defer s.write.Unlock()
	active := s.Active()
	if len(active) == 0 {
		return nil
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Timestamp.Before(active[j].Timestamp) })
	rows := make([]store.FeedbackRow, len(active))
	for i, v := range active {
		rows[i] = rowOf(v)
	}
	seqs, err := s.journal.Adopt(rows)
	if err != nil {
		s.diverged = true
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, v := range active {
		k := key(v.MatchedIoC, v.ClientIP, v.SignalClass)
		if cur, ok := s.suppressions[k]; ok && cur.Timestamp.Equal(v.Timestamp) {
			cur.seq = seqs[i]
			s.suppressions[k] = cur
		}
	}
	return nil
}

// Maintain applies retention to the journal: verdicts older than the TTL
// suppress nothing and go once ClickHouse has them; beyond MaxJournal the
// journal is compacted to what replay needs.
func (s *Store) Maintain() {
	if s.journal == nil {
		return
	}
	if _, err := s.journal.Prune(s.now().Add(-s.opts.TTL), s.opts.Forwarding); err != nil {
		slog.Warn("feedback retention failed", "error", err)
	}
	n, err := s.journal.Count()
	if err != nil || n <= s.opts.MaxJournal {
		return
	}
	// Held across the compaction: a verdict recorded meanwhile would not be
	// in keep.
	s.write.Lock()
	defer s.write.Unlock()
	if s.diverged {
		return
	}
	s.mu.RLock()
	keep := make([]int64, 0, len(s.suppressions))
	for _, v := range s.suppressions {
		if v.seq != 0 {
			keep = append(keep, v.seq)
		}
	}
	s.mu.RUnlock()
	removed, err := s.journal.Compact(keep, s.opts.Forwarding)
	if err != nil {
		slog.Warn("feedback journal compaction failed", "rows", n, "error", err)
		return
	}
	slog.Info("feedback journal compacted to the verdicts in force", "rows", n, "removed", removed)
}

func rowOf(v Verdict) store.FeedbackRow {
	return store.FeedbackRow{Seq: v.seq, RecordedAt: v.Timestamp, AlertID: v.AlertID,
		MatchedIoC: v.MatchedIoC, ClientIP: v.ClientIP, SignalClass: v.SignalClass,
		Verdict: v.Verdict, Reason: v.Reason, Analyst: v.Analyst}
}

func verdictOf(r store.FeedbackRow) Verdict {
	return Verdict{AlertID: r.AlertID, MatchedIoC: r.MatchedIoC, ClientIP: r.ClientIP,
		SignalClass: r.SignalClass, Verdict: r.Verdict, Reason: r.Reason, Analyst: r.Analyst,
		Timestamp: r.RecordedAt, seq: r.Seq}
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

// decodeRequest reads a verdict request, attributing it to the
// authenticated identity when the request carries one, so "who silenced
// this detection" (or lifted it) is answerable.
func decodeRequest(w http.ResponseWriter, r *http.Request) (Verdict, bool) {
	var req feedbackRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, maxFeedbackBody)).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return Verdict{}, false
	}
	v := Verdict{
		AlertID: req.AlertID, MatchedIoC: req.MatchedIoC, ClientIP: req.ClientIP,
		SignalClass: req.SignalClass, Verdict: req.Verdict, Reason: req.Reason, Analyst: req.Analyst,
	}
	if actor := r.Header.Get("X-Netsoldier-Actor"); actor != "" {
		v.Analyst = actor
	}
	return v, true
}

// HandleFeedback records a verdict posted from the UI.
//
// The caller must already be authenticated (see the auth middleware in
// cmd/detection-engine): a suppression installed here stops a detection from
// ever reaching the killswitch, so this endpoint can disable the response
// pipeline. It needs at least the protection the killswitch's own POST
// endpoints have.
func (s *Store) HandleFeedback(w http.ResponseWriter, r *http.Request) {
	v, ok := decodeRequest(w, r)
	if !ok {
		return
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

// HandleLift serves POST /feedback/lift: it ends the one suppression named
// by matched_ioc, client_ip (empty: the indicator-wide one) and
// signal_class. Authenticated like POST /feedback, for the same reason in
// reverse: lifting a suppression lets detections reach the killswitch again.
func (s *Store) HandleLift(w http.ResponseWriter, r *http.Request) {
	v, ok := decodeRequest(w, r)
	if !ok {
		return
	}
	_, persisted, err := s.Lift(v)
	switch {
	case errors.Is(err, ErrNotSuppressed):
		writeJSONError(w, http.StatusNotFound, err.Error())
		return
	case err != nil:
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "lifted", "persisted": persisted})
}

// HandleList returns the active suppressions, each with its expires_at.
func (s *Store) HandleList(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Suppressions())
}

// writeJSONError encodes the error so a message containing a quote cannot
// produce malformed JSON.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
