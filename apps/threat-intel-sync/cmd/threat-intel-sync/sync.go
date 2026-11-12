package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// This service had no /metrics endpoint at all, which meant feed health
	// was unobservable: a sync that had been failing for weeks looked
	// exactly like a quiet network. Stale threat intel is a silent
	// detection gap, so it needs to be a number someone can alert on.
	syncLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_last_success_timestamp_seconds",
		Help:      "Unix timestamp of the last successful fetch per source (0 = never).",
	}, []string{"source"})
	syncFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_failures_total",
		Help:      "Feed fetch failures per source, including responses from which nothing was accepted.",
	}, []string{"source"})
	indicatorsFetched = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_indicators",
		Help:      "Indicators accepted from the most recent successful fetch per source.",
	}, []string{"source"})
	indicatorsRejected = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_indicators_rejected_total",
		Help:      "Indicators dropped as unsafe or malformed per source.",
	}, []string{"source"})
	indicatorsDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_indicators_dropped_total",
		Help:      "Valid indicators refused because the store is at INDICATOR_STORE_MAX.",
	}, []string{"source"})
	sourceEnabled = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_enabled",
		Help:      "1 if the source is configured and fetched, 0 if it is disabled (see the start-up log for why).",
	}, []string{"source"})
	storeSize = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "store_indicators",
		Help:      "Total unique indicators currently in the store.",
	})
	storeCapacity = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "store_capacity",
		Help:      "Maximum number of unique indicators the store accepts (INDICATOR_STORE_MAX).",
	})
	storePersistent = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "store_persistent",
		Help:      "1 if the store is backed by INDICATOR_DB_PATH, 0 if it is memory-only.",
	})
	storePersistErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "store_persist_errors_total",
		Help:      "Failed writes to the indicator database.",
	})
	indicatorsPruned = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "indicators_pruned_total",
		Help:      "Indicators removed because no feed has re-asserted them.",
	})
	cycleLastComplete = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "sync_cycle_last_complete_timestamp_seconds",
		Help:      "Unix timestamp of the last completed sync cycle.",
	})
	readyGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "ready",
		Help:      "1 once there is an indicator set worth serving; exports answer 503 until then.",
	})
)

func init() {
	prometheus.MustRegister(syncLastSuccess, syncFailures, indicatorsFetched,
		indicatorsRejected, indicatorsDropped, sourceEnabled, storeSize, storeCapacity,
		storePersistent, storePersistErrors, indicatorsPruned, cycleLastComplete, readyGauge)
}

// initSourceMetrics creates every per-source series up front. They used to
// appear only after a source's first success, so a source that had never
// worked had no source_last_success series and the staleness alert could not
// fire for it. A never-successful source now reports 0.
func initSourceMetrics(cfg config, lastSuccess map[string]time.Time) {
	for _, src := range cfg.sources {
		sourceEnabled.WithLabelValues(src.name).Set(1)
		ts := 0.0
		if t, ok := lastSuccess[src.name]; ok && !t.IsZero() {
			ts = float64(t.Unix())
		}
		syncLastSuccess.WithLabelValues(src.name).Set(ts)
		syncFailures.WithLabelValues(src.name)
		indicatorsFetched.WithLabelValues(src.name)
		indicatorsRejected.WithLabelValues(src.name)
		indicatorsDropped.WithLabelValues(src.name)
	}
	for _, d := range cfg.disabled {
		sourceEnabled.WithLabelValues(d.name).Set(0)
	}
}

// readiness tracks whether there is a set worth serving: a non-empty store
// that was either loaded from the database or filled by at least one
// successful fetch. Before it existed, a pod restarted during a feed outage
// answered every export with 200 and an empty list, and every consumer
// replaced its good list with nothing.
type readiness struct {
	mu      sync.RWMutex
	trusted bool
	store   *ioc.Store
	reason  string
}

func newReadiness(store *ioc.Store) *readiness {
	return &readiness{store: store, reason: "no successful sync yet"}
}

// trust marks the current store contents as worth serving.
func (r *readiness) trust() {
	r.mu.Lock()
	r.trusted = true
	r.mu.Unlock()
	r.Ready()
}

// Ready reports whether exports may be served, and why not.
func (r *readiness) Ready() (bool, string) {
	r.mu.RLock()
	trusted, reason := r.trusted, r.reason
	r.mu.RUnlock()
	switch {
	case !trusted:
		readyGauge.Set(0)
		return false, reason
	case r.store.Len() == 0:
		readyGauge.Set(0)
		return false, "indicator store is empty"
	}
	readyGauge.Set(1)
	return true, ""
}

// sourceResult is what one fetch of one source amounted to.
type sourceResult struct {
	fetched  int
	stats    ioc.UpsertStats
	err      error
	success  bool
	finished time.Time
}

// syncSource fetches one source and applies the partial-result policy:
//
//   - Whatever validated is kept, even when the fetch also failed (body cap,
//     decode error half-way, MISP page cap or deadline). Those rows are
//     current assertions and are stamped as such.
//   - The fetch counts as successful only if it returned without error and,
//     when it delivered any rows at all, at least one was accepted. A 200
//     whose every row is rejected (a changed format, a poisoned feed) is a
//     failure of that source. A well-formed empty list is a success with
//     zero indicators.
//   - Only a success records the source's last-success time, which is what
//     allows its unasserted indicators to expire: a failed or partial fetch
//     never ages anything out. The time recorded is when the fetch started,
//     before any of its rows were stamped, so the rows of the latest
//     successful answer never count as "withdrawn since" however long the
//     feed is unreachable afterwards.
func syncSource(ctx context.Context, store *ioc.Store, src source, timeout time.Duration) sourceResult {
	started := time.Now().UTC()
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	inds, err := src.fetch(fetchCtx)
	cancel()

	res := sourceResult{fetched: len(inds), err: err}
	if len(inds) > 0 {
		res.stats = store.UpsertFeed(src.name, inds)
	}
	res.finished = time.Now().UTC()
	indicatorsRejected.WithLabelValues(src.name).Add(float64(res.stats.Rejected))
	indicatorsDropped.WithLabelValues(src.name).Add(float64(res.stats.Dropped))
	if res.stats.Err != nil {
		storePersistErrors.Inc()
		slog.Error("indicator database write failed; serving from memory", "source", src.name, "error", res.stats.Err)
	}

	switch {
	case err != nil:
		syncFailures.WithLabelValues(src.name).Inc()
		slog.Error("source failed", "source", src.name, "error", err,
			"kept_from_partial_response", res.stats.Accepted, "rejected", res.stats.Rejected)
	case res.fetched > 0 && res.stats.Accepted == 0:
		syncFailures.WithLabelValues(src.name).Inc()
		slog.Error("source returned rows but none were accepted", "source", src.name,
			"fetched", res.fetched, "rejected", res.stats.Rejected, "dropped", res.stats.Dropped)
	default:
		res.success = true
		syncLastSuccess.WithLabelValues(src.name).Set(float64(res.finished.Unix()))
		indicatorsFetched.WithLabelValues(src.name).Set(float64(res.stats.Accepted))
		if err := store.MarkFeedSuccess(src.name, started); err != nil {
			storePersistErrors.Inc()
			slog.Error("indicator database write failed", "source", src.name, "error", err)
		}
		if res.fetched == 0 {
			slog.Warn("source returned an empty list", "source", src.name)
		}
	}
	if res.stats.Rejected > 0 {
		slog.Warn("source returned unusable indicators",
			"source", src.name, "rejected", res.stats.Rejected, "accepted", res.stats.Accepted)
	}
	slog.Info("source synced", "source", src.name, "success", res.success, "fetched", res.fetched,
		"accepted", res.stats.Accepted, "rejected", res.stats.Rejected, "dropped", res.stats.Dropped,
		"store_total", store.Len())
	return res
}

func pruneAndReport(store *ioc.Store, indicatorTTL time.Duration, anySucceeded bool) {
	if n := store.PruneExpired(time.Now().UTC().Add(-indicatorTTL)); n > 0 {
		indicatorsPruned.Add(float64(n))
		slog.Info("pruned stale indicators", "removed", n, "ttl", indicatorTTL)
	}
	storeSize.Set(float64(store.Len()))
	cycleLastComplete.SetToCurrentTime()
	slog.Info("sync cycle complete", "store_total", store.Len(), "any_source_succeeded", anySucceeded)
}

// scheduler runs each source on its own clock: SYNC_INTERVAL after a
// success, exponential backoff after a failure (backoffMin doubling up to
// backoffMax), never sooner than the source's own minimum interval. A failed
// first cycle used to wait a full SYNC_INTERVAL (6 h) before trying again,
// and one failing source cannot force the healthy ones to be re-fetched.
type scheduler struct {
	store      *ioc.Store
	sources    []source
	interval   time.Duration
	ttl        time.Duration
	timeout    time.Duration
	backoffMin time.Duration
	backoffMax time.Duration
	ready      *readiness

	next     map[string]time.Time
	failures map[string]int
}

func newScheduler(cfg config, store *ioc.Store, ready *readiness) *scheduler {
	s := &scheduler{
		store:      store,
		sources:    cfg.sources,
		interval:   cfg.syncInterval,
		ttl:        cfg.indicatorTTL,
		timeout:    cfg.sourceTimeout,
		backoffMin: time.Minute,
		backoffMax: min(cfg.syncInterval, time.Hour),
		ready:      ready,
		next:       make(map[string]time.Time),
		failures:   make(map[string]int),
	}
	// After a restart with a persisted set, a source that succeeded recently
	// is not fetched again straight away: the set is already being served,
	// and the feeds' fair-use rules (Spamhaus: an hour apart) still apply.
	now := time.Now()
	last := store.FeedSuccess()
	for _, src := range s.sources {
		s.next[src.name] = now
		if t, ok := last[src.name]; ok {
			if due := t.Add(max(s.interval, src.minInterval)); due.After(now) {
				s.next[src.name] = due
			}
		}
	}
	return s
}

// runDue fetches every source whose time has come and reschedules it.
func (s *scheduler) runDue(ctx context.Context, now time.Time) {
	var due []source
	for _, src := range s.sources {
		if !s.next[src.name].After(now) {
			due = append(due, src)
		}
	}
	if len(due) == 0 {
		return
	}
	slog.Info("sync cycle starting", "due_sources", len(due))
	anySucceeded := false
	for _, src := range due {
		if ctx.Err() != nil {
			return
		}
		res := syncSource(ctx, s.store, src, s.timeout)
		s.reschedule(src, res.success, res.finished)
		if res.success {
			anySucceeded = true
			s.ready.trust()
		}
	}
	pruneAndReport(s.store, s.ttl, anySucceeded)
	if ok, reason := s.ready.Ready(); !ok {
		slog.Warn("not ready: exports answer 503", "reason", reason, "next_attempt_in", s.untilNext(time.Now()))
	}
}

func (s *scheduler) reschedule(src source, success bool, at time.Time) {
	delay := s.interval
	if success {
		s.failures[src.name] = 0
	} else {
		s.failures[src.name]++
		delay = s.backoffMin << min(s.failures[src.name]-1, 16)
		if delay > s.backoffMax || delay <= 0 {
			delay = s.backoffMax
		}
	}
	delay = max(delay, src.minInterval)
	s.next[src.name] = at.Add(delay)
	if !success {
		slog.Info("source retry scheduled", "source", src.name, "in", delay,
			"consecutive_failures", s.failures[src.name])
	}
}

func (s *scheduler) untilNext(now time.Time) time.Duration {
	first := time.Time{}
	for _, t := range s.next {
		if first.IsZero() || t.Before(first) {
			first = t
		}
	}
	if first.IsZero() {
		return s.interval
	}
	return max(first.Sub(now), time.Second)
}

func (s *scheduler) run(ctx context.Context) {
	slog.Info("sync loop started", "interval", s.interval, "sources", len(s.sources),
		"indicator_ttl", s.ttl, "retry_backoff", s.backoffMin.String()+"…"+s.backoffMax.String())
	for {
		s.runDue(ctx, time.Now())
		timer := time.NewTimer(s.untilNext(time.Now()))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
