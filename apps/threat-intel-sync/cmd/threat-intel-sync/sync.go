package main

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/guard"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/libs/indicator"
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

	// Step 134: the never-block list, the volume guard and freshness.
	indicatorsNeverBlock = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_indicators_never_block_total",
		Help:      "Feed rows dropped because they name a host on the never-block list, per source and reason.",
	}, []string{"source", "reason"})
	quarantined = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_quarantined",
		Help:      "1 while a fetch of the source is held by the volume guard; the previous set is still served.",
	}, []string{"source"})
	quarantinedIndicators = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_quarantined_indicators",
		Help:      "Distinct indicators in the source's held fetch (0 when nothing is held).",
	}, []string{"source"})
	quarantineTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_quarantine_total",
		Help:      "Fetches held by the volume guard, per source and reason (growth, collapse, first_sync, total_growth).",
	}, []string{"source", "reason"})
	quarantineResolved = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "threat_intel",
		Name:      "source_quarantine_resolved_total",
		Help:      "Held fetches resolved, per source and action (released, discarded, superseded).",
	}, []string{"source", "action"})
	volumeBaseline = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_volume_baseline",
		Help:      "The source's usual size the volume guard judges fetches against (median of its last applied fetches; 0 before the first).",
	}, []string{"source"})
	freshnessObjective = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "threat_intel",
		Name:      "source_freshness_objective_seconds",
		Help:      "Freshness objective per source (SOURCE_MAX_AGE): the source is stale once its last success is older.",
	}, []string{"source"})
)

// Resolution actions, label values of quarantineResolved.
const (
	actionReleased   = "released"
	actionDiscarded  = "discarded"
	actionSuperseded = "superseded"
)

func init() {
	prometheus.MustRegister(syncLastSuccess, syncFailures, indicatorsFetched,
		indicatorsRejected, indicatorsDropped, sourceEnabled, storeSize, storeCapacity,
		storePersistent, storePersistErrors, indicatorsPruned, cycleLastComplete, readyGauge,
		indicatorsNeverBlock, quarantined, quarantinedIndicators, quarantineTotal,
		quarantineResolved, volumeBaseline, freshnessObjective, fresh)
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
		for _, r := range indicator.NeverBlockReasons() {
			indicatorsNeverBlock.WithLabelValues(src.name, r)
		}
		for _, r := range guard.Reasons() {
			quarantineTotal.WithLabelValues(src.name, r)
		}
		for _, a := range []string{actionReleased, actionDiscarded, actionSuperseded} {
			quarantineResolved.WithLabelValues(src.name, a)
		}
		quarantined.WithLabelValues(src.name)
		quarantinedIndicators.WithLabelValues(src.name)
		volumeBaseline.WithLabelValues(src.name)
		feedhttp.InitSourceMetrics(src.name)
		if src.maxAge > 0 {
			freshnessObjective.WithLabelValues(src.name).Set(src.maxAge.Seconds())
		}
	}
	for _, d := range cfg.disabled {
		sourceEnabled.WithLabelValues(d.name).Set(0)
	}
}

// initGuardMetrics reports the guard state restored with the store: a fetch
// held before a restart keeps its alert up after it.
func initGuardMetrics(cfg config, g *guard.Manager) {
	for _, src := range cfg.sources {
		if base, ok := g.Baseline(src.name); ok {
			volumeBaseline.WithLabelValues(src.name).Set(float64(base))
		}
		if h, ok := g.Get(src.name); ok {
			quarantined.WithLabelValues(src.name).Set(1)
			quarantinedIndicators.WithLabelValues(src.name).Set(float64(h.Size))
		} else {
			quarantined.WithLabelValues(src.name).Set(0)
			quarantinedIndicators.WithLabelValues(src.name).Set(0)
		}
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
	fetched     int
	stats       ioc.UpsertStats
	outcome     guard.Outcome
	err         error
	success     bool
	quarantined bool
	finished    time.Time
}

// syncSource fetches one source, passes it through the volume guard and
// applies the partial-result policy:
//
//   - Whatever validated is kept, even when the fetch also failed (body cap,
//     decode error half-way, MISP page cap or deadline). Those rows are
//     current assertions and are stamped as such — unless the guard holds
//     them: a partial fetch ten times the usual size is held like a
//     complete one.
//   - The fetch counts as successful only if it returned without error and,
//     when it delivered any rows at all, at least one was accepted. A 200
//     whose every row is rejected (a changed format, a poisoned feed) is a
//     failure of that source. A well-formed empty list is a success with
//     zero indicators — unless the source usually lists hundreds, which the
//     guard holds as a collapse.
//   - A held fetch is neither: the previous set keeps being served, the
//     source's last success does not move (so its freshness objective will
//     eventually report it stale too), and the alert metric
//     threat_intel_source_quarantined is 1 until the fetch is released,
//     discarded or superseded by a fetch that passes.
//   - Only a success records the source's last-success time, which is what
//     allows its unasserted indicators to expire: a failed, partial or held
//     fetch never ages anything out. The time recorded is when the fetch
//     started, before any of its rows were stamped, so the rows of the latest
//     successful answer never count as "withdrawn since" however long the
//     feed is unreachable afterwards.
func syncSource(ctx context.Context, g *guard.Manager, store *ioc.Store, src source, timeout time.Duration) sourceResult {
	started := time.Now().UTC()
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	inds, err := src.fetch(fetchCtx)
	cancel()

	res := sourceResult{fetched: len(inds), err: err}
	out := g.Ingest(src.name, inds, err == nil, started)
	res.outcome, res.stats = out, out.Stats
	res.finished = time.Now().UTC()
	indicatorsRejected.WithLabelValues(src.name).Add(float64(out.Prepare.Rejected))
	indicatorsDropped.WithLabelValues(src.name).Add(float64(out.Stats.Dropped))
	for reason, n := range out.Prepare.NeverBlock {
		indicatorsNeverBlock.WithLabelValues(src.name, reason).Add(float64(n))
	}
	if out.Stats.Err != nil {
		storePersistErrors.Inc()
		slog.Error("indicator database write failed; serving from memory", "source", src.name, "error", out.Stats.Err)
	}
	if out.PersistErr != nil {
		storePersistErrors.Inc()
		slog.Error("indicator database write failed", "source", src.name, "error", out.PersistErr)
	}
	if n := out.Prepare.NeverBlocked(); n > 0 {
		slog.Warn("source listed hosts that must never be blocked; dropped", "source", src.name,
			"never_block", n, "by_reason", out.Prepare.NeverBlock)
	}

	switch {
	case out.Held != nil:
		res.quarantined = true
		h := out.Held
		quarantineTotal.WithLabelValues(src.name, h.Reason).Inc()
		quarantined.WithLabelValues(src.name).Set(1)
		quarantinedIndicators.WithLabelValues(src.name).Set(float64(h.Size))
		if err != nil {
			syncFailures.WithLabelValues(src.name).Inc()
		}
		slog.Error("QUARANTINE: fetch held by the volume guard; the previous indicator set is still served",
			"source", src.name, "reason", h.Reason, "detail", h.Detail, "size", h.Size,
			"baseline", h.Baseline, "new", h.NewKeys, "partial", h.Partial, "id", h.ID,
			"fetch_error", errString(err),
			"hint", "inspect GET /quarantine/"+src.name+", then POST /quarantine/"+src.name+
				"/release with {\"id\":\""+h.ID+"\"} or POST /quarantine/"+src.name+"/discard")
	case err != nil:
		syncFailures.WithLabelValues(src.name).Inc()
		slog.Error("source failed", "source", src.name, "error", err,
			"kept_from_partial_response", res.stats.Accepted, "rejected", out.Prepare.Rejected)
	case res.fetched > 0 && res.stats.Accepted == 0:
		syncFailures.WithLabelValues(src.name).Inc()
		slog.Error("source returned rows but none were accepted", "source", src.name,
			"fetched", res.fetched, "rejected", out.Prepare.Rejected,
			"never_block", out.Prepare.NeverBlocked(), "dropped", res.stats.Dropped)
	default:
		res.success = true
		syncLastSuccess.WithLabelValues(src.name).Set(float64(res.finished.Unix()))
		indicatorsFetched.WithLabelValues(src.name).Set(float64(res.stats.Accepted))
		if res.fetched == 0 {
			slog.Warn("source returned an empty list", "source", src.name)
		}
		if s := out.Superseded; s != nil {
			quarantineResolved.WithLabelValues(src.name, actionSuperseded).Inc()
			quarantined.WithLabelValues(src.name).Set(0)
			quarantinedIndicators.WithLabelValues(src.name).Set(0)
			slog.Warn("quarantine superseded: the source answered normally again; the held fetch is discarded",
				"source", src.name, "id", s.ID, "reason", s.Reason, "held_at", s.HeldAt)
		}
	}
	if base, ok := g.Baseline(src.name); ok {
		volumeBaseline.WithLabelValues(src.name).Set(float64(base))
	}
	if out.Prepare.Rejected > 0 {
		slog.Warn("source returned unusable indicators",
			"source", src.name, "rejected", out.Prepare.Rejected, "accepted", res.stats.Accepted)
	}
	slog.Info("source synced", "source", src.name, "success", res.success, "quarantined", res.quarantined,
		"fetched", res.fetched, "distinct", out.Distinct, "accepted", res.stats.Accepted,
		"rejected", out.Prepare.Rejected, "never_block", out.Prepare.NeverBlocked(),
		"dropped", res.stats.Dropped, "store_total", store.Len())
	return res
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
// and one failing source cannot force the healthy ones to be re-fetched. A
// held fetch is not a failure of the download: the source is fetched again
// after SYNC_INTERVAL, by when an operator may have decided, or the feed
// recovered.
type scheduler struct {
	store      *ioc.Store
	guard      *guard.Manager
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

func newScheduler(cfg config, store *ioc.Store, g *guard.Manager, ready *readiness) *scheduler {
	s := &scheduler{
		store:      store,
		guard:      g,
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
	// A held fetch was a download too.
	now := time.Now()
	last := store.FeedSuccess()
	for feed, h := range store.HeldSets() {
		if h.Started.After(last[feed]) {
			last[feed] = h.Started
		}
	}
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
		res := syncSource(ctx, s.guard, s.store, src, s.timeout)
		s.reschedule(src, res.success || (res.quarantined && res.err == nil), res.finished)
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
