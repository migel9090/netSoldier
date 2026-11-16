package enforce

import "github.com/prometheus/client_golang/prometheus"

var (
	pendingActions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "actions_pending",
		Help:      "Number of actions awaiting approval.",
	})
	activeActions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "actions_active",
		Help:      "Number of actions still enforced (active and revert_failed).",
	})
	revertFailedActions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "actions_revert_failed",
		Help:      "Actions whose enforcement could not be lifted and is still in force; the reaper keeps retrying.",
	})
	awaitingActions = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "killswitch",
		Name:      "actions_awaiting_confirmation",
		Help:      "Approved actions whose driver has not confirmed the apply yet.",
	})
	driverFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "driver_failures_total",
		Help:      "Enforcement driver failures by operation (apply, revert, compensate).",
	}, []string{"operation"})
	compensations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "compensations_total",
		Help:      "Reverts run to undo an apply whose outcome was unknown, by outcome.",
	}, []string{"outcome"})
	revertRetries = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "revert_retries_total",
		Help:      "Reaper retries of reverts that had failed, by outcome.",
	}, []string{"outcome"})
	interruptedOps = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "interrupted_operations_total",
		Help:      "Driver operations found unfinished at start-up, by operation.",
	}, []string{"operation"})
	confirmTimeouts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "agent_confirm_timeouts_total",
		Help:      "netagent commands not confirmed within the deadline, by command.",
	}, []string{"command"})
	agentResults = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "agent_results_total",
		Help:      "Command results reported by the netagent, by command and outcome.",
	}, []string{"command", "outcome"})
	agentUnknownResults = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "agent_unknown_results_total",
		Help:      "netagent results for unknown or already settled command ids (ignored).",
	})
	agentInvalidEntries = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "agent_invalid_entries_total",
		Help:      "Entries of netagent polls dropped as malformed.",
	})
	reconcileRuns = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "reconcile_runs_total",
		Help:      "Reconciliation passes against what is really in force, by driver and outcome.",
	}, []string{"driver", "outcome"})
	reconcileFindings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "reconcile_findings_total",
		Help:      "Differences reconciliation found and repaired, by driver and finding.",
	}, []string{"driver", "finding"})
	pendingExpired = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "pending_expired_total",
		Help:      "Pending actions expired without a decision, by reason (ttl, capacity).",
	}, []string{"reason"})
	detectionsFolded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "killswitch",
		Name:      "detections_folded_total",
		Help:      "Detections that created no new action, by outcome (folded, promoted, duplicate).",
	}, []string{"outcome"})
)

// Finding labels.
const (
	findingMissing          = "missing"
	findingRemoved          = "orphan_removed"
	findingStaleRef         = "stale_reference"
	findingAdopted          = "adopted"
	findingUnowned          = "unowned_released"
	findingLateConfirmation = "late_confirmation"
	findingRevertTookEffect = "revert_took_effect"
	findingReissued         = "reissued"
)

func init() {
	prometheus.MustRegister(pendingActions, activeActions, revertFailedActions, awaitingActions,
		driverFailures, compensations, revertRetries, interruptedOps, confirmTimeouts, agentResults,
		agentUnknownResults, agentInvalidEntries, reconcileRuns, reconcileFindings, pendingExpired,
		detectionsFolded)
	for _, op := range []string{"apply", "revert", "compensate"} {
		driverFailures.WithLabelValues(op)
	}
	for _, o := range []string{"ok", "failed"} {
		compensations.WithLabelValues(o)
		revertRetries.WithLabelValues(o)
	}
	for _, r := range []string{"ttl", "capacity"} {
		pendingExpired.WithLabelValues(r)
	}
}
