package main

import (
	"crypto/sha256"
	"log/slog"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// maxLedgerEntries bounds the ledger under a flood of distinct, validly
// signed events. Only completed entries past their retention are dropped
// first; beyond this the oldest completed ones go regardless.
const maxLedgerEntries = 20000

// ledgerRetention is how long an evaluated event id is remembered. A
// signature stays acceptable while |now - t| <= tolerance, and t may lie up
// to tolerance in the future, so a captured request can be replayed for up
// to twice the tolerance after it was first seen. The margin covers the time
// the first evaluation itself took.
func ledgerRetention(tolerance time.Duration) time.Duration {
	if tolerance <= 0 {
		tolerance = events.DefaultSignatureTolerance
	}
	return 2*tolerance + time.Minute
}

// evaluationLedger makes /evaluate idempotent on the detection event id.
//
// The signature's timestamp limits a captured request to a short window;
// inside that window this is what stops a replay — or the sender's own
// retry after a timeout — from creating a second action. A repeat gets the
// decision the first delivery got, and nothing is created.
type evaluationLedger struct {
	retention time.Duration
	now       func() time.Time

	mu      sync.Mutex
	entries map[string]*evaluation
	order   []string // insertion order, for pruning
}

// evaluation is one event id's outcome. done is closed once decision and
// actionID are final (or the evaluation was abandoned, ok=false).
type evaluation struct {
	digest [sha256.Size]byte
	at     time.Time
	done   chan struct{}

	ok       bool
	decision policy.Decision
	actionID string
}

func newEvaluationLedger(retention time.Duration) *evaluationLedger {
	return &evaluationLedger{
		retention: retention,
		now:       time.Now,
		entries:   make(map[string]*evaluation),
	}
}

// claim registers id as being evaluated. It returns the entry and true when
// the caller is first and must call finish or abandon; otherwise it returns
// the existing entry and false.
func (l *evaluationLedger) claim(id string, digest [sha256.Size]byte) (*evaluation, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked()
	if e, ok := l.entries[id]; ok {
		return e, false
	}
	e := &evaluation{digest: digest, at: l.now(), done: make(chan struct{})}
	l.entries[id] = e
	l.order = append(l.order, id)
	return e, true
}

// finish records the outcome and releases anyone waiting on the same id.
func (l *evaluationLedger) finish(e *evaluation, d policy.Decision, actionID string) {
	l.mu.Lock()
	e.ok, e.decision, e.actionID = true, d, actionID
	l.mu.Unlock()
	close(e.done)
}

// abandon forgets an evaluation that did not complete, so a later delivery
// is evaluated afresh instead of being answered with nothing.
func (l *evaluationLedger) abandon(id string, e *evaluation) {
	l.mu.Lock()
	if l.entries[id] == e {
		delete(l.entries, id)
	}
	l.mu.Unlock()
	close(e.done)
}

// outcome reads a completed entry.
func (l *evaluationLedger) outcome(e *evaluation) (policy.Decision, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return e.decision, e.actionID, e.ok
}

func (l *evaluationLedger) pruneLocked() {
	now := l.now()
	cut := 0
	for cut < len(l.order) {
		id := l.order[cut]
		e, ok := l.entries[id]
		if ok && !(isClosed(e.done) && now.Sub(e.at) > l.retention) {
			break
		}
		if ok {
			delete(l.entries, id)
		}
		cut++
	}
	l.order = l.order[cut:]

	if len(l.entries) <= maxLedgerEntries {
		return
	}
	kept := l.order[:0:0]
	for _, id := range l.order {
		e, ok := l.entries[id]
		if !ok {
			continue
		}
		if len(l.entries) > maxLedgerEntries && isClosed(e.done) {
			delete(l.entries, id)
			continue
		}
		kept = append(kept, id)
	}
	l.order = kept
	slog.Warn("evaluation ledger full: forgot event ids still inside the replay window",
		"max", maxLedgerEntries)
}

func isClosed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
