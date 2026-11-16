package main

import (
	"crypto/sha256"
	"encoding/json"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
)

// maxLedgerEntries bounds the durable ledger under a flood of distinct,
// validly signed events; the reaper drops the oldest beyond it.
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

// evaluationLedger makes /evaluate idempotent on the detection event id,
// across restarts.
//
// The signature's timestamp limits a captured request to a short window;
// inside that window this is what stops a replay — or the sender's own
// retry after a timeout — from creating a second action. A repeat gets the
// decision the first delivery got, and nothing is created. Outcomes are
// kept in the store; deliveries still being evaluated are tracked here, so
// a concurrent repeat waits for the first instead of racing it.
type evaluationLedger struct {
	store     *actions.Store
	retention time.Duration
	now       func() time.Time

	mu       sync.Mutex
	inflight map[string]*evaluation
}

// evaluation is one event id's outcome. done is closed once decision and
// actionID are final (or the evaluation was abandoned, ok=false).
type evaluation struct {
	digest [sha256.Size]byte
	done   chan struct{}

	ok       bool
	decision policy.Decision
	actionID string
}

func newEvaluationLedger(store *actions.Store, retention time.Duration) *evaluationLedger {
	return &evaluationLedger{
		store:     store,
		retention: retention,
		now:       time.Now,
		inflight:  make(map[string]*evaluation),
	}
}

// claim registers id as being evaluated. It returns the entry and true when
// the caller is first and must call finish or abandon; otherwise the entry
// of the earlier delivery and false. An outcome older than the retention is
// forgotten: the signature window has closed by then, and the store still
// refuses to create a second action for the same detection id.
func (l *evaluationLedger) claim(id string, digest [sha256.Size]byte) (*evaluation, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.inflight[id]; ok {
		return e, false, nil
	}
	past, found, err := l.store.GetEvaluation(id)
	if err != nil {
		return nil, false, err
	}
	if found && l.now().Sub(past.EvaluatedAt) <= l.retention {
		e := &evaluation{done: make(chan struct{}), ok: true, actionID: past.ActionID}
		copy(e.digest[:], past.Digest)
		if err := json.Unmarshal(past.Decision, &e.decision); err != nil {
			return nil, false, err
		}
		close(e.done)
		return e, false, nil
	}
	e := &evaluation{digest: digest, done: make(chan struct{})}
	l.inflight[id] = e
	return e, true, nil
}

// finish records the outcome durably and releases anyone waiting on it.
func (l *evaluationLedger) finish(id string, e *evaluation, digest [sha256.Size]byte, d policy.Decision,
	actionID string) error {
	raw, err := json.Marshal(d)
	if err == nil {
		err = l.store.PutEvaluation(actions.Evaluation{DetectionID: id, Digest: digest[:], Decision: raw,
			ActionID: actionID, EvaluatedAt: l.now()})
	}
	l.mu.Lock()
	e.ok, e.decision, e.actionID = true, d, actionID
	if l.inflight[id] == e {
		delete(l.inflight, id)
	}
	l.mu.Unlock()
	close(e.done)
	return err
}

// abandon forgets an evaluation that did not complete, so a later delivery
// is evaluated afresh instead of being answered with nothing.
func (l *evaluationLedger) abandon(id string, e *evaluation) {
	l.mu.Lock()
	if l.inflight[id] == e {
		delete(l.inflight, id)
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
