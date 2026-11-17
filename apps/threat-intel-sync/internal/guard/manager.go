package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// Errors of the operator calls.
var (
	ErrNotHeld = errors.New("nothing is held for this source")
	ErrStale   = errors.New("the held fetch has changed since it was inspected")
)

// Manager applies the guard to every fetch and owns the held fetches. All
// of its operations are serialised: a fetch being judged, an operator
// releasing a held one and an operator discarding one never interleave.
type Manager struct {
	mu      sync.Mutex
	store   *ioc.Store
	limits  Limits
	feeds   []string
	holdCap int
	now     func() time.Time
}

// New returns a guard over store for the enabled feeds. holdCap bounds the
// rows kept from one held fetch (the store's own cap: more could never be
// applied). History and held fetches are the store's (persisted with it).
func New(store *ioc.Store, limits Limits, feeds []string, holdCap int) *Manager {
	return &Manager{
		store:   store,
		limits:  limits,
		feeds:   append([]string(nil), feeds...),
		holdCap: holdCap,
		now:     time.Now,
	}
}

// Limits returns the thresholds in force.
func (m *Manager) Limits() Limits { return m.limits }

// Outcome is what one fetch amounted to.
type Outcome struct {
	Prepare  ioc.PrepareStats // what validation made of the delivery
	Distinct int              // distinct valid indicators
	Verdict  Verdict
	// Applied: the rows were applied to the store (Stats says how). For a
	// complete fetch the feed's success was recorded too.
	Applied bool
	Stats   ioc.UpsertStats
	// Held: the fetch was held in quarantine instead (Rows are not set).
	Held *ioc.HeldSet
	// Superseded is the held fetch this complete, applied fetch replaced
	// (Rows not set), if there was one.
	Superseded *ioc.HeldSet
	// PersistErr: recording the outcome in the database failed; the
	// in-memory state is still correct.
	PersistErr error
}

// Ingest judges one fetch of feed and applies or holds it. complete is
// false when the fetch failed half-way: what validated is still applied
// (the partial-result policy), but never recorded as the feed's answer,
// never judged on collapse and never added to its history.
//
// A complete fetch that delivered rows of which none were valid applies
// nothing and is not judged: it is a failure of the source (the caller's
// rule), not a set to hold.
func (m *Manager) Ingest(feed string, inds []ioc.Indicator, complete bool, started time.Time) Outcome {
	m.mu.Lock()
	defer m.mu.Unlock()

	b := m.store.Prepare(feed, inds)
	out := Outcome{Prepare: b.Stats, Distinct: b.Len()}
	if b.Len() == 0 && (!complete || b.Stats.Rows > 0) {
		return out
	}

	in := Input{
		Size:         b.Len(),
		History:      m.store.VolumeHistory(feed),
		NewKeys:      m.store.CountNew(b),
		StoreTotal:   m.store.Len(),
		TotalHistory: m.store.VolumeHistory(ioc.TotalHistoryKey),
		Partial:      !complete,
	}
	out.Verdict = m.limits.Check(in)
	if out.Verdict.Hold {
		h := m.heldSet(b, in, out.Verdict, started)
		out.PersistErr = m.store.Hold(h)
		h.Rows = nil
		out.Held = &h
		return out
	}

	out.Stats = m.store.Apply(b)
	out.Applied = true
	if !complete || (b.Stats.Rows > 0 && out.Stats.Accepted == 0) {
		// Partial, or every row refused by the store cap: what was applied
		// stays, but it is not the feed's answer (the caller counts the
		// latter as a failure, as before the guard existed).
		return out
	}
	var errs []error
	errs = append(errs, m.store.MarkFeedSuccess(feed, started))
	errs = append(errs, m.store.SetVolumeHistory(feed, Append(in.History, b.Len())))
	errs = append(errs, m.recordTotal())
	if prev, ok := m.store.Held(feed); ok {
		errs = append(errs, m.store.DropHeld(feed))
		prev.Rows = nil
		out.Superseded = &prev
	}
	out.PersistErr = errors.Join(errs...)
	return out
}

// recordTotal adds the store's size to the store-wide history once every
// enabled feed has a history of its own: before that the store is still
// filling, and "usual" would mean "whatever arrived first".
func (m *Manager) recordTotal() error {
	for _, f := range m.feeds {
		if len(m.store.VolumeHistory(f)) == 0 {
			return nil
		}
	}
	return m.store.SetVolumeHistory(ioc.TotalHistoryKey,
		Append(m.store.VolumeHistory(ioc.TotalHistoryKey), m.store.Len()))
}

func (m *Manager) heldSet(b *ioc.Batch, in Input, v Verdict, started time.Time) ioc.HeldSet {
	rows := b.Indicators()
	truncated := 0
	if m.holdCap > 0 && len(rows) > m.holdCap {
		truncated = len(rows) - m.holdCap
		rows = rows[:m.holdCap]
	}
	return ioc.HeldSet{
		Feed:      b.Feed(),
		ID:        heldID(b.Feed(), b.Keys(), !in.Partial),
		Reason:    v.Reason,
		Detail:    v.Detail,
		Partial:   in.Partial,
		Started:   started.UTC(),
		HeldAt:    m.now().UTC(),
		Size:      in.Size,
		Baseline:  v.Baseline,
		NewKeys:   in.NewKeys,
		Total:     in.StoreTotal,
		Truncated: truncated,
		Rows:      rows,
	}
}

// heldID names a held fetch by its content, so an operator releases exactly
// the set that was inspected: a later fetch with different content gets a
// different id, the same content the same one.
func heldID(feed string, keys []string, complete bool) string {
	sort.Strings(keys)
	h := sha256.New()
	h.Write([]byte(feed))
	if complete {
		h.Write([]byte{0, 'c'})
	} else {
		h.Write([]byte{0, 'p'})
	}
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k))
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// Released is what a release applied.
type Released struct {
	Held     ioc.HeldSet     // the fetch released (Rows not set)
	Stats    ioc.UpsertStats // what applying it did
	Baseline int             // the feed's usual size from now on
}

// Release applies feed's held fetch as if it had passed, and makes its size
// the feed's usual size: the operator has confirmed the change is real, so
// the next fetch of similar size must not be held again. id must be the
// held fetch's ID (ErrStale otherwise). A partial held fetch is applied
// without being recorded as the feed's answer, like any partial result.
//
// The store-wide history restarts from the store's new size for the same
// reason; otherwise every other feed's next fetch would be judged against
// a store that no longer exists.
func (m *Manager) Release(feed, id string) (Released, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.store.Held(feed)
	if !ok {
		return Released{}, ErrNotHeld
	}
	if id != h.ID {
		return Released{}, ErrStale
	}
	// Validated again: the held rows are applied under today's rules, not
	// the ones in force when they were held.
	b := m.store.Prepare(feed, h.Rows)
	rel := Released{Stats: m.store.Apply(b)}
	var errs []error
	if !h.Partial {
		errs = append(errs, m.store.MarkFeedSuccess(feed, h.Started))
		errs = append(errs, m.store.SetVolumeHistory(feed, []int{b.Len()}))
		rel.Baseline = b.Len()
	} else {
		rel.Baseline = Median(m.store.VolumeHistory(feed))
	}
	errs = append(errs, m.store.SetVolumeHistory(ioc.TotalHistoryKey, nil))
	errs = append(errs, m.recordTotal())
	errs = append(errs, m.store.DropHeld(feed))
	h.Rows = nil
	rel.Held = h
	return rel, errors.Join(errs...)
}

// Discard forgets feed's held fetch. The previous set stays as it is, and
// the feed's next fetch is judged afresh.
func (m *Manager) Discard(feed string) (ioc.HeldSet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.store.Held(feed)
	if !ok {
		return ioc.HeldSet{}, ErrNotHeld
	}
	err := m.store.DropHeld(feed)
	h.Rows = nil
	return h, err
}

// Held returns every held fetch (without rows), sorted by feed.
func (m *Manager) Held() []ioc.HeldSet {
	all := m.store.HeldSets()
	out := make([]ioc.HeldSet, 0, len(all))
	for _, h := range all {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Feed < out[j].Feed })
	return out
}

// Get returns feed's held fetch with its rows (shared: do not modify).
func (m *Manager) Get(feed string) (ioc.HeldSet, bool) {
	return m.store.Held(feed)
}

// Baseline returns feed's usual size and whether it has a history at all.
func (m *Manager) Baseline(feed string) (int, bool) {
	h := m.store.VolumeHistory(feed)
	return Median(h), len(h) > 0
}
