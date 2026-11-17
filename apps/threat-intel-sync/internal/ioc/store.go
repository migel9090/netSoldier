package ioc

import (
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/libs/indicator"
)

// DefaultMaxIndicators caps the store when no explicit limit is configured.
// A household deployment carries tens of thousands of indicators; a cap an
// order of magnitude above that keeps a hostile or broken feed from growing
// the store until the pod is OOM-killed, while never biting in normal use.
const DefaultMaxIndicators = 100_000

// maxRejectLogs bounds per-batch logging of rejected rows: a hostile feed
// can deliver a million bad rows, and one log line each is a second outage.
const maxRejectLogs = 10

// assertion is one feed's current claim about an indicator: the validated
// row as that feed last delivered it, stamped with when it did.
type assertion struct {
	feed string
	ind  Indicator
}

// entry is everything known about one (Type, Value) key. Each feed keeps its
// own assertion, so a feed lowering its confidence, or withdrawing the
// indicator, takes effect instead of being masked by the maximum ever seen.
type entry struct {
	feeds []assertion // sorted by feed name
	agg   Indicator   // aggregate of feeds, served to every export
}

// Store is a thread-safe IoC store with deduplication, a size cap and
// optional SQLite persistence. Indicators sharing the same (Type, Value) key
// are served as one aggregated indicator.
type Store struct {
	mu          sync.RWMutex
	items       map[string]*entry
	feedSuccess map[string]time.Time
	history     map[string][]int   // volume history per feed, see SetVolumeHistory
	held        map[string]HeldSet // fetches held back by the volume guard
	max         int
	now         func() time.Time

	dbMu sync.Mutex // serialises writes to db; never taken while holding mu
	db   *sqliteDB
}

// Option configures a Store.
type Option func(*Store)

// WithMaxIndicators caps the number of distinct indicators. Once full, new
// keys are refused (existing ones are still refreshed): a flood from one feed
// must not evict indicators other feeds vouched for. n <= 0 means no cap.
func WithMaxIndicators(n int) Option { return func(s *Store) { s.max = n } }

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option { return func(s *Store) { s.now = now } }

// NewStore creates an empty in-memory IoC store.
func NewStore(opts ...Option) *Store {
	s := &Store{
		items:       make(map[string]*entry),
		feedSuccess: make(map[string]time.Time),
		history:     make(map[string][]int),
		held:        make(map[string]HeldSet),
		now:         time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// UpsertStats reports what one batch did to the store.
type UpsertStats struct {
	Accepted int // valid rows now asserted by the feed
	Rejected int // rows that failed validation
	Dropped  int // valid rows refused because the store is full
	// NeverBlock counts the rows refused because they name a host on the
	// never-block list, by reason (indicator.Reason*). They are not in
	// Rejected: the row is well formed, it only must not become a block.
	NeverBlock map[string]int
	Err        error // persistence failed; the in-memory set was still updated
}

// PrepareStats reports what validation made of one feed delivery.
type PrepareStats struct {
	Rows       int            // rows delivered
	Rejected   int            // rows that failed validation
	NeverBlock map[string]int // rows naming a never-block host, by reason
}

// NeverBlocked is the number of rows refused by the never-block list.
func (p PrepareStats) NeverBlocked() int {
	n := 0
	for _, v := range p.NeverBlock {
		n += v
	}
	return n
}

// Batch is one feed's delivery after validation, not yet applied to the
// store: what the volume guard judges before anything changes. Duplicate
// keys within the delivery are already merged.
type Batch struct {
	feed  string
	order []string
	inds  map[string]Indicator
	rows  map[string]int
	Stats PrepareStats
}

// Feed returns the feed the batch was delivered by.
func (b *Batch) Feed() string { return b.feed }

// Len is the number of distinct valid indicators in the batch.
func (b *Batch) Len() int { return len(b.order) }

// Indicators returns the batch's validated indicators, in delivery order.
func (b *Batch) Indicators() []Indicator {
	out := make([]Indicator, 0, len(b.order))
	for _, k := range b.order {
		out = append(out, b.inds[k])
	}
	return out
}

// Keys returns the batch's deduplication keys, in delivery order.
func (b *Batch) Keys() []string { return append([]string(nil), b.order...) }

// Upsert validates and inserts or refreshes one indicator, asserted by the
// feed named in its Source. Invalid indicators are dropped.
func (s *Store) Upsert(ind Indicator) {
	s.UpsertFeed(ind.Source, []Indicator{ind})
}

// UpsertAll validates and inserts/merges a batch of indicators, returning
// how many were accepted and how many were rejected (invalid, or refused
// because the store is full). Each indicator is asserted by the feed named
// in its Source.
//
// Feed content is third-party input, so this is a trust boundary: an
// indicator that is too broad to act on (a bare TLD, a catch-all CIDR) is
// dropped here rather than stored, because everything downstream — the
// Suricata datasets, the Zeek intel file, the AdGuard rules, the Vector
// enrichment tables and the detection-engine's matcher — is generated from
// this store.
func (s *Store) UpsertAll(inds []Indicator) (accepted, rejected int) {
	byFeed := make(map[string][]Indicator)
	var order []string
	for _, ind := range inds {
		if _, ok := byFeed[ind.Source]; !ok {
			order = append(order, ind.Source)
		}
		byFeed[ind.Source] = append(byFeed[ind.Source], ind)
	}
	for _, feed := range order {
		st := s.UpsertFeed(feed, byFeed[feed])
		accepted += st.Accepted
		rejected += st.Rejected + st.Dropped
		for _, n := range st.NeverBlock {
			rejected += n
		}
	}
	return accepted, rejected
}

// UpsertFeed validates a batch delivered by one feed and records each valid
// row as that feed's current assertion, stamped with the current time.
// Duplicate keys within the batch are merged first. It is Prepare followed
// by Apply, without a volume guard in between.
func (s *Store) UpsertFeed(feed string, inds []Indicator) UpsertStats {
	return s.Apply(s.Prepare(feed, inds))
}

// Prepare validates a delivery from feed without changing the store: rows
// that fail validation are counted as rejected, rows naming a never-block
// host are counted by reason, and duplicate keys are merged.
func (s *Store) Prepare(feed string, inds []Indicator) *Batch {
	b := &Batch{
		feed:  feed,
		inds:  make(map[string]Indicator, len(inds)),
		rows:  make(map[string]int, len(inds)),
		Stats: PrepareStats{Rows: len(inds)},
	}
	neverBlockLogs := 0
	for _, raw := range inds {
		v, err := Validate(raw)
		var nb *indicator.NeverBlockError
		switch {
		case errors.As(err, &nb):
			if b.Stats.NeverBlock == nil {
				b.Stats.NeverBlock = make(map[string]int)
			}
			b.Stats.NeverBlock[nb.Reason]++
			if neverBlockLogs++; neverBlockLogs <= maxRejectLogs {
				slog.Warn("dropped never-block indicator from feed", "feed", feed,
					"type", nb.Type, "value", truncateForLog(nb.Value),
					"reason", nb.Reason, "entry", nb.Entry)
			}
			continue
		case err != nil:
			b.Stats.Rejected++
			if b.Stats.Rejected <= maxRejectLogs {
				slog.Warn("rejected indicator from feed", "feed", feed,
					"source", indicator.Text(raw.Source, indicator.MaxSourceLen), "type", indicator.Text(raw.Type, 32),
					"value", truncateForLog(raw.Value), "error", err)
			}
			continue
		}
		if v.Source == "" {
			v.Source = feed
		}
		k := v.Key()
		if prev, ok := b.inds[k]; ok {
			prev.Merge(v)
			b.inds[k] = prev
		} else {
			b.inds[k] = v
			b.order = append(b.order, k)
		}
		b.rows[k]++
	}
	if b.Stats.Rejected > maxRejectLogs {
		slog.Warn("further indicators rejected from feed", "feed", feed,
			"not_logged", b.Stats.Rejected-maxRejectLogs)
	}
	if neverBlockLogs > maxRejectLogs {
		slog.Warn("further never-block indicators dropped from feed", "feed", feed,
			"not_logged", neverBlockLogs-maxRejectLogs)
	}
	return b
}

// CountNew returns how many of the batch's indicators the store does not
// hold at all yet: what applying it would add to every export.
func (s *Store) CountNew(b *Batch) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, k := range b.order {
		if _, ok := s.items[k]; !ok {
			n++
		}
	}
	return n
}

// Contains reports whether the store holds an indicator with key k
// (Indicator.Key).
func (s *Store) Contains(k string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.items[k]
	return ok
}

// Apply records each indicator of a prepared batch as its feed's current
// assertion, stamped with the current time.
func (s *Store) Apply(b *Batch) UpsertStats {
	st := UpsertStats{Rejected: b.Stats.Rejected}
	if len(b.Stats.NeverBlock) > 0 {
		st.NeverBlock = make(map[string]int, len(b.Stats.NeverBlock))
		for r, n := range b.Stats.NeverBlock {
			st.NeverBlock[r] = n
		}
	}
	feed := b.feed
	now := s.now().UTC()

	applied := make([]Indicator, 0, len(b.order))
	s.mu.Lock()
	for _, k := range b.order {
		e := s.items[k]
		if e == nil {
			if s.max > 0 && len(s.items) >= s.max {
				st.Dropped += b.rows[k]
				continue
			}
			e = &entry{}
			s.items[k] = e
		}
		ind := b.inds[k]
		ind.LastAsserted = now
		e.set(feed, ind)
		applied = append(applied, ind)
		st.Accepted += b.rows[k]
	}
	s.mu.Unlock()

	if st.Dropped > 0 {
		slog.Error("indicator store is full: new indicators refused",
			"feed", feed, "dropped", st.Dropped, "max", s.max)
	}
	if s.db != nil && len(applied) > 0 {
		s.dbMu.Lock()
		st.Err = s.db.upsertAssertions(feed, applied)
		s.dbMu.Unlock()
	}
	return st
}

// MarkFeedSuccess records that a successful fetch from feed started at t.
// Expiry only counts silence from a feed that has answered since an
// indicator was last asserted: an outage must never age out the indicators
// the unreachable feed vouched for. t must not be later than the upsert of
// that fetch's rows, or those rows would look withdrawn by their own answer.
func (s *Store) MarkFeedSuccess(feed string, t time.Time) error {
	t = t.UTC()
	s.mu.Lock()
	s.feedSuccess[feed] = t
	s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	return s.db.setFeedSuccess(feed, t)
}

// FeedSuccess returns the last recorded success time per feed, including
// those loaded from the database.
func (s *Store) FeedSuccess() map[string]time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]time.Time, len(s.feedSuccess))
	for k, v := range s.feedSuccess {
		out[k] = v
	}
	return out
}

// PruneBefore removes every assertion last made before cutoff, whichever
// feed made it, and returns how many indicators disappeared entirely.
//
// Expiry is measured from the last time a feed asserted the indicator, not
// from the feed's own first_seen/last_seen dates: those made entries flap
// (a C2 still listed but "last online" weeks ago was pruned and re-added
// every cycle) or never expire (a delisted Spamhaus range carries no date
// at all and was kept forever).
func (s *Store) PruneBefore(cutoff time.Time) int {
	return s.prune(func(a assertion) bool { return a.ind.LastAsserted.Before(cutoff) })
}

// PruneExpired removes assertions last made before cutoff by feeds that have
// answered successfully since, and returns how many indicators disappeared
// entirely. A feed that has been unreachable keeps its assertions however
// old they are.
func (s *Store) PruneExpired(cutoff time.Time) int {
	s.mu.RLock()
	success := make(map[string]time.Time, len(s.feedSuccess))
	for k, v := range s.feedSuccess {
		success[k] = v
	}
	s.mu.RUnlock()
	return s.prune(func(a assertion) bool {
		return a.ind.LastAsserted.Before(cutoff) && success[a.feed].After(a.ind.LastAsserted)
	})
}

// RetainFeeds removes every assertion made by a feed not in keep, and
// returns how many indicators disappeared entirely. It runs at start-up so
// a source that has since been disabled — notably the non-commercial feeds
// under COMMERCIAL_MODE — is not served from the persisted set. The
// disabled feeds' volume history and held fetches go too; the store-wide
// history (TotalHistoryKey) is kept.
func (s *Store) RetainFeeds(keep []string) int {
	allowed := make(map[string]bool, len(keep)+1)
	for _, f := range keep {
		allowed[f] = true
	}
	n := s.prune(func(a assertion) bool { return !allowed[a.feed] })
	allowed[TotalHistoryKey] = true
	s.mu.Lock()
	gone := map[string]bool{}
	for f := range s.feedSuccess {
		if !allowed[f] {
			gone[f] = true
			delete(s.feedSuccess, f)
		}
	}
	for f := range s.history {
		if !allowed[f] {
			gone[f] = true
			delete(s.history, f)
		}
	}
	for f := range s.held {
		if !allowed[f] {
			gone[f] = true
			delete(s.held, f)
		}
	}
	s.mu.Unlock()
	if s.db != nil && len(gone) > 0 {
		s.dbMu.Lock()
		defer s.dbMu.Unlock()
		for f := range gone {
			if err := s.db.deleteFeed(f); err != nil {
				slog.Error("indicator database: removing disabled feed failed", "feed", f, "error", err)
			}
		}
	}
	return n
}

// TotalHistoryKey is the volume-history key of the whole store; it can never
// be a feed name.
const TotalHistoryKey = "*"

// VolumeHistory returns the recorded set sizes of feed (or of the whole
// store, TotalHistoryKey), oldest first. The volume guard decides what is
// recorded and how much is kept.
func (s *Store) VolumeHistory(feed string) []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]int(nil), s.history[feed]...)
}

// SetVolumeHistory replaces feed's volume history and persists it; nil or
// empty forgets it.
func (s *Store) SetVolumeHistory(feed string, sizes []int) error {
	sizes = append([]int(nil), sizes...)
	s.mu.Lock()
	if len(sizes) == 0 {
		delete(s.history, feed)
	} else {
		s.history[feed] = sizes
	}
	s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	return s.db.setVolumeHistory(feed, sizes)
}

// HeldSet is one feed fetch that the volume guard held back instead of
// applying: the previous set keeps being served until an operator releases
// or discards it, or a later fetch of the feed passes and supersedes it.
type HeldSet struct {
	Feed     string    `json:"source"`
	ID       string    `json:"id"`      // content hash; a release must name it
	Reason   string    `json:"reason"`  // the guard's reason
	Detail   string    `json:"detail"`  // the guard's explanation, for humans
	Partial  bool      `json:"partial"` // the fetch itself failed half-way
	Started  time.Time `json:"fetch_started"`
	HeldAt   time.Time `json:"held_at"`
	Size     int       `json:"size"`     // distinct valid indicators in the fetch
	Baseline int       `json:"baseline"` // the usual size it was judged against
	NewKeys  int       `json:"new"`      // indicators the store did not hold, when held
	Total    int       `json:"store_total"`
	// Truncated counts indicators beyond the held cap that were not kept
	// (the store could not have taken them anyway).
	Truncated int         `json:"truncated,omitempty"`
	Rows      []Indicator `json:"-"`
}

// Held returns the held fetch of feed, if any. Rows are shared: do not
// modify them.
func (s *Store) Held(feed string) (HeldSet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h, ok := s.held[feed]
	return h, ok
}

// HeldSets returns every held fetch without its rows, by feed.
func (s *Store) HeldSets() map[string]HeldSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]HeldSet, len(s.held))
	for f, h := range s.held {
		h.Rows = nil
		out[f] = h
	}
	return out
}

// Hold records h as feed's held fetch, replacing any earlier one, and
// persists it. On a persistence error it is still held in memory.
func (s *Store) Hold(h HeldSet) error {
	s.mu.Lock()
	s.held[h.Feed] = h
	s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	return s.db.saveHeld(h)
}

// DropHeld forgets feed's held fetch.
func (s *Store) DropHeld(feed string) error {
	s.mu.Lock()
	delete(s.held, feed)
	s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	return s.db.deleteHeld(feed)
}

func (s *Store) prune(drop func(assertion) bool) int {
	var removed []assertionKey
	gone := 0
	s.mu.Lock()
	for k, e := range s.items {
		before := len(e.feeds)
		kept := e.feeds[:0]
		for _, a := range e.feeds {
			if drop(a) {
				removed = append(removed, assertionKey{typ: a.ind.Type, value: a.ind.Value, feed: a.feed})
				continue
			}
			kept = append(kept, a)
		}
		e.feeds = kept
		switch {
		case len(kept) == 0:
			delete(s.items, k)
			gone++
		case len(kept) != before:
			e.agg = aggregate(kept)
		}
	}
	s.mu.Unlock()

	if s.db != nil && len(removed) > 0 {
		s.dbMu.Lock()
		err := s.db.deleteAssertions(removed)
		s.dbMu.Unlock()
		if err != nil {
			slog.Error("indicator database: deleting expired assertions failed", "error", err)
		}
	}
	return gone
}

// All returns a snapshot of every indicator in the store.
func (s *Store) All() []Indicator {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Indicator, 0, len(s.items))
	for _, e := range s.items {
		out = append(out, e.agg)
	}
	return out
}

// ByType returns all indicators matching the given type.
func (s *Store) ByType(iocType string) []Indicator {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []Indicator
	for _, e := range s.items {
		if e.agg.Type == iocType {
			out = append(out, e.agg)
		}
	}
	return out
}

// Len returns the number of unique indicators.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items)
}

// Persistent reports whether the store is backed by a database.
func (s *Store) Persistent() bool { return s.db != nil }

// Clear removes all indicators, including persisted ones.
func (s *Store) Clear() {
	s.mu.Lock()
	s.items = make(map[string]*entry)
	s.mu.Unlock()
	if s.db != nil {
		s.dbMu.Lock()
		defer s.dbMu.Unlock()
		if err := s.db.clearAssertions(); err != nil {
			slog.Error("indicator database: clear failed", "error", err)
		}
	}
}

// Close releases the database, if any.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	s.dbMu.Lock()
	defer s.dbMu.Unlock()
	return s.db.close()
}

// set replaces feed's assertion and refreshes the aggregate.
func (e *entry) set(feed string, ind Indicator) {
	i := sort.Search(len(e.feeds), func(i int) bool { return e.feeds[i].feed >= feed })
	if i < len(e.feeds) && e.feeds[i].feed == feed {
		e.feeds[i].ind = ind
	} else {
		e.feeds = append(e.feeds, assertion{})
		copy(e.feeds[i+1:], e.feeds[i:])
		e.feeds[i] = assertion{feed: feed, ind: ind}
	}
	e.agg = aggregate(e.feeds)
}

// aggregate combines the current assertions of one key. Confidence is the
// highest any feed currently claims; threat and reference come from that
// feed; dates span all of them.
func aggregate(feeds []assertion) Indicator {
	best := 0
	for i, a := range feeds {
		b := feeds[best].ind
		if a.ind.Confidence > b.Confidence ||
			(a.ind.Confidence == b.Confidence && a.ind.LastAsserted.After(b.LastAsserted)) {
			best = i
		}
	}
	agg := feeds[best].ind
	agg.Tags = nil
	sources := map[string]struct{}{}
	for _, a := range feeds {
		ind := a.ind
		for _, src := range strings.Split(ind.Source, ",") {
			if src != "" {
				sources[src] = struct{}{}
			}
		}
		if !ind.FirstSeen.IsZero() && (agg.FirstSeen.IsZero() || ind.FirstSeen.Before(agg.FirstSeen)) {
			agg.FirstSeen = ind.FirstSeen
		}
		if ind.LastSeen.After(agg.LastSeen) {
			agg.LastSeen = ind.LastSeen
		}
		if ind.LastAsserted.After(agg.LastAsserted) {
			agg.LastAsserted = ind.LastAsserted
		}
		if agg.Threat == "" {
			agg.Threat = ind.Threat
		}
		if agg.Reference == "" {
			agg.Reference = ind.Reference
		}
		agg.Tags = mergeTags(agg.Tags, ind.Tags)
	}
	names := make([]string, 0, len(sources))
	for src := range sources {
		names = append(names, src)
	}
	sort.Strings(names)
	agg.Source = strings.Join(names, ",")
	return agg
}

func truncateForLog(v string) string {
	const max = 128
	if len(v) <= max {
		return v
	}
	return fmt.Sprintf("%s…(%d bytes)", v[:max], len(v))
}
