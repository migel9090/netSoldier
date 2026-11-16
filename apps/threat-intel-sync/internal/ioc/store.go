package ioc

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
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
		now:         time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// UpsertStats reports what one batch did to the store.
type UpsertStats struct {
	Accepted int   // valid rows now asserted by the feed
	Rejected int   // rows that failed validation
	Dropped  int   // valid rows refused because the store is full
	Err      error // persistence failed; the in-memory set was still updated
}

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
	}
	return accepted, rejected
}

// UpsertFeed validates a batch delivered by one feed and records each valid
// row as that feed's current assertion, stamped with the current time.
// Duplicate keys within the batch are merged first.
func (s *Store) UpsertFeed(feed string, inds []Indicator) UpsertStats {
	var st UpsertStats
	now := s.now().UTC()

	batch := make(map[string]Indicator, len(inds))
	rows := make(map[string]int, len(inds))
	var order []string
	for _, raw := range inds {
		v, err := Validate(raw)
		if err != nil {
			st.Rejected++
			if st.Rejected <= maxRejectLogs {
				slog.Warn("rejected indicator from feed", "feed", feed,
					"source", raw.Source, "type", raw.Type,
					"value", truncateForLog(raw.Value), "error", err)
			}
			continue
		}
		if v.Source == "" {
			v.Source = feed
		}
		v.LastAsserted = now
		k := v.Key()
		if prev, ok := batch[k]; ok {
			prev.Merge(v)
			batch[k] = prev
		} else {
			batch[k] = v
			order = append(order, k)
		}
		rows[k]++
	}
	if st.Rejected > maxRejectLogs {
		slog.Warn("further indicators rejected from feed", "feed", feed,
			"not_logged", st.Rejected-maxRejectLogs)
	}

	applied := make([]Indicator, 0, len(order))
	s.mu.Lock()
	for _, k := range order {
		e := s.items[k]
		if e == nil {
			if s.max > 0 && len(s.items) >= s.max {
				st.Dropped += rows[k]
				continue
			}
			e = &entry{}
			s.items[k] = e
		}
		ind := batch[k]
		e.set(feed, ind)
		applied = append(applied, ind)
		st.Accepted += rows[k]
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
// under COMMERCIAL_MODE — is not served from the persisted set.
func (s *Store) RetainFeeds(keep []string) int {
	allowed := make(map[string]bool, len(keep))
	for _, f := range keep {
		allowed[f] = true
	}
	n := s.prune(func(a assertion) bool { return !allowed[a.feed] })
	s.mu.Lock()
	var gone []string
	for f := range s.feedSuccess {
		if !allowed[f] {
			gone = append(gone, f)
			delete(s.feedSuccess, f)
		}
	}
	s.mu.Unlock()
	if s.db != nil && len(gone) > 0 {
		s.dbMu.Lock()
		defer s.dbMu.Unlock()
		for _, f := range gone {
			if err := s.db.deleteFeed(f); err != nil {
				slog.Error("indicator database: removing disabled feed failed", "feed", f, "error", err)
			}
		}
	}
	return n
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
