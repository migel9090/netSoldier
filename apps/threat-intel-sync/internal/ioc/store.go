package ioc

import (
	"log/slog"
	"sync"
	"time"
)

// Store is a thread-safe in-memory IoC store with deduplication.
// Indicators sharing the same (Type, Value) key are merged.
type Store struct {
	mu    sync.RWMutex
	items map[string]*Indicator
}

// NewStore creates an empty IoC store.
func NewStore() *Store {
	return &Store{items: make(map[string]*Indicator)}
}

// Upsert inserts a new indicator or merges it with an existing one.
func (s *Store) Upsert(ind Indicator) {
	key := ind.Key()
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.items[key]; ok {
		existing.Merge(ind)
	} else {
		copy := ind
		s.items[key] = &copy
	}
}

// UpsertAll validates and inserts/merges a batch of indicators, returning
// how many were accepted and how many were rejected.
//
// Feed content is third-party input, so this is a trust boundary: an
// indicator that is too broad to act on (a bare TLD, a catch-all CIDR) is
// dropped here rather than stored, because everything downstream — the
// Suricata datasets, the Zeek intel file, the AdGuard rules, the Vector
// enrichment tables and the detection-engine's matcher — is generated from
// this store.
func (s *Store) UpsertAll(inds []Indicator) (accepted, rejected int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ind := range inds {
		valid, err := Validate(ind)
		if err != nil {
			rejected++
			slog.Warn("rejected indicator from feed",
				"source", ind.Source, "type", ind.Type, "value", ind.Value, "error", err)
			continue
		}
		key := valid.Key()
		if existing, ok := s.items[key]; ok {
			existing.Merge(valid)
		} else {
			copied := valid
			s.items[key] = &copied
		}
		accepted++
	}
	return accepted, rejected
}

// PruneBefore removes indicators whose most recent sighting is older than
// cutoff, returning how many were dropped.
//
// Nothing used to expire: a domain withdrawn by a feed (because it was a
// false positive, or because the registration lapsed and a legitimate owner
// took it over) kept matching forever, since the store only ever grew. An
// indicator is a current claim, not a permanent fact.
func (s *Store) PruneBefore(cutoff time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	for key, ind := range s.items {
		stamp := ind.LastSeen
		if stamp.IsZero() {
			stamp = ind.FirstSeen
		}
		if stamp.IsZero() {
			continue // never dated; keep rather than guess
		}
		if stamp.Before(cutoff) {
			delete(s.items, key)
			removed++
		}
	}
	return removed
}

// All returns a snapshot of every indicator in the store.
func (s *Store) All() []Indicator {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Indicator, 0, len(s.items))
	for _, ind := range s.items {
		out = append(out, *ind)
	}
	return out
}

// ByType returns all indicators matching the given type.
func (s *Store) ByType(iocType string) []Indicator {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []Indicator
	for _, ind := range s.items {
		if ind.Type == iocType {
			out = append(out, *ind)
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

// Clear removes all indicators.
func (s *Store) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = make(map[string]*Indicator)
}
