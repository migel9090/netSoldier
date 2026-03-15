package ioc

import (
	"sync"
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

// UpsertAll inserts or merges a batch of indicators.
func (s *Store) UpsertAll(inds []Indicator) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, ind := range inds {
		key := ind.Key()
		if existing, ok := s.items[key]; ok {
			existing.Merge(ind)
		} else {
			copy := ind
			s.items[key] = &copy
		}
	}
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
