// Package guard is the volume guard: a feed fetch that would change the
// indicator set far beyond what the feed usually delivers is held in
// quarantine instead of applied, and the previous set keeps being served.
//
// Validation (libs/indicator) refuses rows that are malformed or too broad,
// and the never-block list refuses popular and shared hosts, but neither
// can tell a feed that suddenly lists fifty thousand well-formed domains —
// poisoned upstream, a broken export, a misconfigured MISP feed — from a
// normal day. Every one of those domains would become a block in AdGuard
// for the whole household within one sync. The guard compares each fetch
// with the feed's own history and refuses to apply a sudden multiple, or a
// sudden collapse, until an operator has looked at it.
//
// The rules, with the defaults:
//
//   - The usual size of a feed is the median of the distinct-indicator
//     counts of its last HistoryLen applied fetches. A median, not the last
//     value, so one odd fetch neither moves it far nor can be used to ratchet
//     it up step by step.
//   - Growth: a fetch larger than GrowthFactor (3) × usual, by at least
//     MinChange (500) indicators, is held. A source that legitimately grows
//     does so by less than that per fetch, or once — and an operator
//     releasing a held fetch makes its size the new usual.
//   - Collapse: a complete fetch smaller than usual / ShrinkFactor (4), by
//     at least MinChange, is held. Applying it would mark the feed as having
//     withdrawn most of its set, and the withdrawn indicators would expire
//     after INDICATOR_TTL. A partial (failed) fetch is never judged on
//     collapse: it is incomplete by definition and never starts any expiry.
//   - Cold start: a feed with no history has no usual size. Its first fetch
//     is accepted up to FirstSyncMax (50000) distinct indicators and held
//     above that.
//   - Whole store: once every enabled feed has a history, the store size is
//     recorded after each applied fetch, and a fetch that would grow the
//     store beyond GrowthFactor × its usual size (by at least MinChange) is
//     held. This is what bounds a newly enabled feed joining an established
//     store. It is skipped until that history exists, so a fresh install —
//     where every feed is new — is not held for being fresh.
//   - MinChange keeps small feeds (Feodo lists a few dozen online C2s) from
//     tripping the factors on ordinary swings.
//
// A fetch can only grow the store: removals happen through expiry, one
// INDICATOR_TTL after a feed stopped listing an indicator, so a collapse of
// the whole store within one sync is not possible and not checked.
package guard

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

// HistoryLen is how many applied fetches a feed's usual size is taken from.
const HistoryLen = 7

// Reasons a fetch is held. They are label values of
// threat_intel_source_quarantine_total, so they must not change.
const (
	ReasonGrowth      = "growth"
	ReasonCollapse    = "collapse"
	ReasonFirstSync   = "first_sync"
	ReasonTotalGrowth = "total_growth"
)

// Reasons returns every reason, for pre-creating counter series.
func Reasons() []string {
	return []string{ReasonGrowth, ReasonCollapse, ReasonFirstSync, ReasonTotalGrowth}
}

// Limits are the guard's thresholds.
type Limits struct {
	GrowthFactor float64 // hold a fetch larger than this × usual
	ShrinkFactor float64 // hold a complete fetch smaller than usual / this
	MinChange    int     // ... and only when it differs from usual by at least this many
	FirstSyncMax int     // hold a feed's first fetch above this many indicators
}

// DefaultLimits are the safe defaults documented above.
func DefaultLimits() Limits {
	return Limits{GrowthFactor: 3, ShrinkFactor: 4, MinChange: 500, FirstSyncMax: 50000}
}

// Bounds of the configurable values. A factor of 1 or less would hold
// every fetch that is not exactly the usual size; above 1000 the guard is
// effectively off, which is not a supported configuration.
const (
	MinFactor       = 1.0
	MaxFactor       = 1000.0
	MaxMinChange    = 10_000_000
	MaxFirstSyncMax = 10_000_000
)

// Validate reports every limit outside its bounds.
func (l Limits) Validate() error {
	var errs []error
	if !(l.GrowthFactor > MinFactor && l.GrowthFactor <= MaxFactor) || math.IsNaN(l.GrowthFactor) {
		errs = append(errs, fmt.Errorf("growth factor %v: must be above %v and at most %v", l.GrowthFactor, MinFactor, MaxFactor))
	}
	if !(l.ShrinkFactor > MinFactor && l.ShrinkFactor <= MaxFactor) || math.IsNaN(l.ShrinkFactor) {
		errs = append(errs, fmt.Errorf("shrink factor %v: must be above %v and at most %v", l.ShrinkFactor, MinFactor, MaxFactor))
	}
	if l.MinChange < 0 || l.MinChange > MaxMinChange {
		errs = append(errs, fmt.Errorf("minimum change %d: must be between 0 and %d", l.MinChange, MaxMinChange))
	}
	if l.FirstSyncMax < 1 || l.FirstSyncMax > MaxFirstSyncMax {
		errs = append(errs, fmt.Errorf("first-sync maximum %d: must be between 1 and %d", l.FirstSyncMax, MaxFirstSyncMax))
	}
	return errors.Join(errs...)
}

// Input is what the guard knows about one fetch.
type Input struct {
	Size         int   // distinct valid indicators the fetch asserts
	History      []int // the feed's sizes after its last applied fetches, oldest first
	NewKeys      int   // indicators the store does not hold yet
	StoreTotal   int   // indicators in the store now
	TotalHistory []int // the store's sizes after applied fetches, oldest first
	Partial      bool  // the fetch failed half-way; only its rows so far are known
}

// Verdict is the guard's decision.
type Verdict struct {
	Hold     bool
	Reason   string // when held
	Baseline int    // the usual size the fetch was judged against
	Detail   string // a sentence for the log and the operator
}

// Check judges one fetch.
func (l Limits) Check(in Input) Verdict {
	if len(in.History) == 0 {
		if in.Size > l.FirstSyncMax {
			return Verdict{Hold: true, Reason: ReasonFirstSync, Detail: fmt.Sprintf(
				"first fetch of this source has %d indicators, above the first-sync maximum of %d",
				in.Size, l.FirstSyncMax)}
		}
	} else {
		base := Median(in.History)
		if in.Size > base && float64(in.Size) > l.GrowthFactor*float64(base) && in.Size-base >= l.MinChange {
			return Verdict{Hold: true, Reason: ReasonGrowth, Baseline: base, Detail: fmt.Sprintf(
				"fetch has %d indicators, %s the usual %d (limit: %v× and at least %d more)",
				in.Size, times(in.Size, base), base, l.GrowthFactor, l.MinChange)}
		}
		if !in.Partial && in.Size < base && float64(in.Size)*l.ShrinkFactor < float64(base) && base-in.Size >= l.MinChange {
			return Verdict{Hold: true, Reason: ReasonCollapse, Baseline: base, Detail: fmt.Sprintf(
				"fetch has %d indicators against the usual %d (limit: 1/%v and at least %d fewer)",
				in.Size, base, l.ShrinkFactor, l.MinChange)}
		}
	}
	if len(in.TotalHistory) > 0 {
		base := Median(in.TotalHistory)
		projected := in.StoreTotal + in.NewKeys
		if projected > base && float64(projected) > l.GrowthFactor*float64(base) && projected-base >= l.MinChange {
			return Verdict{Hold: true, Reason: ReasonTotalGrowth, Baseline: base, Detail: fmt.Sprintf(
				"applying it would grow the whole store to %d indicators, %s its usual %d (limit: %v× and at least %d more)",
				projected, times(projected, base), base, l.GrowthFactor, l.MinChange)}
		}
	}
	v := Verdict{}
	if len(in.History) > 0 {
		v.Baseline = Median(in.History)
	}
	return v
}

// Append returns history with size added, keeping the last HistoryLen.
func Append(history []int, size int) []int {
	out := append(append([]int(nil), history...), size)
	if len(out) > HistoryLen {
		out = out[len(out)-HistoryLen:]
	}
	return out
}

// Median of xs (the lower middle value for an even count, so a single high
// value among two cannot raise the usual size); 0 for none.
func Median(xs []int) int {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int(nil), xs...)
	sort.Ints(s)
	return s[(len(s)-1)/2]
}

func times(n, base int) string {
	if base <= 0 {
		return "against"
	}
	return fmt.Sprintf("%.1f× against", float64(n)/float64(base))
}
