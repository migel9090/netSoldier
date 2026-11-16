package store

import (
	"sync"
	"time"
)

// maxTracked bounds the per-source maps. A flood of random source MACs fills
// them and they are simply reset: memory stays constant, and the worst case
// is a few extra writes for legitimate devices right after a reset.
const maxTracked = 8192

type bucket struct {
	tokens float64
	last   time.Time
}

func (b *bucket) allow(now time.Time, rate float64, burst int) bool {
	if b.last.IsZero() {
		b.tokens = float64(burst)
	} else if dt := now.Sub(b.last).Seconds(); dt > 0 {
		b.tokens = min(float64(burst), b.tokens+dt*rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type recent struct {
	sig string
	at  time.Time
}

// limiter decides, before any database work, whether a sighting is worth a
// write: identical repeats are coalesced, each source has a token bucket,
// and new rows share one global bucket.
type limiter struct {
	opts Options

	mu         sync.Mutex
	recent     map[string]recent
	perSource  map[string]*bucket
	newDevices bucket
}

func newLimiter(o Options) *limiter {
	return &limiter{opts: o, recent: make(map[string]recent), perSource: make(map[string]*bucket)}
}

func (l *limiter) admit(key, sig string, now time.Time) (Outcome, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if r, ok := l.recent[key]; ok && r.sig == sig && now.Sub(r.at) < l.opts.Coalesce {
		return Coalesced, false
	}
	b := l.perSource[key]
	if b == nil {
		if len(l.perSource) >= maxTracked {
			clear(l.perSource)
		}
		b = &bucket{}
		l.perSource[key] = b
	}
	if !b.allow(now, l.opts.PerSourceRate, l.opts.PerSourceBurst) {
		return RateLimited, false
	}
	return "", true
}

func (l *limiter) allowNew(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.newDevices.allow(now, l.opts.NewDeviceRate, l.opts.NewDeviceBurst)
}

func (l *limiter) remember(key, sig string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.recent[key]; !ok && len(l.recent) >= maxTracked {
		clear(l.recent)
	}
	l.recent[key] = recent{sig: sig, at: now}
}
