// Package ratelimit is a token bucket: the agent's rate limits on the
// commands that make it transmit.
package ratelimit

import (
	"sync"
	"time"
)

// Bucket allows n events per interval with a burst of n.
type Bucket struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

// New returns a full bucket that refills n tokens per interval.
func New(n int, interval time.Duration) *Bucket {
	return &Bucket{rate: float64(n) / interval.Seconds(), burst: float64(n), tokens: float64(n)}
}

// Allow takes a token if one is available at now.
func (b *Bucket) Allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() {
		if dt := now.Sub(b.last).Seconds(); dt > 0 {
			b.tokens = min(b.burst, b.tokens+dt*b.rate)
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
