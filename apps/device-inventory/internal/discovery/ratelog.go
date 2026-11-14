package discovery

import (
	"sync"
	"time"
)

// LogLimiter lets a hot path log at most once per interval and reports how
// many events it swallowed in between, so a flood of forged frames costs one
// log line per interval instead of one per frame.
type LogLimiter struct {
	Interval time.Duration

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

// Allow reports whether the caller may log now and, if so, how many earlier
// events were suppressed since the last line.
func (l *LogLimiter) Allow(now time.Time) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.last.IsZero() && now.Sub(l.last) < l.Interval {
		l.suppressed++
		return false, 0
	}
	n := l.suppressed
	l.last, l.suppressed = now, 0
	return true, n
}
