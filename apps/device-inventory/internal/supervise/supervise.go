// Package supervise keeps the listener goroutines alive: each one runs under
// a supervisor that recovers panics, restarts it with exponential backoff
// when it returns, and records whether it is currently up. The recorded
// state is what /readyz and the device_inventory_listener_up gauge report.
package supervise

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
)

// RunFunc is a listener body. It calls up() once its socket is open and it
// is about to read; it returns when ctx is done (nil) or when it fails.
type RunFunc func(ctx context.Context, up func()) error

// Backoff bounds. A listener that stayed up for ResetAfter is considered
// healthy again and its next failure restarts after Initial.
var (
	Initial    = time.Second
	Max        = time.Minute
	ResetAfter = time.Minute
)

// Status is the set of supervised listeners and their current state.
type Status struct {
	mu     sync.Mutex
	states map[string]*state
}

type state struct {
	up        bool
	lastError string
	restarts  int
}

// ListenerState is the externally visible state of one listener.
type ListenerState struct {
	Up        bool   `json:"up"`
	LastError string `json:"last_error,omitempty"`
	Restarts  int    `json:"restarts"`
}

// NewStatus returns an empty registry.
func NewStatus() *Status { return &Status{states: make(map[string]*state)} }

// Register declares a listener before it starts, so that readiness is false
// until it has actually come up rather than true because nothing is known.
func (s *Status) Register(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.states[name]; !ok {
		s.states[name] = &state{}
		metrics.ListenerUp.WithLabelValues(name).Set(0)
	}
}

func (s *Status) set(name string, up bool, err error, restarted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.states[name]
	if !ok {
		st = &state{}
		s.states[name] = st
	}
	st.up = up
	if err != nil {
		st.lastError = err.Error()
	}
	if restarted {
		st.restarts++
	}
	v := 0.0
	if up {
		v = 1
	}
	metrics.ListenerUp.WithLabelValues(name).Set(v)
}

// Ready reports whether every registered listener is up, with a snapshot of
// each one's state. Listeners are registered before they start, so a
// configured listener counts as down until it has come up; with none
// configured there is nothing to wait for.
func (s *Status) Ready() (bool, map[string]ListenerState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]ListenerState, len(s.states))
	ready := true
	for name, st := range s.states {
		out[name] = ListenerState{Up: st.up, LastError: st.lastError, Restarts: st.restarts}
		ready = ready && st.up
	}
	return ready, out
}

// Names lists the registered listeners in a stable order.
func (s *Status) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.states))
	for n := range s.states {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Run supervises fn until ctx is done. It never returns early: a listener
// that fails, panics or returns is restarted after a backoff.
func Run(ctx context.Context, st *Status, name string, fn RunFunc) {
	st.Register(name)
	backoff := Initial
	for {
		var upAt time.Time
		err := runOnce(ctx, name, fn, func() {
			upAt = time.Now()
			st.set(name, true, nil, false)
			slog.Info("listener up", "listener", name)
		})
		if ctx.Err() != nil {
			st.set(name, false, nil, false)
			return
		}
		if err == nil {
			err = fmt.Errorf("listener returned without an error")
		}
		if !upAt.IsZero() && time.Since(upAt) >= ResetAfter {
			backoff = Initial
		}
		st.set(name, false, err, true)
		metrics.ListenerRestarts.WithLabelValues(name).Inc()
		slog.Warn("listener stopped; restarting", "listener", name, "error", err, "backoff", backoff.String())

		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			st.set(name, false, nil, false)
			return
		case <-t.C:
		}
		backoff = min(backoff*2, Max)
	}
}

func runOnce(ctx context.Context, name string, fn RunFunc, up func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("listener panicked", "listener", name, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return fn(ctx, up)
}
