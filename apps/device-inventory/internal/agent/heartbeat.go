package agent

import (
	"sort"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
)

// Heartbeat records the latest batch the agent sent. device-inventory's
// readiness and its per-protocol capture metric are derived from it
// (contract 8.1): no batch within the timeout means the agent is gone and
// the service is not ready, whatever its listeners used to say. The agent
// posts at least every heartbeat interval even with no frames.
type Heartbeat struct {
	timeout   time.Duration
	protocols []string
	now       func() time.Time

	mu      sync.Mutex
	seen    bool
	last    time.Time
	agent   string
	iface   string
	capture map[string]bool
	dropped uint64
}

// NewHeartbeat tracks liveness with the given timeout. protocols is the set
// expected to be capturing; readiness needs every one of them up.
func NewHeartbeat(timeout time.Duration, protocols []string) *Heartbeat {
	return &Heartbeat{timeout: timeout, protocols: append([]string(nil), protocols...), now: time.Now,
		capture: map[string]bool{}}
}

// Observe records a batch from the agent and updates the capture metrics.
func (h *Heartbeat) Observe(agent, iface string, capture map[string]bool, dropped uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seen = true
	h.last = h.now()
	h.agent, h.iface = agent, iface
	h.capture = map[string]bool{}
	for k, v := range capture {
		h.capture[k] = v
	}
	h.dropped = dropped
	for _, p := range h.protocols {
		up := 0.0
		if capture[p] {
			up = 1
		}
		metrics.CaptureUp.WithLabelValues(p).Set(up)
	}
	metrics.AgentFramesDropped.Set(float64(dropped))
	metrics.LastHeartbeat.SetToCurrentTime()
}

// State is the heartbeat snapshot the /readyz body shows.
type State struct {
	Ready      bool            `json:"ready"`
	Agent      string          `json:"agent,omitempty"`
	Interface  string          `json:"interface,omitempty"`
	LastSeen   time.Time       `json:"last_seen,omitzero"`
	AgeSeconds float64         `json:"age_seconds"`
	Capture    map[string]bool `json:"capture,omitempty"`
	Dropped    uint64          `json:"dropped"`
	Reason     string          `json:"reason,omitempty"`
}

// Status reports whether the agent is healthy: a batch within the timeout
// and every expected protocol capturing.
func (h *Heartbeat) Status() State {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := State{Agent: h.agent, Interface: h.iface, LastSeen: h.last, Dropped: h.dropped,
		Capture: map[string]bool{}}
	for k, v := range h.capture {
		st.Capture[k] = v
	}
	if !h.seen {
		st.Reason = "no heartbeat from the agent yet"
		return st
	}
	age := h.now().Sub(h.last)
	st.AgeSeconds = age.Seconds()
	if age > h.timeout {
		st.Reason = "no heartbeat within the timeout"
		return st
	}
	var down []string
	for _, p := range h.protocols {
		if !h.capture[p] {
			down = append(down, p)
		}
	}
	if len(down) > 0 {
		sort.Strings(down)
		st.Reason = "captures down: " + join(down)
		return st
	}
	st.Ready = true
	return st
}

func join(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}
