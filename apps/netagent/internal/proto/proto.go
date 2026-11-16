// Package proto holds the JSON shapes of contract v2 section 8 and the limits
// the agent applies to them. Both channels (frames to device-inventory,
// isolation with the killswitch) are outbound HTTP requests whose response
// carries commands, and whose outcomes travel back in a later request.
package proto

import (
	"sync"
	"time"
)

// Command types. arp_probe is only accepted from device-inventory;
// arp_isolate and arp_release only from the killswitch.
const (
	CmdARPProbe   = "arp_probe"
	CmdARPIsolate = "arp_isolate"
	CmdARPRelease = "arp_release"
)

// Limits. MaxBody is the contract's request bound; the others keep a
// misbehaving peer from making the agent buffer or log without bound.
const (
	MaxBody        = 1 << 20  // request body, both channels
	MaxResponse    = 64 << 10 // response body read from a peer
	MaxCommands    = 16       // commands acted on per response; the rest are ignored
	MaxIDLen       = 64
	MaxErrorLen    = 200
	MaxResultBatch = 64 // results reported per request
)

// Frame is one captured Ethernet frame. Data is the whole frame, so the
// receiver can compare the link-layer source with what the payload claims.
type Frame struct {
	T     int64  `json:"t"` // capture time, Unix nanoseconds
	Proto string `json:"proto"`
	Data  []byte `json:"data"` // encoding/json sends it as standard base64
}

// Result is the outcome of one command, reported in a later request.
type Result struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// Status is the agent's heartbeat payload: which captures are running, and
// how many frames the bounded queue has had to drop since the agent started.
type Status struct {
	Capture map[string]bool `json:"capture"`
	Dropped uint64          `json:"dropped"`
}

// Batch is the body of POST /agent/v1/frames.
type Batch struct {
	Agent     string   `json:"agent"`
	Interface string   `json:"interface"`
	Frames    []Frame  `json:"frames"`
	Results   []Result `json:"results"`
	Status    Status   `json:"status"`
}

// Command is what a peer asks for. Target is used by arp_probe; MAC, IP and
// TTLSeconds by the isolation commands.
type Command struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Target     string `json:"target,omitempty"`
	MAC        string `json:"mac,omitempty"`
	IP         string `json:"ip,omitempty"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
}

// Commands is the response body of both channels.
type Commands struct {
	Commands []Command `json:"commands"`
}

// Active is one isolation in force, as reported to the killswitch so it can
// reconcile its own state with what the agent is really doing.
type Active struct {
	MAC     string    `json:"mac"`
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
}

// Poll is the body of POST /agent/v1/poll.
type Poll struct {
	Agent   string   `json:"agent"`
	Results []Result `json:"results"`
	Active  []Active `json:"active"`
}

// ValidID reports whether a command id is safe to echo back and to log:
// 1..MaxIDLen bytes of [A-Za-z0-9._:-]. A command without a valid id cannot
// be answered and is dropped.
func ValidID(id string) bool {
	if len(id) == 0 || len(id) > MaxIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// Clip bounds a string that may have come from a peer before it is logged or
// echoed back.
func Clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Results is a bounded FIFO of outcomes waiting to be reported. When it is
// full the oldest outcome is dropped: a peer that stops listening must not
// make the agent grow.
type Results struct {
	mu      sync.Mutex
	items   []Result
	max     int
	dropped uint64
}

// NewResults returns a queue holding at most max results.
func NewResults(max int) *Results { return &Results{max: max} }

// Add queues r, dropping the oldest result if the queue is full.
func (q *Results) Add(r Result) {
	r.Error = Clip(r.Error, MaxErrorLen)
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) >= q.max {
		q.items = q.items[1:]
		q.dropped++
	}
	q.items = append(q.items, r)
}

// Take removes and returns up to n results, oldest first.
func (q *Results) Take(n int) []Result {
	q.mu.Lock()
	defer q.mu.Unlock()
	n = min(n, len(q.items))
	out := make([]Result, n)
	copy(out, q.items[:n])
	q.items = q.items[n:]
	return out
}

// Return puts results that could not be delivered back at the front, still
// within the bound (the oldest are dropped first).
func (q *Results) Return(rs []Result) {
	if len(rs) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	all := append(append(make([]Result, 0, len(rs)+len(q.items)), rs...), q.items...)
	if over := len(all) - q.max; over > 0 {
		all = all[over:]
		q.dropped += uint64(over)
	}
	q.items = all
}

// Len is the number of results waiting.
func (q *Results) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}
