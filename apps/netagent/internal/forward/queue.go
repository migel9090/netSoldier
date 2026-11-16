package forward

import (
	"sync"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

// Queue is a bounded ring of captured frames. When it is full the oldest
// frame is dropped and counted, so an unreachable device-inventory or a flood
// on the LAN costs frames, never memory.
//
// Delivery is at least once: the forwarder peeks a batch, sends it, and
// commits it only on success. Frames are numbered, so a frame dropped while
// its batch was in flight is not removed twice.
type Queue struct {
	mu      sync.Mutex
	ring    []proto.Frame
	head    uint64 // sequence number of the oldest frame held
	n       int
	dropped uint64
}

// NewQueue holds at most capacity frames.
func NewQueue(capacity int) *Queue { return &Queue{ring: make([]proto.Frame, capacity)} }

// Push adds f, dropping the oldest frame if the queue is full.
func (q *Queue) Push(f proto.Frame) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == len(q.ring) {
		q.ring[q.head%uint64(len(q.ring))] = proto.Frame{}
		q.head++
		q.n--
		q.dropped++
	}
	q.ring[(q.head+uint64(q.n))%uint64(len(q.ring))] = f
	q.n++
}

// Peek returns the oldest frames whose summed cost stays within budget (at
// most max frames), and the sequence number to pass to Commit once they
// have been delivered. The frames are shared, not copied; they are never
// modified after Push.
func (q *Queue) Peek(max, budget int, cost func(proto.Frame) int) ([]proto.Frame, uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []proto.Frame
	spent := 0
	for i := 0; i < q.n && len(out) < max; i++ {
		f := q.ring[(q.head+uint64(i))%uint64(len(q.ring))]
		c := cost(f)
		if spent+c > budget {
			break
		}
		spent += c
		out = append(out, f)
	}
	return out, q.head + uint64(len(out))
}

// Commit removes every frame numbered below end that is still held.
func (q *Queue) Commit(end uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.removeBelow(end)
}

// Discard removes frames below end as Commit does, but counts them as
// dropped: device-inventory refused the batch they were in.
func (q *Queue) Discard(end uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.dropped += uint64(q.removeBelow(end))
}

func (q *Queue) removeBelow(end uint64) int {
	removed := 0
	for q.n > 0 && q.head < end {
		q.ring[q.head%uint64(len(q.ring))] = proto.Frame{}
		q.head++
		q.n--
		removed++
	}
	return removed
}

// Len is the number of frames held.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// Dropped is the number of frames lost since start.
func (q *Queue) Dropped() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}
