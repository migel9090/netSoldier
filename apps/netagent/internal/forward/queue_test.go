package forward

import (
	"testing"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

func frame(n byte) proto.Frame { return proto.Frame{T: int64(n), Proto: "arp", Data: []byte{n}} }

func unit(proto.Frame) int { return 1 }

func TestQueueDropsOldestWhenFull(t *testing.T) {
	q := NewQueue(3)
	for i := byte(0); i < 5; i++ {
		q.Push(frame(i))
	}
	if q.Len() != 3 || q.Dropped() != 2 {
		t.Fatalf("len=%d dropped=%d", q.Len(), q.Dropped())
	}
	got, end := q.Peek(10, 10, unit)
	if len(got) != 3 || got[0].Data[0] != 2 || got[2].Data[0] != 4 {
		t.Fatalf("kept the wrong frames: %+v", got)
	}
	q.Commit(end)
	if q.Len() != 0 {
		t.Fatalf("commit left %d", q.Len())
	}
}

func TestPeekRespectsBudgetAndMax(t *testing.T) {
	q := NewQueue(10)
	for i := byte(0); i < 6; i++ {
		q.Push(frame(i))
	}
	if got, _ := q.Peek(2, 100, unit); len(got) != 2 {
		t.Fatalf("max ignored: %d", len(got))
	}
	if got, _ := q.Peek(10, 3, unit); len(got) != 3 {
		t.Fatalf("budget ignored: %d", len(got))
	}
}

// TestCommitOnlyRemovesDelivered: frames that arrive while a batch is in
// flight are not lost when the batch commits.
func TestCommitOnlyRemovesDelivered(t *testing.T) {
	q := NewQueue(10)
	q.Push(frame(1))
	q.Push(frame(2))
	_, end := q.Peek(10, 100, unit)
	q.Push(frame(3)) // arrives after the peek
	q.Commit(end)
	got, _ := q.Peek(10, 100, unit)
	if len(got) != 1 || got[0].Data[0] != 3 {
		t.Fatalf("commit removed an undelivered frame: %+v", got)
	}
}

func TestDiscardCounts(t *testing.T) {
	q := NewQueue(10)
	q.Push(frame(1))
	q.Push(frame(2))
	_, end := q.Peek(10, 100, unit)
	q.Discard(end)
	if q.Len() != 0 || q.Dropped() != 2 {
		t.Fatalf("len=%d dropped=%d", q.Len(), q.Dropped())
	}
}
