package proto

import (
	"strings"
	"testing"
)

func TestValidID(t *testing.T) {
	good := []string{"c-17", "i-5", "abc.DEF_09:-", strings.Repeat("a", MaxIDLen)}
	for _, id := range good {
		if !ValidID(id) {
			t.Errorf("ValidID(%q) = false", id)
		}
	}
	bad := []string{"", "has space", "a/b", "a\nb", "emoji😀", strings.Repeat("a", MaxIDLen+1), "a;b"}
	for _, id := range bad {
		if ValidID(id) {
			t.Errorf("ValidID(%q) = true", id)
		}
	}
}

func TestResultsRingDropsOldest(t *testing.T) {
	q := NewResults(3)
	for i := 0; i < 5; i++ {
		q.Add(Result{ID: string(rune('a' + i))})
	}
	got := q.Take(10)
	if len(got) != 3 || got[0].ID != "c" || got[2].ID != "e" {
		t.Fatalf("ring kept the wrong three: %+v", got)
	}
	if q.Len() != 0 {
		t.Fatalf("Take did not drain: %d", q.Len())
	}
}

func TestResultsReturnStaysBounded(t *testing.T) {
	q := NewResults(2)
	q.Add(Result{ID: "x"})
	taken := q.Take(1)
	// Add two more while the taken one is "in flight", then return it.
	q.Add(Result{ID: "y"})
	q.Add(Result{ID: "z"})
	q.Return(taken)
	got := q.Take(10)
	if len(got) != 2 {
		t.Fatalf("Return exceeded the bound: %+v", got)
	}
	// The returned one goes to the front but the oldest overflow is dropped.
	if got[len(got)-1].ID != "z" {
		t.Fatalf("newest result lost: %+v", got)
	}
}

func TestClipAndErrorBound(t *testing.T) {
	q := NewResults(1)
	q.Add(Result{ID: "x", Error: strings.Repeat("e", MaxErrorLen+50)})
	if got := q.Take(1); len(got[0].Error) != MaxErrorLen {
		t.Fatalf("error not clipped: %d", len(got[0].Error))
	}
}
