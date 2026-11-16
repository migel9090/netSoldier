package ratelimit

import (
	"testing"
	"time"
)

func TestBucketBurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	b := New(2, time.Minute) // 2 per minute, burst 2
	if !b.Allow(now) || !b.Allow(now) {
		t.Fatal("burst of 2 not allowed")
	}
	if b.Allow(now) {
		t.Fatal("third token allowed within the burst")
	}
	// Half a minute later, one token has refilled.
	if !b.Allow(now.Add(30 * time.Second)) {
		t.Fatal("token did not refill")
	}
	if b.Allow(now.Add(30 * time.Second)) {
		t.Fatal("too many tokens after 30s")
	}
}
