package dnscache

import (
	"fmt"
	"testing"
	"time"
)

// TestCrossClientAnswersStaySeparate: one device resolving its own zone to
// a shared CDN address used to relabel that address for every device, which
// then fed the other devices' SNI checks.
func TestCrossClientAnswersStaySeparate(t *testing.T) {
	c := New(0)
	c.Set("192.168.1.10", "151.101.1.69", "www.legit-shop.example", 300)
	c.Set("192.168.1.66", "151.101.1.69", "evil.attacker.example", 86400)

	if got := c.Get("192.168.1.10", "151.101.1.69"); got != "www.legit-shop.example" {
		t.Errorf("device A sees %q, want its own lookup", got)
	}
	if got := c.Get("192.168.1.66", "151.101.1.69"); got != "evil.attacker.example" {
		t.Errorf("device B sees %q", got)
	}
	if got := c.Get("192.168.1.20", "151.101.1.69"); got != "" {
		t.Errorf("a device that resolved nothing sees %q", got)
	}
}

// TestCacheIsBounded: an attacker-run zone answering every lookup with fresh
// addresses grew the cache without limit (500k entries, 87 MiB, none ever
// deleted).
func TestCacheIsBounded(t *testing.T) {
	const capacity = 1000
	c := New(capacity)
	for i := 0; i < 500_000; i++ {
		c.Set("192.168.1.66", fmt.Sprintf("2001:db8:%x:%x::1", i>>16, i&0xffff),
			fmt.Sprintf("x%d.attacker.example", i%300), 1)
	}
	if n := c.Len(); n > capacity {
		t.Fatalf("cache holds %d entries, cap is %d", n, capacity)
	}
	// The newest answers are the ones kept.
	if got := c.Get("192.168.1.66", fmt.Sprintf("2001:db8:%x:%x::1", 499_999>>16, 499_999&0xffff)); got == "" {
		t.Error("the most recent answer was evicted")
	}
}

func TestExpiredAnswersAreNotReturnedAndDrain(t *testing.T) {
	c := New(0)
	now := time.Now()
	c.now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		c.Set("192.168.1.66", fmt.Sprintf("203.0.113.%d", i), "x.example", 1)
	}
	// TTL 1 s is clamped up to a minute: clients connect a little after it.
	now = now.Add(30 * time.Second)
	if got := c.Get("192.168.1.66", "203.0.113.0"); got != "x.example" {
		t.Errorf("a 1 s answer is gone after 30 s: %q", got)
	}
	now = now.Add(2 * time.Minute)
	if got := c.Get("192.168.1.66", "203.0.113.1"); got != "" {
		t.Errorf("expired answer returned: %q", got)
	}
	// New answers sweep the old ones out without waiting for the cap.
	for i := 0; i < 10; i++ {
		c.Set("192.168.1.67", fmt.Sprintf("198.51.100.%d", i), "y.example", 60)
	}
	if n := c.Len(); n != 10 {
		t.Errorf("Len = %d, want only the 10 live answers", n)
	}
}

func TestLongTTLIsClamped(t *testing.T) {
	c := New(0)
	now := time.Now()
	c.now = func() time.Time { return now }
	c.Set("192.168.1.66", "203.0.113.9", "x.example", 7*24*3600)
	now = now.Add(2 * time.Hour)
	if got := c.Get("192.168.1.66", "203.0.113.9"); got != "" {
		t.Errorf("a week-long TTL kept the answer for 2 h: %q", got)
	}
}

func TestUpdateAndCanonicalForms(t *testing.T) {
	c := New(0)
	c.Set("::ffff:192.168.1.66", "2001:DB8::7", "old.example", 60)
	c.Set("192.168.1.66", "2001:db8::7", "new.example", 60)
	if got := c.Get("192.168.1.66", "2001:db8:0::7"); got != "new.example" {
		t.Errorf("Get = %q, want the latest answer under canonical keys", got)
	}
	if c.Len() != 1 {
		t.Errorf("Len = %d, want one entry for one (client, address)", c.Len())
	}
	c.Set("not-an-ip", "203.0.113.1", "x.example", 60)
	c.Set("192.168.1.66", "203.0.113.1", "", 60)
	if c.Len() != 1 || c.Get("not-an-ip", "203.0.113.1") != "" {
		t.Error("unusable input was cached")
	}
}
