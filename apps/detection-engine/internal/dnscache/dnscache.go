// Package dnscache remembers which name each client resolved to which
// address, so the TLS heuristics can ask "did THIS device look this address
// up, and as what?".
//
// Two properties matter more than hit rate. The key is (client, address): a
// CDN address is shared by thousands of names, and a cache keyed on the
// address alone let one device's lookup of its own zone relabel that address
// for every other device. And the size is bounded: answers come from DNS
// zones anyone can run, with any TTL and any number of distinct addresses.
package dnscache

import (
	"container/list"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

const (
	// DefaultMaxEntries bounds memory at roughly 10 MiB.
	DefaultMaxEntries = 65536
	// Answer TTLs are clamped: clients routinely connect a little after a
	// 1-second TTL ran out, and a day-long TTL would pin an entry that the
	// cap then has to evict anyway.
	minTTL = time.Minute
	maxTTL = time.Hour
	// sweepPerSet is how many of the oldest entries each Set inspects for
	// expiry, so expired entries drain without a background goroutine.
	sweepPerSet = 2
)

type key struct{ client, ip string }

type entry struct {
	key     key
	domain  string
	expires time.Time
}

// Cache is safe for concurrent use.
type Cache struct {
	mu      sync.Mutex
	max     int
	now     func() time.Time
	order   *list.List // front = most recently set
	entries map[key]*list.Element
}

// New returns a cache holding at most maxEntries answers (DefaultMaxEntries
// when maxEntries <= 0).
func New(maxEntries int) *Cache {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	return &Cache{
		max:     maxEntries,
		now:     time.Now,
		order:   list.New(),
		entries: make(map[key]*list.Element),
	}
}

// Set records that client resolved domain to ip, valid for the answer's TTL.
// Addresses that do not parse are ignored.
func (c *Cache) Set(client, ip, domain string, ttlSeconds int) {
	k, ok := makeKey(client, ip)
	if !ok || domain == "" {
		return
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	ttl = min(max(ttl, minTTL), maxTTL)

	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.sweep(now)

	if el, ok := c.entries[k]; ok {
		e := el.Value.(*entry)
		e.domain, e.expires = domain, now.Add(ttl)
		c.order.MoveToFront(el)
		return
	}
	for len(c.entries) >= c.max {
		c.remove(c.order.Back())
	}
	c.entries[k] = c.order.PushFront(&entry{key: k, domain: domain, expires: now.Add(ttl)})
}

// Get returns the name client resolved to ip, or "" when it did not (or the
// answer has expired).
func (c *Cache) Get(client, ip string) string {
	k, ok := makeKey(client, ip)
	if !ok {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.entries[k]
	if !ok {
		return ""
	}
	e := el.Value.(*entry)
	if !c.now().Before(e.expires) {
		c.remove(el)
		return ""
	}
	return e.domain
}

// Len returns the number of entries held, expired ones included until they
// are swept.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *Cache) sweep(now time.Time) {
	for i := 0; i < sweepPerSet; i++ {
		el := c.order.Back()
		if el == nil || now.Before(el.Value.(*entry).expires) {
			return
		}
		c.remove(el)
	}
}

func (c *Cache) remove(el *list.Element) {
	if el == nil {
		return
	}
	c.order.Remove(el)
	delete(c.entries, el.Value.(*entry).key)
}

func makeKey(client, ip string) (key, bool) {
	cl, ok1 := events.CanonicalIP(client)
	addr, ok2 := events.CanonicalIP(ip)
	return key{cl, addr}, ok1 && ok2
}
