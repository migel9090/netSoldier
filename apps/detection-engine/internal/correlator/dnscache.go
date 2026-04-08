package correlator

import (
	"sync"
	"time"
)

// DNSCache maps destination IPs to the domain names that resolved to them,
// using TTL-based expiry.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]dnsEntry
}

type dnsEntry struct {
	domain  string
	expires time.Time
}

func NewDNSCache() *DNSCache {
	return &DNSCache{entries: make(map[string]dnsEntry)}
}

// Set records that the given IP resolved from the given domain name.
func (c *DNSCache) Set(ip, domain string, ttlSeconds int) {
	if ttlSeconds <= 0 {
		ttlSeconds = 300
	}
	c.mu.Lock()
	c.entries[ip] = dnsEntry{
		domain:  domain,
		expires: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	}
	c.mu.Unlock()
}

// Get returns the domain name for an IP, or "" if not cached or expired.
func (c *DNSCache) Get(ip string) string {
	c.mu.RLock()
	e, ok := c.entries[ip]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return ""
	}
	return e.domain
}

// Len returns the number of cached entries (including expired).
func (c *DNSCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
