// Package devices resolves a detection's client address to the device that
// holds it — MAC and name — through device-inventory's
// GET /devices/by-ip/{ip}.
//
// The killswitch allowlist matches MAC first and composite correlation keys
// on it, because home DHCP leases move: an event that carries only an
// address is attributed to whichever device holds that address when it is
// acted on. Resolution is best effort by design — a missing MAC must never
// stop a detection from being reported — so every failure is counted and an
// unreachable inventory is said out loud, once, instead of per detection.
package devices

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	// DefaultTTL is how long an answer (including "no such device") is
	// reused. Short, because a lease that moved must stop being attributed
	// to the old holder quickly; long enough that a burst of detections
	// from one device costs one lookup.
	DefaultTTL = time.Minute
	// requestTimeout bounds one lookup. Lookups run on the alert path.
	requestTimeout = 2 * time.Second
	// retryAfter is how long lookups are skipped after the inventory failed
	// to answer, so an outage costs one timeout per period rather than one
	// per detection.
	retryAfter = 15 * time.Second
	// maxCached bounds the cache; client addresses in sensor rows are not
	// all local.
	maxCached = 4096
	// maxNameBytes bounds the device name, which device-inventory learns
	// from DHCP/mDNS — i.e. from whatever the device chose to announce.
	maxNameBytes = 128
	maxBodyBytes = 64 << 10
)

// Failure reasons for lookupFailures.
const (
	reasonUnreachable  = "unreachable"  // transport error, timeout or 5xx
	reasonUnauthorized = "unauthorized" // 401/403: DEVICE_API_KEY refused
	reasonNotFound     = "not_found"    // no device holds the address
	reasonInvalid      = "invalid"      // unusable answer
)

var lookupFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Name:      "device_lookup_failures_total",
	Help:      "Client address lookups in device-inventory that produced no MAC, by reason.",
}, []string{"reason"})

func init() {
	prometheus.MustRegister(lookupFailures)
	for _, r := range []string{reasonUnreachable, reasonUnauthorized, reasonNotFound, reasonInvalid} {
		lookupFailures.WithLabelValues(r)
	}
}

// Device is what a detection needs to know about its client.
type Device struct {
	MAC  string // lower-case, colon-separated
	Name string
}

type cached struct {
	dev     Device
	reason  string // why there is no MAC, for a negative answer
	expires time.Time
}

// Resolver looks devices up with a small TTL cache. Safe for concurrent use.
type Resolver struct {
	base   string
	apiKey string
	ttl    time.Duration
	http   *http.Client
	now    func() time.Time

	mu        sync.Mutex
	cache     map[string]cached
	downUntil time.Time
	downWhy   string // reason of the current outage, "" while reachable
}

// New returns a resolver for the device-inventory at baseURL, authenticating
// with apiKey (DEVICE_API_KEY). ttl <= 0 means DefaultTTL.
func New(baseURL, apiKey string, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Resolver{
		base:   strings.TrimRight(baseURL, "/"),
		apiKey: apiKey,
		ttl:    ttl,
		http:   &http.Client{Timeout: requestTimeout},
		now:    time.Now,
		cache:  make(map[string]cached),
	}
}

// Resolve returns the MAC and name of the device holding ip, or empty
// strings when that is not known. It never fails the caller.
func (r *Resolver) Resolve(ip string) (mac, name string) {
	addr, ok := events.CanonicalIP(ip)
	if !ok {
		lookupFailures.WithLabelValues(reasonInvalid).Inc()
		return "", ""
	}

	now := r.now()
	r.mu.Lock()
	if c, ok := r.cache[addr]; ok && now.Before(c.expires) {
		r.mu.Unlock()
		if c.reason != "" {
			lookupFailures.WithLabelValues(c.reason).Inc()
		}
		return c.dev.MAC, c.dev.Name
	}
	if now.Before(r.downUntil) {
		why := r.downWhy
		r.mu.Unlock()
		lookupFailures.WithLabelValues(why).Inc()
		return "", ""
	}
	r.mu.Unlock()

	dev, reason, err := r.lookup(addr)

	r.mu.Lock()
	defer r.mu.Unlock()
	switch reason {
	case reasonUnreachable, reasonUnauthorized:
		r.markDown(now, reason, err)
		lookupFailures.WithLabelValues(reason).Inc()
		return "", ""
	}
	r.markUp()
	r.store(addr, cached{dev: dev, reason: reason, expires: now.Add(r.ttl)}, now)
	if reason != "" {
		lookupFailures.WithLabelValues(reason).Inc()
		if reason == reasonInvalid {
			slog.Warn("device-inventory returned an unusable device", "ip", addr, "error", err)
		}
	}
	return dev.MAC, dev.Name
}

// lookup asks the inventory once. reason is "" on success.
func (r *Resolver) lookup(ip string) (Device, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		r.base+"/devices/by-ip/"+url.PathEscape(ip), nil)
	if err != nil {
		return Device{}, reasonUnreachable, err
	}
	if r.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+r.apiKey)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return Device{}, reasonUnreachable, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusNotFound:
		return Device{}, reasonNotFound, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Device{}, reasonUnauthorized, fmt.Errorf("status %d", resp.StatusCode)
	case resp.StatusCode >= 500:
		return Device{}, reasonUnreachable, fmt.Errorf("status %d", resp.StatusCode)
	default:
		return Device{}, reasonInvalid, fmt.Errorf("status %d", resp.StatusCode)
	}

	var d struct {
		MAC      string `json:"mac"`
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		return Device{}, reasonInvalid, fmt.Errorf("decode: %w", err)
	}
	mac, ok := canonicalMAC(d.MAC)
	if !ok {
		return Device{}, reasonInvalid, fmt.Errorf("mac %q is not a unicast hardware address", d.MAC)
	}
	return Device{MAC: mac, Name: cleanName(d.Hostname)}, "", nil
}

// markDown opens the circuit and, on the transition only, says why: one
// line per outage, not one per detection.
func (r *Resolver) markDown(now time.Time, reason string, err error) {
	r.downUntil = now.Add(retryAfter)
	if r.downWhy == reason {
		return
	}
	r.downWhy = reason
	if reason == reasonUnauthorized {
		slog.Error("device-inventory rejected our credentials — detections carry no client MAC; "+
			"check DEVICE_API_KEY against the inventory's key",
			"url", r.base, "has_key", r.apiKey != "", "error", err)
		return
	}
	slog.Warn("device-inventory unreachable — detections carry no client MAC until it answers again",
		"url", r.base, "error", err, "retry_after", retryAfter)
}

func (r *Resolver) markUp() {
	if r.downWhy != "" {
		slog.Info("device-inventory reachable again, client MACs resolve", "url", r.base)
	}
	r.downWhy, r.downUntil = "", time.Time{}
}

func (r *Resolver) store(ip string, c cached, now time.Time) {
	if len(r.cache) >= maxCached {
		for k, v := range r.cache {
			if !now.Before(v.expires) {
				delete(r.cache, k)
			}
		}
		// Still full of live entries: drop an arbitrary quarter rather than
		// grow. A dropped entry only costs one more lookup.
		for k := range r.cache {
			if len(r.cache) < maxCached*3/4 {
				break
			}
			delete(r.cache, k)
		}
	}
	r.cache[ip] = c
}

// canonicalMAC accepts a unicast, non-zero 48-bit MAC in any common notation
// and returns it lower-case and colon-separated. A group (multicast or
// broadcast) address is never a device's own.
func canonicalMAC(s string) (string, bool) {
	hw, err := net.ParseMAC(strings.TrimSpace(s))
	if err != nil || len(hw) != 6 || hw[0]&1 == 1 {
		return "", false
	}
	if string(hw) == "\x00\x00\x00\x00\x00\x00" {
		return "", false
	}
	return hw.String(), true
}

// cleanName keeps a device name printable and bounded; it is shown to
// operators and stored with every alert.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) <= maxNameBytes {
		return s
	}
	s = s[:maxNameBytes]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
