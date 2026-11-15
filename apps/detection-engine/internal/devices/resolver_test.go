package devices

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// inventory is a stub of device-inventory's GET /devices/by-ip/{ip}
// (contract §5): bearer-authenticated, 404 for an address nobody holds.
type inventory struct {
	srv   *httptest.Server
	key   string
	calls atomic.Int32
	mu    sync.Mutex
	byIP  map[string]map[string]any
	down  atomic.Bool
}

func newInventory(t *testing.T, key string) *inventory {
	inv := &inventory{key: key, byIP: map[string]map[string]any{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /devices/by-ip/{ip}", func(w http.ResponseWriter, r *http.Request) {
		inv.calls.Add(1)
		if inv.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+inv.key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		inv.mu.Lock()
		d, ok := inv.byIP[r.PathValue("ip")]
		inv.mu.Unlock()
		if !ok {
			http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(d)
	})
	inv.srv = httptest.NewServer(mux)
	t.Cleanup(inv.srv.Close)
	return inv
}

func (inv *inventory) set(ip, mac, hostname string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	inv.byIP[ip] = map[string]any{"mac": mac, "ip": ip, "hostname": hostname, "labels": []string{}}
}

func failures(reason string) float64 {
	return testutil.ToFloat64(lookupFailures.WithLabelValues(reason))
}

func TestResolvesMACAndNameWithBearer(t *testing.T) {
	inv := newInventory(t, "dev-key")
	inv.set("192.168.1.77", "AA-BB-CC-DD-EE-FF", "kids-tablet")
	inv.set("2001:db8::77", "02:00:00:00:00:77", "v6-phone")
	r := New(inv.srv.URL, "dev-key", 0)

	if mac, name := r.Resolve("192.168.1.77"); mac != "aa:bb:cc:dd:ee:ff" || name != "kids-tablet" {
		t.Errorf("Resolve = %q, %q; want the canonical MAC and the name", mac, name)
	}
	if mac, _ := r.Resolve("2001:DB8::77"); mac != "02:00:00:00:00:77" {
		t.Errorf("IPv6 client resolved to %q", mac)
	}
}

// TestBurstCostsOneLookup: a device that makes 250 detections in a poll
// must not cost 250 inventory requests; within the TTL the answer is
// reused, and after it the lease may have moved, so it is asked again.
func TestBurstCostsOneLookup(t *testing.T) {
	inv := newInventory(t, "k")
	inv.set("192.168.1.77", "aa:bb:cc:dd:ee:ff", "tablet")
	r := New(inv.srv.URL, "k", time.Minute)
	now := time.Now()
	r.now = func() time.Time { return now }

	for i := 0; i < 250; i++ {
		r.Resolve("192.168.1.77")
	}
	if c := inv.calls.Load(); c != 1 {
		t.Errorf("250 lookups cost %d requests, want 1", c)
	}

	inv.set("192.168.1.77", "10:22:33:44:55:00", "laptop") // the lease moved
	now = now.Add(2 * time.Minute)
	if mac, _ := r.Resolve("192.168.1.77"); mac != "10:22:33:44:55:00" {
		t.Errorf("after the TTL the old holder %q is still reported", mac)
	}
}

func TestUnknownAddressIsCountedAndCached(t *testing.T) {
	inv := newInventory(t, "k")
	r := New(inv.srv.URL, "k", time.Minute)
	before := failures(reasonNotFound)
	for i := 0; i < 3; i++ {
		if mac, name := r.Resolve("192.168.1.200"); mac != "" || name != "" {
			t.Fatalf("unknown address resolved to %q %q", mac, name)
		}
	}
	if got := failures(reasonNotFound) - before; got != 3 {
		t.Errorf("not_found counted %v times, want once per detection without a MAC", got)
	}
	if c := inv.calls.Load(); c != 1 {
		t.Errorf("a 404 was not cached: %d requests", c)
	}
}

// TestUnreachableInventoryIsCountedNotRetriedPerDetection: an outage costs
// one request per retry period, every detection without a MAC is counted,
// and the service recovers by itself.
func TestUnreachableInventoryIsCountedNotRetriedPerDetection(t *testing.T) {
	inv := newInventory(t, "k")
	inv.set("192.168.1.77", "aa:bb:cc:dd:ee:ff", "tablet")
	inv.down.Store(true)
	r := New(inv.srv.URL, "k", time.Minute)
	now := time.Now()
	r.now = func() time.Time { return now }

	before := failures(reasonUnreachable)
	for i := 0; i < 50; i++ {
		if mac, _ := r.Resolve("192.168.1.77"); mac != "" {
			t.Fatal("resolved during an outage")
		}
	}
	if c := inv.calls.Load(); c != 1 {
		t.Errorf("outage cost %d requests, want 1 per retry period", c)
	}
	if got := failures(reasonUnreachable) - before; got != 50 {
		t.Errorf("unreachable counted %v, want 50", got)
	}

	inv.down.Store(false)
	now = now.Add(retryAfter + time.Second)
	if mac, _ := r.Resolve("192.168.1.77"); mac != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("did not recover after the outage: %q", mac)
	}
}

func TestNothingListening(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	r := New(url, "", 0)
	before := failures(reasonUnreachable)
	if mac, _ := r.Resolve("192.168.1.5"); mac != "" {
		t.Fatal("resolved with nothing listening")
	}
	if failures(reasonUnreachable) <= before {
		t.Error("an unreachable inventory must be counted")
	}
}

func TestRefusedKeyIsReportedAsUnauthorized(t *testing.T) {
	inv := newInventory(t, "right-key")
	inv.set("192.168.1.77", "aa:bb:cc:dd:ee:ff", "tablet")
	r := New(inv.srv.URL, "wrong-key", 0)
	before := failures(reasonUnauthorized)
	r.Resolve("192.168.1.77")
	r.Resolve("192.168.1.78")
	if got := failures(reasonUnauthorized) - before; got != 2 {
		t.Errorf("unauthorized counted %v, want 2", got)
	}
	if c := inv.calls.Load(); c != 1 {
		t.Errorf("a refused key was retried per detection: %d requests", c)
	}
}

// TestUnusableAnswersCarryNoMAC: a MAC from the inventory goes into the
// event the killswitch acts on. A group address is never a device's own,
// and an unparsable one must not reach the contract.
func TestUnusableAnswersCarryNoMAC(t *testing.T) {
	inv := newInventory(t, "k")
	inv.set("192.168.1.1", "ff:ff:ff:ff:ff:ff", "broadcast")
	inv.set("192.168.1.2", "01:00:5e:00:00:fb", "multicast")
	inv.set("192.168.1.3", "00:00:00:00:00:00", "zero")
	inv.set("192.168.1.4", "not-a-mac", "garbage")
	inv.set("192.168.1.5", "aa:bb:cc:dd:ee:ff:00:11", "eui64")
	r := New(inv.srv.URL, "k", 0)
	before := failures(reasonInvalid)
	for _, ip := range []string{"192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "bogus"} {
		if mac, _ := r.Resolve(ip); mac != "" {
			t.Errorf("%s resolved to %q", ip, mac)
		}
	}
	if got := failures(reasonInvalid) - before; got != 6 {
		t.Errorf("invalid counted %v, want 6", got)
	}
}

func TestNameIsPrintableAndBounded(t *testing.T) {
	inv := newInventory(t, "k")
	inv.set("192.168.1.9", "aa:bb:cc:dd:ee:09", "  evil\x1b[31mname\n"+strings.Repeat("ł", 200))
	r := New(inv.srv.URL, "k", 0)
	_, name := r.Resolve("192.168.1.9")
	if strings.ContainsAny(name, "\x1b\n") {
		t.Errorf("control characters kept: %q", name)
	}
	if len(name) > maxNameBytes || !strings.HasPrefix(name, "evil[31mname") {
		t.Errorf("name = %q (%d bytes)", name, len(name))
	}
}

func TestCacheIsBounded(t *testing.T) {
	inv := newInventory(t, "k")
	r := New(inv.srv.URL, "k", time.Hour)
	for i := 0; i < maxCached+100; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)
		r.Resolve(ip)
	}
	if n := len(r.cache); n > maxCached {
		t.Errorf("cache holds %d entries, cap %d", n, maxCached)
	}
}
