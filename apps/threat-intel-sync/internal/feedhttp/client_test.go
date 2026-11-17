package feedhttp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// TestRedirectToAnotherHostIsRefused: a feed answering with a redirect to
// another origin is a failed fetch. Go's default client would have followed
// it and carried the Auth-Key header along.
func TestRedirectToAnotherHostIsRefused(t *testing.T) {
	var leaked atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Auth-Key") != "" {
			leaked.Add(1)
		}
		w.Write([]byte("0.0.0.0/1 ; SBL0\n"))
	}))
	defer other.Close()
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/drop.txt", http.StatusFound)
	}))
	defer feed.Close()

	before := counter("redirect-test")
	req, _ := http.NewRequest(http.MethodGet, feed.URL+"/drop.txt", nil)
	req.Header.Set("Auth-Key", "secret")
	resp, err := NewClient("redirect-test", 5*time.Second).Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a redirect to another origin was followed")
	}
	if !errors.Is(err, ErrRedirectRefused) {
		t.Errorf("error = %v, want ErrRedirectRefused", err)
	}
	if leaked.Load() != 0 {
		t.Error("the Auth-Key reached the other host")
	}
	if got := counter("redirect-test") - before; got != 1 {
		t.Errorf("feed_redirects_refused_total rose by %v, want 1", got)
	}
}

func TestSameOriginRedirectIsFollowed(t *testing.T) {
	hops := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/old":
			http.Redirect(w, r, "/new", http.StatusMovedPermanently)
		case "/loop":
			hops++
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	c := NewClient("same-origin-test", 5*time.Second)
	resp, err := c.Get(srv.URL + "/old")
	if err != nil {
		t.Fatalf("a same-origin redirect was refused: %v", err)
	}
	resp.Body.Close()
	if _, err := c.Get(srv.URL + "/loop"); !errors.Is(err, ErrRedirectRefused) || hops > MaxRedirects+1 {
		t.Errorf("redirect loop: %v after %d hops", err, hops)
	}
}

func TestOrigin(t *testing.T) {
	for _, c := range []struct {
		a, b string
		same bool
	}{
		{"https://Feed.example/a", "https://feed.example:443/b", true},
		{"https://feed.example/a", "http://feed.example/a", false}, // downgrade
		{"https://feed.example/a", "https://feed.example:8443/a", false},
		{"https://feed.example/a", "https://evil.example/a", false},
		{"https://feed.example/a", "https://feed.example.evil.example/a", false},
		{"http://[2001:db8::1]/a", "http://[2001:db8::1]:80/b", true},
	} {
		ua, _ := url.Parse(c.a)
		ub, _ := url.Parse(c.b)
		if got := origin(ua) == origin(ub); got != c.same {
			t.Errorf("origin(%s) == origin(%s): %v, want %v", c.a, c.b, got, c.same)
		}
	}
}

func TestCheckPinned(t *testing.T) {
	if err := CheckPinned("https://www.spamhaus.org/drop/drop.txt", "www.spamhaus.org"); err != nil {
		t.Error(err)
	}
	for _, u := range []string{
		"http://www.spamhaus.org/drop/drop.txt",
		"https://www.spamhaus.org:8443/drop/drop.txt",
		"https://user@www.spamhaus.org/drop/drop.txt",
		"https://spamhaus.org/drop/drop.txt",
		"https://www.spamhaus.org.evil.example/drop/drop.txt",
	} {
		if err := CheckPinned(u, "www.spamhaus.org"); err == nil {
			t.Errorf("CheckPinned(%q) accepted it", u)
		}
	}
}

// counter reads threat_intel_feed_redirects_refused_total{source} from the
// default registry (prometheus/testutil would add a module dependency for
// tests only).
func counter(source string) float64 {
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != "threat_intel_feed_redirects_refused_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "source" && lp.GetValue() == source {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}
