package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// fakeClock advances by step on every read, so each signing attempt sees a
// later time than the one before.
type fakeClock struct {
	mu   sync.Mutex
	t    time.Time
	step time.Duration
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(c.step)
	return c.t
}

func (c *fakeClock) peek() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

type delivery struct {
	sig  string
	body []byte
	err  error
}

// TestRetryIsResignedWithFreshTimestamp: the receiver rejects a signature
// older than its tolerance, so a signature computed once and reused would
// turn a slow retry into a rejection. Here the clock moves six minutes per
// attempt — past the five-minute window — and the retry must still verify.
func TestRetryIsResignedWithFreshTimestamp(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0), step: 6 * time.Minute}
	verifier := &events.SignatureVerifier{Secret: "wh-secret", Now: clock.peek}

	var mu sync.Mutex
	var got []delivery
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		sig := r.Header.Get(events.SignatureHeader)
		mu.Lock()
		got = append(got, delivery{sig: sig, body: body, err: verifier.Verify(sig, body)})
		first := len(got) == 1
		mu.Unlock()
		if first {
			w.WriteHeader(http.StatusServiceUnavailable) // killswitch restarting
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	s := NewSender(srv.URL, "wh-secret", "tok", 3)
	s.now = clock.now
	s.deliver(context.Background(), map[string]any{"id": "DET-abc-1"})

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("expected one failed attempt and one retry, got %d", len(got))
	}
	if got[0].sig == got[1].sig {
		t.Fatal("the retry reused the first attempt's signature")
	}
	if got[1].err != nil {
		t.Fatalf("the retry must carry a fresh, verifiable signature: %v", got[1].err)
	}
	if string(got[0].body) != string(got[1].body) {
		t.Error("the body (and the event id the receiver deduplicates on) must not change between attempts")
	}
}

func TestSignedDeliveryVerifies(t *testing.T) {
	var sig, auth string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		sig = r.Header.Get(events.SignatureHeader)
		auth = r.Header.Get("Authorization")
	}))
	t.Cleanup(srv.Close)

	NewSender(srv.URL, "wh-secret", "tok", 0).deliver(context.Background(), map[string]string{"id": "DET-abc-2"})

	if err := events.VerifyPayload("wh-secret", sig, body); err != nil {
		t.Fatalf("delivery must verify under signature v2: %v", err)
	}
	if auth != "Bearer tok" {
		t.Errorf("Authorization = %q", auth)
	}
}

func TestUnsignedWithoutSecret(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get(events.SignatureHeader)
	}))
	t.Cleanup(srv.Close)

	NewSender(srv.URL, "", "", 0).deliver(context.Background(), map[string]string{})
	if sig != "" {
		t.Errorf("no secret configured should mean no signature header, got %q", sig)
	}
}

// TestClientErrorIsNotRetried: a 4xx (an event the receiver refuses as
// invalid, say) cannot be fixed by sending it again.
func TestClientErrorIsNotRetried(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	t.Cleanup(srv.Close)

	NewSender(srv.URL, "s", "t", 3).deliver(context.Background(), map[string]string{})
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Errorf("a 422 was attempted %d times, want 1", calls)
	}
}
