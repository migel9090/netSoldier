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
// attempt — past the five-minute window — and the retry, made by the
// dispatcher from the outbox, must still verify.
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

	s := NewSender(srv.URL, "wh-secret", "tok")
	s.now = clock.now
	ob := newOutbox(t)
	enqueue(t, ob, testEvent(1, events.SeverityHigh))
	d := fastDispatcher(ob, s)
	runUntil(t, d, func() bool { return ob.Pending() == 0 })

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

	res, err := NewSender(srv.URL, "wh-secret", "tok").Send(context.Background(), []byte(`{"id":"DET-abc-2"}`))
	if res != ResultSuccess || err != nil {
		t.Fatalf("Send = %s, %v", res, err)
	}
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

	_, _ = NewSender(srv.URL, "", "").Send(context.Background(), []byte(`{}`))
	if sig != "" {
		t.Errorf("no secret configured should mean no signature header, got %q", sig)
	}
}

func TestSendClassifiesAnswers(t *testing.T) {
	for code, want := range map[int]string{
		http.StatusOK:                    ResultSuccess,
		http.StatusAccepted:              ResultSuccess,
		http.StatusUnauthorized:          ResultUnauthorized,
		http.StatusForbidden:             ResultUnauthorized,
		http.StatusBadRequest:            ResultRejected,
		http.StatusUnprocessableEntity:   ResultRejected,
		http.StatusRequestEntityTooLarge: ResultRejected,
		http.StatusNotFound:              ResultFailure, // wrong URL: fixable, keep the event
		http.StatusTooManyRequests:       ResultFailure,
		http.StatusServiceUnavailable:    ResultFailure,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
		}))
		got, _ := NewSender(srv.URL, "s", "t").Send(context.Background(), []byte(`{}`))
		srv.Close()
		if got != want {
			t.Errorf("status %d classified as %s, want %s", code, got, want)
		}
	}

	// Nothing listening: transient.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	if got, err := NewSender(url, "", "").Send(context.Background(), []byte(`{}`)); got != ResultFailure || err == nil {
		t.Errorf("unreachable receiver = %s, %v; want failure", got, err)
	}
}
