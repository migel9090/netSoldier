package webhook

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

// Delivery attempt results, the label values of deliveriesTotal.
const (
	ResultSuccess      = "success"      // acknowledged (2xx)
	ResultFailure      = "failure"      // transient: will be retried
	ResultUnauthorized = "unauthorized" // credentials refused: retried, and loudly reported
	ResultRejected     = "rejected"     // the receiver refuses this event for good
)

var deliveriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Subsystem: "webhook",
	Name:      "deliveries_total",
	Help:      "Webhook delivery attempts by result.",
}, []string{"result"})

func init() {
	prometheus.MustRegister(deliveriesTotal)
	for _, r := range []string{ResultSuccess, ResultFailure, ResultUnauthorized, ResultRejected} {
		deliveriesTotal.WithLabelValues(r)
	}
}

// Sender makes one signed, authenticated delivery attempt.
type Sender struct {
	url    string
	secret string
	token  string
	http   *http.Client
	// now is the signing clock; tests replace it.
	now func() time.Time
}

// NewSender builds a webhook sender.
//
// secret signs each request with HMAC-SHA256 over a timestamp and the body
// (events.SignatureHeader) so the receiver can prove the payload was not
// altered in transit and is not a replay of an old capture. token is the
// bearer credential the receiver authenticates the CALLER with — the
// killswitch's authMiddleware requires it on every POST, so omitting it is
// how enforcement silently stopped working the moment auth was enabled.
// They answer different questions ("is this really from the engine, now?"
// vs. "is this request allowed?") and are both needed.
func NewSender(url, secret, token string) *Sender {
	return &Sender{
		url:    url,
		secret: secret,
		token:  token,
		http:   &http.Client{Timeout: 10 * time.Second},
		now:    time.Now,
	}
}

// URL is the receiver's address.
func (s *Sender) URL() string { return s.url }

// Send makes one attempt to deliver body and classifies the answer.
//
// Signed per attempt, at send time: the receiver rejects a signature older
// than its tolerance, so one computed when the event was queued would turn a
// slow retry into a rejection. The body — and with it the event id the
// receiver deduplicates on — is the same bytes on every attempt.
func (s *Sender) Send(ctx context.Context, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return ResultRejected, err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.secret != "" {
		req.Header.Set(events.SignatureHeader, events.SignPayloadAt(s.secret, s.now(), body))
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return ResultFailure, err
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	resp.Body.Close()

	switch code := resp.StatusCode; {
	case code >= 200 && code < 300:
		return ResultSuccess, nil
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		// A deployment bug, not a property of the event: once the token is
		// fixed the same event goes through, so it is kept and retried.
		return ResultUnauthorized, fmt.Errorf("status %d: %s", code, bytes.TrimSpace(msg))
	case code == http.StatusBadRequest || code == http.StatusRequestEntityTooLarge ||
		code == http.StatusUnsupportedMediaType || code == http.StatusUnprocessableEntity:
		// The receiver read the event and refuses it; sending the same bytes
		// again cannot change that.
		return ResultRejected, fmt.Errorf("status %d: %s", code, bytes.TrimSpace(msg))
	default:
		return ResultFailure, fmt.Errorf("status %d: %s", code, bytes.TrimSpace(msg))
	}
}
