package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

var deliveriesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Subsystem: "webhook",
	Name:      "deliveries_total",
	Help:      "Total webhook delivery attempts by result.",
}, []string{"result"})

func init() {
	prometheus.MustRegister(deliveriesTotal)
}

type Sender struct {
	url     string
	secret  string
	token   string
	retries int
	http    *http.Client
	ch      chan any
}

// NewSender builds a webhook sender.
//
// secret signs the body with HMAC-SHA256 (events.SignatureHeader) so the
// receiver can prove the payload was not altered in transit. token is the
// bearer credential the receiver authenticates the CALLER with — the
// killswitch's authMiddleware requires it on every POST, so omitting it is
// how enforcement silently stopped working the moment auth was enabled.
// They answer different questions ("is this really from the engine?" vs.
// "is this request allowed?") and are both needed.
func NewSender(url, secret, token string, retries int) *Sender {
	return &Sender{
		url:     url,
		secret:  secret,
		token:   token,
		retries: retries,
		http:    &http.Client{Timeout: 10 * time.Second},
		ch:      make(chan any, 64),
	}
}

// Send enqueues a payload for asynchronous delivery. Non-blocking; drops
// the payload if the internal queue is full.
func (s *Sender) Send(payload any) {
	select {
	case s.ch <- payload:
	default:
		deliveriesTotal.WithLabelValues("dropped").Inc()
		slog.Warn("webhook queue full, alert dropped")
	}
}

func (s *Sender) Run(ctx context.Context) {
	slog.Info("webhook sender started", "url", s.url, "retries", s.retries)
	for {
		select {
		case payload := <-s.ch:
			s.deliver(ctx, payload)
		case <-ctx.Done():
			return
		}
	}
}

func (s *Sender) deliver(ctx context.Context, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		slog.Error("webhook marshal failed", "error", err)
		deliveriesTotal.WithLabelValues("failure").Inc()
		return
	}

	var lastErr error
	for attempt := 0; attempt <= s.retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * time.Second
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		if s.secret != "" {
			req.Header.Set(events.SignatureHeader, events.SignPayload(s.secret, body))
		}
		if s.token != "" {
			req.Header.Set("Authorization", "Bearer "+s.token)
		}

		resp, err := s.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			resp.Body.Close()
			deliveriesTotal.WithLabelValues("success").Inc()
			return
		}

		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		lastErr = fmt.Errorf("status %d: %s", resp.StatusCode, string(errBody))

		// Rejected credentials are a deployment bug, not a transient fault.
		// Retrying cannot fix it and a generic "delivery failed" buries it,
		// so give it its own metric label and an unambiguous message: an
		// unauthenticated sender means NOTHING gets enforced.
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			deliveriesTotal.WithLabelValues("unauthorized").Inc()
			slog.Error("webhook rejected our credentials — enforcement is NOT running; "+
				"check WEBHOOK_TOKEN against the receiver's API key",
				"url", s.url, "status", resp.StatusCode, "has_token", s.token != "")
			return
		}

		// 4xx = client error, retrying won't help
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			break
		}
	}

	deliveriesTotal.WithLabelValues("failure").Inc()
	slog.Error("webhook delivery failed", "url", s.url, "error", lastErr)
}
