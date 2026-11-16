// Package peer is the agent's side of both channels: one authenticated
// outbound POST per round, a bounded response that carries commands, and a
// record of how the peer has been answering. The agent never accepts a
// connection; commands only ever arrive as answers to its own requests.
package peer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

// ErrTooLarge is returned when a request body would exceed proto.MaxBody.
var ErrTooLarge = errors.New("request body exceeds 1 MiB")

// Health is how a peer has been answering.
type Health struct {
	LastOK    time.Time `json:"last_ok,omitzero"`
	Failures  int       `json:"consecutive_failures"`
	LastError string    `json:"last_error,omitempty"`
}

// Client posts to one endpoint with one bearer token.
type Client struct {
	name, url, token string
	http             *http.Client

	mu         sync.Mutex
	health     Health
	lastLog    time.Time
	suppressed int
}

// New returns a client for url. Proxies from the environment are ignored
// (both peers are cluster or host-local services) and redirects are not
// followed, so the token is only ever sent to the configured endpoint.
func New(name, url, token string, timeout time.Duration) *Client {
	return &Client{name: name, url: url, token: token, http: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			MaxIdleConns:          2,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Post sends body and returns the HTTP status and, on 200, the commands in
// the response. A 200 whose body does not decode still returns 200 with the
// error, because the request itself was accepted.
func (c *Client) Post(ctx context.Context, body any) (int, []proto.Command, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	if len(buf) > proto.MaxBody {
		return 0, nil, ErrTooLarge
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(buf))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "netagent")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, proto.MaxResponse+1))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, proto.Clip(string(bytes.TrimSpace(data)), 200))
	}
	if len(data) > proto.MaxResponse {
		return resp.StatusCode, nil, fmt.Errorf("response exceeds %d bytes; commands ignored", proto.MaxResponse)
	}
	var out proto.Commands
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &out); err != nil {
			return resp.StatusCode, nil, fmt.Errorf("response does not decode; commands ignored: %w", err)
		}
	}
	return resp.StatusCode, out.Commands, nil
}

// Succeeded records a delivered request.
func (c *Client) Succeeded(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.health.Failures > 0 {
		slog.Info("peer reachable again", "peer", c.name, "after_failures", c.health.Failures)
	}
	c.health = Health{LastOK: now}
}

// Failed records an undelivered request and logs it, at most every 30 s.
func (c *Client) Failed(now time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.Failures++
	c.health.LastError = proto.Clip(err.Error(), proto.MaxErrorLen)
	if c.health.Failures == 1 || now.Sub(c.lastLog) >= 30*time.Second {
		slog.Warn("request to peer failed", "peer", c.name, "error", err,
			"consecutive_failures", c.health.Failures, "suppressed_since_last", c.suppressed)
		c.lastLog, c.suppressed = now, 0
		return
	}
	c.suppressed++
}

// Health returns a snapshot.
func (c *Client) Health() Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

// Backoff doubles from Initial to Max with ±20 % jitter, so a fleet of
// agents does not retry in lockstep after a restart of the peer.
type Backoff struct {
	Initial, Max time.Duration
	cur          time.Duration
}

// Next returns the next wait.
func (b *Backoff) Next() time.Duration {
	if b.cur == 0 {
		b.cur = b.Initial
	} else {
		b.cur = min(2*b.cur, b.Max)
	}
	return time.Duration(float64(b.cur) * (0.8 + 0.4*rand.Float64()))
}

// Reset starts over at Initial.
func (b *Backoff) Reset() { b.cur = 0 }
