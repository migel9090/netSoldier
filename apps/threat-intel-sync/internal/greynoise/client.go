package greynoise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to the GreyNoise Community API for IP reputation lookups.
// The Community tier is rate-limited; callers should pace requests.
type Client struct {
	apiURL string
	apiKey string
	http   *http.Client
}

// NewClient creates a GreyNoise Community API client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiURL: "https://api.greynoise.io/v3/community/",
		apiKey: apiKey,
		http:   &http.Client{Timeout: 15 * time.Second},
	}
}

// IPReputation is the response from a GreyNoise Community IP lookup.
type IPReputation struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"` // "malicious", "benign", "unknown"
	Name           string `json:"name"`
	Link           string `json:"link"`
	LastSeen       string `json:"last_seen"`
	Message        string `json:"message"`
}

// IsMalicious returns true if the IP is classified as malicious.
func (r *IPReputation) IsMalicious() bool {
	return r.Classification == "malicious"
}

// IsBenign returns true if the IP is classified as benign or RIOT.
func (r *IPReputation) IsBenign() bool {
	return r.Classification == "benign" || r.Riot
}

// Lookup checks the reputation of a single IP address.
// Returns classification "unknown" for IPs not observed by GreyNoise.
func (c *Client) Lookup(ctx context.Context, ip string) (*IPReputation, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiURL+ip, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &IPReputation{
			IP:             ip,
			Classification: "unknown",
			Message:        "not observed",
		}, nil
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("GreyNoise rate limit exceeded")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GreyNoise %d: %s", resp.StatusCode, body)
	}

	var rep IPReputation
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return &rep, nil
}

// EnrichConfidence adjusts an IoC confidence score based on GreyNoise data.
// Malicious: +10 (cap 100). Benign/RIOT: halved. Unknown: unchanged.
func EnrichConfidence(current int, rep *IPReputation) int {
	if rep == nil {
		return current
	}
	switch {
	case rep.IsMalicious():
		c := current + 10
		if c > 100 {
			return 100
		}
		return c
	case rep.IsBenign():
		return current / 2
	default:
		return current
	}
}
