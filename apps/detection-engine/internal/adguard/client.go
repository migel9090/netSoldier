package adguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type QueryLogEntry struct {
	Question struct {
		Host string `json:"host"`
		Type string `json:"type"`
	} `json:"question"`
	Client string    `json:"client"`
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
}

type queryLogResponse struct {
	Data   []QueryLogEntry `json:"data"`
	Oldest string          `json:"oldest"`
}

type Client struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
}

func NewClient(baseURL, user, password string) *Client {
	return &Client{
		baseURL:  baseURL,
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) QueryLog(ctx context.Context, limit int) ([]QueryLogEntry, error) {
	url := fmt.Sprintf("%s/control/querylog?limit=%d", c.baseURL, limit)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.user, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result queryLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return result.Data, nil
}
