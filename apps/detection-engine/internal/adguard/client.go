package adguard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type QueryLogEntry struct {
	Question struct {
		// Name is the queried name, as AdGuard Home sends it (the A-label
		// spelling). A "host" key, which only this project's old test
		// doubles ever sent, is not read: an entry without "name" has no
		// name to match.
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"question"`
	Answer []struct {
		Value string `json:"value"`
		Type  string `json:"type"`
		TTL   int    `json:"ttl"`
	} `json:"answer"`
	Client string    `json:"client"`
	Time   time.Time `json:"time"`
	// Reason is AdGuard's filtering verdict (NotFilteredNotFound,
	// FilteredBlackList, Rewrite, ...).
	Reason string `json:"reason"`
	// Status is the response code (NOERROR, NXDOMAIN, ...); absent when
	// AdGuard kept no answer.
	Status string `json:"status"`
	// ElapsedMs is how long the answer took, in milliseconds, as AdGuard
	// sends it: a decimal string.
	ElapsedMs string `json:"elapsedMs"`
}

type queryLogResponse struct {
	Data []QueryLogEntry `json:"data"`
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

// QueryLogPage is one page of the querylog, newest first.
type QueryLogPage struct {
	Entries []QueryLogEntry
	// Oldest is the time of the oldest entry on the page, the older_than of
	// the next page. Zero when the page is empty.
	Oldest time.Time
}

// QueryLog returns up to limit entries older than olderThan (the newest ones
// when olderThan is zero), newest first. Paging with the previous page's
// Oldest walks back through the whole log, which is how AdGuard's own UI
// reads it.
func (c *Client) QueryLog(ctx context.Context, olderThan time.Time, limit int) (QueryLogPage, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	if !olderThan.IsZero() {
		q.Set("older_than", olderThan.UTC().Format(time.RFC3339Nano))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/control/querylog?"+q.Encode(), nil)
	if err != nil {
		return QueryLogPage{}, fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(c.user, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return QueryLogPage{}, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return QueryLogPage{}, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var result queryLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return QueryLogPage{}, fmt.Errorf("decode: %w", err)
	}

	// The next page starts below the oldest entry actually returned. The
	// response's own "oldest" is not used: it is missing from some releases
	// and stubs, and a value older than what was returned would skip entries.
	page := QueryLogPage{Entries: result.Data}
	for _, e := range result.Data {
		if page.Oldest.IsZero() || e.Time.Before(page.Oldest) {
			page.Oldest = e.Time
		}
	}
	return page, nil
}
