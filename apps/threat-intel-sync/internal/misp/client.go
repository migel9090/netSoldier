package misp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
)

// Defaults for FetchAllAttributes. Pagination used to have no page cap and
// no deadline: a MISP that always answered with a full page (one that
// ignores "page", or simply holds more than anyone expected) kept the loop
// accumulating attributes until the pod was OOM-killed.
const (
	DefaultPageSize = 5000
	DefaultMaxPages = 20
)

// ErrPageCap reports that pagination stopped at the page cap with more
// results still available. The attributes fetched so far are returned with
// it.
var ErrPageCap = errors.New("MISP page cap reached")

// Client talks to a MISP instance via its REST API.
type Client struct {
	baseURL  string
	apiKey   string
	http     *http.Client
	maxBytes int64
	maxPages int
	pageSize int
}

// NewClient creates a MISP REST client. The apiKey is sent as the
// Authorization header on every request.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL:  strings.TrimRight(baseURL, "/"),
		apiKey:   apiKey,
		http:     &http.Client{Timeout: 30 * time.Second},
		maxBytes: feedhttp.DefaultMaxBodyBytes,
		maxPages: DefaultMaxPages,
		pageSize: DefaultPageSize,
	}
}

// SetLimits overrides the per-response body cap, the page cap and the page
// size; zero or negative values keep the defaults.
func (c *Client) SetLimits(maxBytes int64, maxPages, pageSize int) {
	if maxBytes > 0 {
		c.maxBytes = maxBytes
	}
	if maxPages > 0 {
		c.maxPages = maxPages
	}
	if pageSize > 0 {
		c.pageSize = pageSize
	}
}

// FetchAttributes searches for attributes matching the given criteria.
// Returns the attributes from a single page; use FetchAllAttributes to
// auto-paginate.
func (c *Client) FetchAttributes(ctx context.Context, req SearchRequest) ([]Attribute, error) {
	body := searchBody{
		"returnFormat": "json",
	}
	if len(req.Types) > 0 {
		body["type"] = req.Types
	}
	if req.Published {
		body["published"] = 1
	}
	if req.Timestamp != "" {
		body["timestamp"] = req.Timestamp
	}
	if req.Limit > 0 {
		body["limit"] = req.Limit
	}
	if req.Page > 0 {
		body["page"] = req.Page
	}
	if req.ToIDs {
		body["to_ids"] = 1
	}
	if req.EnforceWarninglist {
		body["enforceWarninglist"] = true
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal search body: %w", err)
	}

	url := c.baseURL + "/attributes/restSearch"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Authorization", c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, feedhttp.StatusError("MISP", resp)
	}

	var result attributeResponse
	if err := json.NewDecoder(feedhttp.LimitBody(resp.Body, c.maxBytes)).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return result.Response.Attribute, nil
}

// FetchAllAttributes auto-paginates through all matching attributes.
// It stops when a page returns fewer results than the limit, when the
// context is done (the caller sets the overall deadline), or after the page
// cap — the last two return what was fetched so far together with an error.
func (c *Client) FetchAllAttributes(ctx context.Context, req SearchRequest) ([]Attribute, error) {
	if req.Limit <= 0 {
		req.Limit = c.pageSize
	}
	if req.Page <= 0 {
		req.Page = 1
	}

	var all []Attribute
	for pages := 0; ; pages++ {
		if pages == c.maxPages {
			return all, fmt.Errorf("%w (%d pages of %d)", ErrPageCap, c.maxPages, req.Limit)
		}
		if err := ctx.Err(); err != nil {
			return all, fmt.Errorf("page %d: %w", req.Page, err)
		}
		attrs, err := c.FetchAttributes(ctx, req)
		if err != nil {
			return all, fmt.Errorf("page %d: %w", req.Page, err)
		}
		if len(attrs) > req.Limit {
			// A server that ignores "limit" would otherwise multiply the
			// page cap by whatever it chooses to send.
			all = append(all, attrs[:req.Limit]...)
			return all, fmt.Errorf("page %d: MISP returned %d attributes for a page of %d",
				req.Page, len(attrs), req.Limit)
		}

		all = append(all, attrs...)
		slog.Debug("misp page fetched", "page", req.Page, "count", len(attrs), "total", len(all))

		if len(attrs) < req.Limit {
			break
		}
		req.Page++
	}
	return all, nil
}
