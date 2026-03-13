package misp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Client talks to a MISP instance via its REST API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewClient creates a MISP REST client. The apiKey is sent as the
// Authorization header on every request.
func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
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
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("MISP %d: %s", resp.StatusCode, string(errBody))
	}

	var result attributeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}

	return result.Response.Attribute, nil
}

// FetchAllAttributes auto-paginates through all matching attributes.
// It stops when a page returns fewer results than the limit.
func (c *Client) FetchAllAttributes(ctx context.Context, req SearchRequest) ([]Attribute, error) {
	if req.Limit <= 0 {
		req.Limit = 10000
	}
	if req.Page <= 0 {
		req.Page = 1
	}

	var all []Attribute
	for {
		attrs, err := c.FetchAttributes(ctx, req)
		if err != nil {
			return all, fmt.Errorf("page %d: %w", req.Page, err)
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
