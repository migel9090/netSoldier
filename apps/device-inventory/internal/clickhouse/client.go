// Package clickhouse is a minimal client for ClickHouse's HTTP interface,
// following the platform conventions (contract v2, section 6): credentials
// on every call in the X-ClickHouse-User/Key headers, no schema management
// (the migration Job owns the schema), and readers that accept the quoted
// form ClickHouse uses for 64-bit integers in JSON.
package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// maxResponseBytes bounds a query result. The service's queries are LIMITed
// to a few hundred rows; anything this large is a fault, not data.
const maxResponseBytes = 16 << 20

// Timestamp layouts. device_events.timestamp is DateTime64(3) after
// migration 023; the devices table keeps DateTime columns.
const (
	MillisLayout  = "2006-01-02 15:04:05.000"
	SecondsLayout = "2006-01-02 15:04:05"
)

// Client writes records to ClickHouse via its HTTP interface.
type Client struct {
	baseURL  string
	database string
	user     string
	password string
	http     *http.Client
}

// NewClient creates a ClickHouse HTTP client. Credentials travel in the
// X-ClickHouse-User/Key headers rather than the URL so they do not land in
// ClickHouse's own query_log or any proxy's access log. An empty user means
// ClickHouse's "default" user, which is sent explicitly.
func NewClient(baseURL, database, user, password string) *Client {
	if user == "" {
		user = "default"
	}
	return &Client{
		baseURL:  baseURL,
		database: database,
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) newRequest(ctx context.Context, method string, params url.Values, body io.Reader) (*http.Request, error) {
	params.Set("database", c.database)
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+"/?"+params.Encode(), body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("X-ClickHouse-User", c.user)
	req.Header.Set("X-ClickHouse-Key", c.password)
	return req, nil
}

// Insert writes one or more JSON records to the given table using
// JSONEachRow format. Each record is marshalled with encoding/json. The
// table name must be a constant, never input.
func (c *Client) Insert(ctx context.Context, table string, records ...any) error {
	if len(records) == 0 {
		return nil
	}

	var buf bytes.Buffer
	for _, rec := range records {
		b, err := json.Marshal(rec)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}

	params := url.Values{"query": {fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", table)}}
	req, err := c.newRequest(ctx, http.MethodPost, params, &buf)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Query runs a SELECT and decodes the JSON result into dest (a pointer to
// a slice). The query must NOT contain a FORMAT clause. Use {name:Type}
// placeholders with params for safe parameterized queries.
func (c *Client) Query(ctx context.Context, query string, dest any, params ...map[string]string) error {
	v := url.Values{"query": {query + " FORMAT JSON"}}
	if len(params) > 0 {
		for k, val := range params[0] {
			v.Set("param_"+k, val)
		}
	}
	req, err := c.newRequest(ctx, http.MethodGet, v, nil)
	if err != nil {
		return err
	}
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&envelope); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if len(envelope.Data) == 0 {
		return fmt.Errorf("decode: response has no data field")
	}
	return json.Unmarshal(envelope.Data, dest)
}

// CheckSchema verifies that the tables this service writes exist. It is a
// readiness check only: creating them is the migration Job's job.
func (c *Client) CheckSchema(ctx context.Context, tables ...string) error {
	var rows []struct {
		Name string `json:"name"`
	}
	if err := c.Query(ctx, `SELECT name FROM system.tables WHERE database = {db:String}`, &rows,
		map[string]string{"db": c.database}); err != nil {
		return err
	}
	have := make(map[string]bool, len(rows))
	for _, r := range rows {
		have[r.Name] = true
	}
	for _, t := range tables {
		if !have[t] {
			return fmt.Errorf("table %s.%s does not exist (has the migration Job run?)", c.database, t)
		}
	}
	return nil
}

func (c *Client) do(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return resp, nil
}

// UInt64 decodes a ClickHouse 64-bit integer whether it arrives quoted (the
// JSON formats' default, output_format_json_quote_64bit_integers=1) or bare,
// and encodes as a plain JSON number.
type UInt64 uint64

// UnmarshalJSON accepts 123 and "123".
func (u *UInt64) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*u = 0
		return nil
	}
	if len(b) >= 2 && b[0] == '"' && b[len(b)-1] == '"' {
		b = b[1 : len(b)-1]
	}
	v, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("clickhouse UInt64: %w", err)
	}
	*u = UInt64(v)
	return nil
}

// DeviceRecord is a snapshot row for the devices table
// (ReplacingMergeTree(updated_at), one current row per MAC).
type DeviceRecord struct {
	MAC         string   `json:"mac"`
	IP          string   `json:"ip"`
	Hostname    string   `json:"hostname"`
	Fingerprint string   `json:"fingerprint"`
	VendorClass string   `json:"vendor_class"`
	Vendor      string   `json:"vendor"`
	OS          string   `json:"os"`
	DeviceType  string   `json:"device_type"`
	StableID    string   `json:"stable_id"`
	Labels      []string `json:"labels"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	UpdatedAt   string   `json:"updated_at"`
}

// DeviceEvent is a timestamped observation for the device_events table.
// EventType is one of new, seen, rebind, conflict.
type DeviceEvent struct {
	Timestamp string `json:"timestamp"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	Vendor    string `json:"vendor"`
	Protocol  string `json:"protocol"`
	EventType string `json:"event_type"`
}
