package clickhouse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// Client writes records to ClickHouse via its HTTP interface.
type Client struct {
	baseURL  string
	database string
	http     *http.Client
}

// NewClient creates a ClickHouse HTTP client.
func NewClient(baseURL, database string) *Client {
	return &Client{
		baseURL:  baseURL,
		database: database,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

// Exec runs an arbitrary SQL statement (DDL, etc.).
func (c *Client) Exec(ctx context.Context, query string) error {
	u := fmt.Sprintf("%s/?database=%s", c.baseURL, url.QueryEscape(c.database))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewBufferString(query))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	return c.do(req)
}

// Insert writes one or more JSON records to the given table using
// JSONEachRow format. Each record is marshalled with encoding/json.
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

	query := fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", table)
	u := fmt.Sprintf("%s/?database=%s&query=%s", c.baseURL, url.QueryEscape(c.database), url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, &buf)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	return c.do(req)
}

func (c *Client) do(req *http.Request) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, body)
	}
	return nil
}

// InitSchema creates the devices and device_events tables if they don't exist.
func (c *Client) InitSchema(ctx context.Context) error {
	if err := c.Exec(ctx, "CREATE DATABASE IF NOT EXISTS "+c.database); err != nil {
		return fmt.Errorf("create database: %w", err)
	}

	for _, ddl := range schemaDDL {
		if err := c.Exec(ctx, ddl); err != nil {
			slog.Warn("clickhouse schema statement failed", "error", err)
		}
	}
	return nil
}

var schemaDDL = []string{
	`CREATE TABLE IF NOT EXISTS devices (
		mac          String,
		ip           String,
		hostname     String,
		fingerprint  String,
		vendor_class String,
		vendor       String,
		os           String,
		device_type  String,
		stable_id    String,
		labels       Array(String),
		first_seen   DateTime,
		last_seen    DateTime,
		updated_at   DateTime DEFAULT now()
	) ENGINE = ReplacingMergeTree(updated_at)
	ORDER BY mac`,

	`CREATE TABLE IF NOT EXISTS device_events (
		timestamp    DateTime,
		mac          String,
		ip           String,
		hostname     String,
		vendor       String,
		protocol     LowCardinality(String),
		event_type   LowCardinality(String)
	) ENGINE = MergeTree()
	ORDER BY (timestamp, mac)
	TTL timestamp + INTERVAL 30 DAY`,
}

// DeviceRecord is the ClickHouse row for the devices table.
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
}

// DeviceEvent is a timestamped observation for the device_events table.
type DeviceEvent struct {
	Timestamp string `json:"timestamp"`
	MAC       string `json:"mac"`
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	Vendor    string `json:"vendor"`
	Protocol  string `json:"protocol"`
	EventType string `json:"event_type"`
}
