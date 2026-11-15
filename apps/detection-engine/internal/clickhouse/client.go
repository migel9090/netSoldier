// Package clickhouse is detection-engine's one client for the ClickHouse
// HTTP interface: sensor reads, feedback writes and feedback replay all go
// through it, so credentials and failure reporting are handled once.
//
// The service only reads and writes rows. Databases and tables belong to the
// migration Job (deploy/clickhouse/migrations); nothing here creates schema.
package clickhouse

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Header names ClickHouse reads credentials from. Headers rather than URL
// parameters keep the password out of access logs and error messages.
const (
	HeaderUser = "X-ClickHouse-User"
	HeaderKey  = "X-ClickHouse-Key"
)

var writeFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Name:      "clickhouse_write_failures_total",
	Help:      "Rows ClickHouse did not accept, by table.",
}, []string{"table"})

func init() {
	prometheus.MustRegister(writeFailures)
}

// Config is where and as whom the service talks to ClickHouse.
type Config struct {
	URL      string
	Database string
	User     string
	Password string
}

// ConfigFromEnv reads CLICKHOUSE_URL, CLICKHOUSE_DATABASE, CLICKHOUSE_USER and
// CLICKHOUSE_PASSWORD (the names every netSoldier client uses). ok is false
// when no URL is configured, i.e. the deployment has no ClickHouse.
func ConfigFromEnv(getenv func(string) string) (cfg Config, ok bool) {
	cfg = Config{
		URL:      strings.TrimSpace(getenv("CLICKHOUSE_URL")),
		Database: strings.TrimSpace(getenv("CLICKHOUSE_DATABASE")),
		User:     getenv("CLICKHOUSE_USER"),
		Password: getenv("CLICKHOUSE_PASSWORD"),
	}
	if cfg.Database == "" {
		cfg.Database = "netsoldier"
	}
	return cfg, cfg.URL != ""
}

// Client runs queries and inserts over the HTTP interface.
type Client struct {
	base     string // scheme://host[:port][/path], never with credentials
	database string
	user     string
	password string
	http     *http.Client
}

// New builds a client. Credentials embedded in the URL are moved into the
// headers: ClickHouse refuses a request that authenticates two ways at once,
// and a URL with a password in it ends up in logs.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("CLICKHOUSE_URL %q is not an absolute URL", redact(cfg.URL))
	}
	user, password := cfg.User, cfg.Password
	if u.User != nil {
		if user == "" {
			user = u.User.Username()
			password, _ = u.User.Password()
		}
		u.User = nil
	}
	u.RawQuery, u.Fragment = "", ""
	return &Client{
		base:     strings.TrimRight(u.String(), "/"),
		database: cfg.Database,
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// String describes the endpoint for logs, without credentials.
func (c *Client) String() string {
	return fmt.Sprintf("%s (database %s, user %s)", c.base, c.database, firstNonEmpty(c.user, "default"))
}

// Authenticated reports whether a user is configured. Without one ClickHouse
// treats the caller as `default`, which the deployment does not grant
// anything to from a pod address.
func (c *Client) Authenticated() bool { return c.user != "" }

// QueryJSONEachRow executes a SELECT that ends with FORMAT JSONEachRow and
// calls fn once per row.
func (c *Client) QueryJSONEachRow(ctx context.Context, query string, fn func(json.RawMessage) error) error {
	resp, err := c.do(ctx, url.Values{}, strings.NewReader(query))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		row := make(json.RawMessage, len(line))
		copy(row, line)
		if err := fn(row); err != nil {
			return err
		}
	}
	return scanner.Err()
}

var tableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Insert writes rows to table as JSONEachRow.
//
// Every failure is logged at Warn and counted here, for every caller, so a
// write that does not land is never just a debug line next to a counter that
// keeps rising. Unknown fields are an error rather than silently dropped: a
// column the migrations have not added yet must show up as a failed write,
// not as data that quietly vanished.
func (c *Client) Insert(ctx context.Context, table string, rows ...any) error {
	if err := c.insert(ctx, table, rows); err != nil {
		writeFailures.WithLabelValues(table).Add(float64(max(len(rows), 1)))
		slog.Warn("clickhouse write failed", "table", table, "rows", len(rows), "error", err)
		return err
	}
	return nil
}

func (c *Client) insert(ctx context.Context, table string, rows []any) error {
	if !tableName.MatchString(table) {
		return fmt.Errorf("invalid table name %q", table)
	}
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("encode row: %w", err)
		}
	}
	q := url.Values{}
	q.Set("query", "INSERT INTO "+table+" FORMAT JSONEachRow")
	q.Set("input_format_skip_unknown_fields", "0")
	resp, err := c.do(ctx, q, &body)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// do sends one request and turns a non-200 answer into an error carrying the
// start of ClickHouse's message (which never contains our credentials: they
// travel in headers).
func (c *Client) do(ctx context.Context, q url.Values, body io.Reader) (*http.Response, error) {
	q.Set("database", c.database)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+q.Encode(), body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if c.user != "" {
		req.Header.Set(HeaderUser, c.user)
		req.Header.Set(HeaderKey, c.password)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // the URL is ours and adds nothing
		}
		return nil, fmt.Errorf("clickhouse request: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return resp, nil
}

// redact strips the password from a URL for an error message.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparsable)"
	}
	return u.Redacted()
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
