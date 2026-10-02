package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// CHAuditWriter writes audit entries to ClickHouse via the HTTP API.
//
// Credentials are sent via the X-ClickHouse-User/Key headers rather than in
// the URL, so they do not end up in ClickHouse's own query_log or in any
// proxy's access log. The audit log is the accountability record for every
// enforcement decision, so the account writing it must be authenticated and
// should only hold INSERT on this table.
type CHAuditWriter struct {
	baseURL  string
	database string
	user     string
	password string
	http     *http.Client
}

func NewCHAuditWriter(baseURL, database, user, password string) *CHAuditWriter {
	return &CHAuditWriter{
		baseURL:  baseURL,
		database: database,
		user:     user,
		password: password,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *CHAuditWriter) Write(ctx context.Context, entry AuditEntry) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	body = append(body, '\n')

	query := "INSERT INTO audit_log FORMAT JSONEachRow"
	u := fmt.Sprintf("%s/?database=%s&query=%s", w.baseURL, url.QueryEscape(w.database), url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if w.user != "" {
		req.Header.Set("X-ClickHouse-User", w.user)
		req.Header.Set("X-ClickHouse-Key", w.password)
	}

	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, errBody)
	}
	return nil
}

// NopAuditWriter discards audit entries (used when ClickHouse is not configured).
type NopAuditWriter struct{}

func (NopAuditWriter) Write(_ context.Context, _ AuditEntry) error { return nil }
