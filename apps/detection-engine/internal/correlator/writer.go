package correlator

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

// CHWriter writes enriched records to ClickHouse via its HTTP API.
type CHWriter struct {
	baseURL  string
	database string
	http     *http.Client
}

func NewCHWriter(baseURL, database string) *CHWriter {
	return &CHWriter{
		baseURL:  baseURL,
		database: database,
		http:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *CHWriter) Insert(ctx context.Context, table string, record any) error {
	body, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	body = append(body, '\n')

	query := fmt.Sprintf("INSERT INTO %s FORMAT JSONEachRow", table)
	u := fmt.Sprintf("%s/?database=%s&query=%s", w.baseURL, url.QueryEscape(w.database), url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, errBody)
	}
	return nil
}
