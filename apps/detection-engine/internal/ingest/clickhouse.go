package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// CHClient runs SELECT queries against the ClickHouse HTTP interface in
// JSONEachRow format (mirrors correlator.CHWriter, read side).
type CHClient struct {
	baseURL  string
	database string
	http     *http.Client
}

func NewCHClient(baseURL, database string) *CHClient {
	return &CHClient{
		baseURL:  baseURL,
		database: database,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// QueryJSONEachRow executes the query (which must end with FORMAT
// JSONEachRow) and invokes fn once per result row.
func (c *CHClient) QueryJSONEachRow(ctx context.Context, query string, fn func(json.RawMessage) error) error {
	u := fmt.Sprintf("%s/?database=%s", c.baseURL, url.QueryEscape(c.database))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte(query)))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("clickhouse %d: %s", resp.StatusCode, errBody)
	}

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
