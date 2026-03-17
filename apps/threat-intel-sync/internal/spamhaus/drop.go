package spamhaus

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

const (
	dropURL  = "https://www.spamhaus.org/drop/drop.txt"
	edropURL = "https://www.spamhaus.org/drop/edrop.txt"
)

// Client downloads and parses Spamhaus DROP/EDROP CIDR blocklists.
type Client struct {
	http *http.Client
}

// NewClient creates a Spamhaus list client.
func NewClient() *Client {
	return &Client{
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// FetchDROP downloads and parses the Spamhaus DROP list.
func (c *Client) FetchDROP(ctx context.Context) ([]ioc.Indicator, error) {
	return c.fetchList(ctx, dropURL, "spamhaus-drop", "drop")
}

// FetchEDROP downloads and parses the Spamhaus Extended DROP list.
func (c *Client) FetchEDROP(ctx context.Context) ([]ioc.Indicator, error) {
	return c.fetchList(ctx, edropURL, "spamhaus-edrop", "edrop")
}

// FetchAll downloads both DROP and EDROP lists and returns combined results.
// Partial results are returned if one list fails.
func (c *Client) FetchAll(ctx context.Context) ([]ioc.Indicator, error) {
	drop, errDrop := c.FetchDROP(ctx)
	edrop, errEdrop := c.FetchEDROP(ctx)

	all := append(drop, edrop...)

	if errDrop != nil {
		return all, fmt.Errorf("DROP: %w", errDrop)
	}
	if errEdrop != nil {
		return all, fmt.Errorf("EDROP: %w", errEdrop)
	}
	return all, nil
}

func (c *Client) fetchList(ctx context.Context, url, source, tag string) ([]ioc.Indicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("Spamhaus %d: %s", resp.StatusCode, body)
	}

	return parseDROPList(resp.Body, source, tag)
}

// parseDROPList parses lines of format "1.10.16.0/20 ; SBL256263".
func parseDROPList(r io.Reader, source, tag string) ([]ioc.Indicator, error) {
	var indicators []ioc.Indicator
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}

		parts := strings.SplitN(line, ";", 2)
		cidr := strings.TrimSpace(parts[0])
		if cidr == "" {
			continue
		}

		var ref string
		if len(parts) > 1 {
			sbl := strings.TrimSpace(parts[1])
			if sbl != "" {
				ref = "https://www.spamhaus.org/sbl/query/" + sbl
			}
		}

		indicators = append(indicators, ioc.Indicator{
			Type:       ioc.TypeIP,
			Value:      cidr,
			Source:     source,
			Threat:     "hijacked-network",
			Confidence: 95,
			Tags:       []string{tag, "spamhaus"},
			Reference:  ref,
		})
	}

	if err := scanner.Err(); err != nil {
		return indicators, fmt.Errorf("read list: %w", err)
	}
	return indicators, nil
}
