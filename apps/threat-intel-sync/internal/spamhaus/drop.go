package spamhaus

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// DROPURL is the DROP list in text form, on the pinned host Host (see
// feedhttp.NewClient: no redirect may leave it). EDROP is no longer fetched:
// Spamhaus merged it into DROP on 2024-04-10
// (https://www.spamhaus.org/blocklists/do-not-route-or-peer/), and fetching
// the retired URL made every cycle report this source as failed.
const (
	Host    = "www.spamhaus.org"
	DROPURL = "https://" + Host + "/drop/drop.txt"
)

// MinFetchInterval is Spamhaus' own rule: "Automated downloads must be at
// least one hour apart". Retries after a failure respect it as well.
const MinFetchInterval = time.Hour

// Client downloads and parses the Spamhaus DROP CIDR blocklist.
type Client struct {
	http     *http.Client
	dropURL  string
	maxBytes int64
}

// NewClient creates a Spamhaus list client. maxBytes caps the response
// body (0 = feedhttp.DefaultMaxBodyBytes).
func NewClient(maxBytes int64) *Client {
	return &Client{
		http:     feedhttp.NewClient("spamhaus", 30*time.Second),
		dropURL:  DROPURL,
		maxBytes: maxBytes,
	}
}

// FetchDROP downloads and parses the Spamhaus DROP list.
func (c *Client) FetchDROP(ctx context.Context) ([]ioc.Indicator, error) {
	return c.fetchList(ctx, c.dropURL, "spamhaus-drop", "drop")
}

// FetchAll returns everything this client fetches; since the EDROP merge
// that is the DROP list alone.
func (c *Client) FetchAll(ctx context.Context) ([]ioc.Indicator, error) {
	return c.FetchDROP(ctx)
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
		return nil, feedhttp.StatusError("Spamhaus", resp)
	}

	return parseDROPList(feedhttp.LimitBody(resp.Body, c.maxBytes), source, tag)
}

// parseDROPList parses lines of format "1.10.16.0/20 ; SBL256263". On a
// read error (including the body cap) the complete lines read so far are
// returned together with the error; a truncated last line never is.
func parseDROPList(r io.Reader, source, tag string) ([]ioc.Indicator, error) {
	var indicators []ioc.Indicator
	err := feedhttp.Lines(r, func(line string) error {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			return nil
		}

		parts := strings.SplitN(line, ";", 2)
		cidr := strings.TrimSpace(parts[0])
		if cidr == "" {
			return nil
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
		return nil
	})
	if err != nil {
		return indicators, fmt.Errorf("read list: %w", err)
	}
	return indicators, nil
}
