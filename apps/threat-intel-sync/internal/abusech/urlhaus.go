package abusech

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// URLhausMaxLimit is the largest "limit" the recent-URLs endpoint accepts,
// per https://urlhaus-api.abuse.ch/.
const URLhausMaxLimit = 1000

// URLhausClient fetches malicious URLs from URLhaus (abuse.ch).
type URLhausClient struct {
	apiURL string
	http   *http.Client
	opts   options
}

func NewURLhausClient(opts ...Option) *URLhausClient {
	return &URLhausClient{
		apiURL: URLhausURL,
		http:   feedhttp.NewClient("urlhaus", 60*time.Second),
		opts:   buildOptions(opts),
	}
}

// Fetch retrieves the most recent malicious URLs (up to limit).
//
// The documented call is an HTTP GET with the limit as a path segment
// (/v1/urls/recent/limit/<n>/); the client used to POST a form, which the
// API answers with query_status "http_get_expected".
func (c *URLhausClient) Fetch(ctx context.Context, limit int) ([]ioc.Indicator, error) {
	if limit <= 0 || limit > URLhausMaxLimit {
		limit = URLhausMaxLimit
	}

	target := strings.TrimRight(c.apiURL, "/") + "/limit/" + strconv.Itoa(limit) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	c.opts.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, feedhttp.StatusError("URLhaus", resp)
	}

	var indicators []ioc.Indicator
	status, rows, malformed, err := decodeEnvelope(feedhttp.LimitBody(resp.Body, c.opts.maxBytes), "urls",
		func(dec *json.Decoder) error {
			var e urlhausEntry
			if err := dec.Decode(&e); err != nil {
				return err
			}
			added := parseAbusechTime(e.DateAdded)
			indicators = append(indicators, ioc.Indicator{
				Type:      ioc.TypeURL,
				Value:     e.URL,
				Source:    "urlhaus",
				Threat:    e.Threat,
				FirstSeen: added,
				Tags:      e.Tags,
				Reference: e.Reference,
			})
			if host := extractHost(e.URL); host != "" && !isIPAddress(host) {
				indicators = append(indicators, ioc.Indicator{
					Type:      ioc.TypeDomain,
					Value:     host,
					Source:    "urlhaus",
					Threat:    e.Threat,
					FirstSeen: added,
					Tags:      e.Tags,
				})
			}
			return nil
		})
	if err != nil {
		return indicators, fmt.Errorf("decode after %d rows: %w", rows, err)
	}
	switch status {
	case "ok":
	case "no_results", "no_result":
		return nil, nil
	default:
		return indicators, fmt.Errorf("URLhaus query_status: %q", status)
	}
	if malformed > 0 && len(indicators) == 0 {
		return nil, fmt.Errorf("URLhaus: all %d rows malformed", malformed)
	}
	if malformed > 0 {
		slog.Warn("urlhaus: skipped malformed rows", "malformed", malformed, "rows", rows)
	}
	return indicators, nil
}

func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	return strings.ToLower(host)
}

func isIPAddress(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// urlhausEntry mirrors one recent-URLs row as documented at
// https://urlhaus-api.abuse.ch/ ("date_added", "urlhaus_reference"; the
// client used to read "dateadded" and "urlhaus_link", which this endpoint
// does not send). Only the fields used are declared.
type urlhausEntry struct {
	DateAdded string   `json:"date_added"`
	URL       string   `json:"url"`
	Threat    string   `json:"threat"`
	Tags      []string `json:"tags"`
	Reference string   `json:"urlhaus_reference"`
}
