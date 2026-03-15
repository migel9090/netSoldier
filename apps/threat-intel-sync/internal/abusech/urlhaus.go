package abusech

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// URLhausClient fetches malicious URLs from URLhaus (abuse.ch).
type URLhausClient struct {
	apiURL string
	http   *http.Client
}

func NewURLhausClient() *URLhausClient {
	return &URLhausClient{
		apiURL: "https://urlhaus-api.abuse.ch/v1/urls/recent/",
		http:   &http.Client{Timeout: 60 * time.Second},
	}
}

// Fetch retrieves the most recent malicious URLs (up to limit).
func (c *URLhausClient) Fetch(ctx context.Context, limit int) ([]ioc.Indicator, error) {
	if limit <= 0 {
		limit = 1000
	}

	form := url.Values{"limit": {strconv.Itoa(limit)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("URLhaus %d: %s", resp.StatusCode, body)
	}

	var result urlhausResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if result.QueryStatus != "ok" {
		return nil, fmt.Errorf("URLhaus query_status: %s", result.QueryStatus)
	}

	indicators := make([]ioc.Indicator, 0, len(result.URLs))
	for _, e := range result.URLs {
		indicators = append(indicators, ioc.Indicator{
			Type:      ioc.TypeURL,
			Value:     e.URL,
			Source:    "urlhaus",
			Threat:    e.Threat,
			FirstSeen: parseAbusechTime(e.DateAdded),
			Tags:      e.Tags,
			Reference: e.URLhausLink,
		})

		if host := extractHost(e.URL); host != "" && !isIPAddress(host) {
			indicators = append(indicators, ioc.Indicator{
				Type:      ioc.TypeDomain,
				Value:     host,
				Source:    "urlhaus",
				Threat:    e.Threat,
				FirstSeen: parseAbusechTime(e.DateAdded),
				Tags:      e.Tags,
			})
		}
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
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return len(s) > 0
}

type urlhausResponse struct {
	QueryStatus string          `json:"query_status"`
	URLs        []urlhausEntry  `json:"urls"`
}

type urlhausEntry struct {
	ID         string   `json:"id"`
	DateAdded  string   `json:"dateadded"`
	URL        string   `json:"url"`
	URLStatus  string   `json:"url_status"`
	Threat     string   `json:"threat"`
	Tags       []string `json:"tags"`
	URLhausLink string  `json:"urlhaus_link"`
	Host       string   `json:"host"`
	Reporter   string   `json:"reporter"`
}
