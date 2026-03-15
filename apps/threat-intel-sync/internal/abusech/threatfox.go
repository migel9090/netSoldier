package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// ThreatFoxClient fetches IoCs from the ThreatFox API (abuse.ch).
type ThreatFoxClient struct {
	apiURL string
	http   *http.Client
}

func NewThreatFoxClient() *ThreatFoxClient {
	return &ThreatFoxClient{
		apiURL: "https://threatfox-api.abuse.ch/api/v1/",
		http:   &http.Client{Timeout: 60 * time.Second},
	}
}

// Fetch retrieves IoCs published within the last N days.
func (c *ThreatFoxClient) Fetch(ctx context.Context, days int) ([]ioc.Indicator, error) {
	if days <= 0 {
		days = 7
	}

	payload, _ := json.Marshal(map[string]any{
		"query": "get_iocs",
		"days":  days,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("ThreatFox %d: %s", resp.StatusCode, body)
	}

	var result threatFoxResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if result.QueryStatus != "ok" {
		return nil, fmt.Errorf("ThreatFox query_status: %s", result.QueryStatus)
	}

	indicators := make([]ioc.Indicator, 0, len(result.Data))
	for _, e := range result.Data {
		iocType := mapThreatFoxType(e.IoCType)
		if iocType == "" {
			slog.Debug("threatfox: skipping unknown ioc_type", "ioc_type", e.IoCType)
			continue
		}
		indicators = append(indicators, ioc.Indicator{
			Type:       iocType,
			Value:      e.IoC,
			Source:     "threatfox",
			Threat:     e.MalwarePrintable,
			Confidence: e.ConfidenceLevel,
			FirstSeen:  parseAbusechTime(e.FirstSeenUTC),
			LastSeen:   parseAbusechTime(e.LastSeenUTC),
			Tags:       e.Tags,
			Reference:  e.Reference,
		})
	}
	return indicators, nil
}

func mapThreatFoxType(t string) string {
	switch t {
	case "domain":
		return ioc.TypeDomain
	case "ip:port":
		return ioc.TypeIP
	case "url":
		return ioc.TypeURL
	case "md5_hash":
		return ioc.TypeMD5
	case "sha256_hash":
		return ioc.TypeSHA256
	default:
		return ""
	}
}

type threatFoxResponse struct {
	QueryStatus string           `json:"query_status"`
	Data        []threatFoxEntry `json:"data"`
}

type threatFoxEntry struct {
	ID               string   `json:"id"`
	IoC              string   `json:"ioc"`
	IoCType          string   `json:"ioc_type"`
	ThreatType       string   `json:"threat_type"`
	MalwarePrintable string   `json:"malware_printable"`
	ConfidenceLevel  int      `json:"confidence_level"`
	FirstSeenUTC     string   `json:"first_seen_utc"`
	LastSeenUTC      string   `json:"last_seen_utc"`
	Reporter         string   `json:"reporter"`
	Reference        string   `json:"reference"`
	Tags             []string `json:"tags"`
}
