package abusech

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// ThreatFox API limits for get_iocs, per https://threatfox.abuse.ch/api/:
// "days" is 1–7 (IOCs older than 7 days are not returned by this endpoint).
const (
	ThreatFoxMinDays = 1
	ThreatFoxMaxDays = 7
)

// ThreatFoxClient fetches IoCs from the ThreatFox API (abuse.ch).
type ThreatFoxClient struct {
	apiURL string
	http   *http.Client
	opts   options
}

func NewThreatFoxClient(opts ...Option) *ThreatFoxClient {
	return &ThreatFoxClient{
		apiURL: "https://threatfox-api.abuse.ch/api/v1/",
		http:   &http.Client{Timeout: 60 * time.Second},
		opts:   buildOptions(opts),
	}
}

// Fetch retrieves IoCs published within the last N days.
//
// The body is streamed and capped; on a cap or decode failure the rows read
// so far are returned together with the error.
func (c *ThreatFoxClient) Fetch(ctx context.Context, days int) ([]ioc.Indicator, error) {
	if days < ThreatFoxMinDays || days > ThreatFoxMaxDays {
		days = ThreatFoxMaxDays
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
	c.opts.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, feedhttp.StatusError("ThreatFox", resp)
	}

	var indicators []ioc.Indicator
	unsupported := 0
	status, rows, malformed, err := decodeEnvelope(feedhttp.LimitBody(resp.Body, c.opts.maxBytes), "data",
		func(dec *json.Decoder) error {
			var e threatFoxEntry
			if err := dec.Decode(&e); err != nil {
				return err
			}
			iocType := mapThreatFoxType(e.IoCType)
			if iocType == "" {
				unsupported++
				return nil
			}
			indicators = append(indicators, ioc.Indicator{
				Type:       iocType,
				Value:      e.IoC,
				Source:     "threatfox",
				Threat:     e.MalwarePrintable,
				Confidence: e.ConfidenceLevel,
				FirstSeen:  parseAbusechTime(e.FirstSeen),
				LastSeen:   parseAbusechTime(e.LastSeen),
				Tags:       e.Tags,
				Reference:  e.Reference,
			})
			return nil
		})
	if unsupported > 0 {
		slog.Debug("threatfox: skipped unsupported ioc types", "count", unsupported)
	}
	if err != nil {
		return indicators, fmt.Errorf("decode after %d rows: %w", rows, err)
	}
	switch status {
	case "ok":
	case "no_result", "no_results":
		return nil, nil
	default:
		return indicators, fmt.Errorf("ThreatFox query_status: %q", status)
	}
	if malformed > 0 && len(indicators) == 0 {
		return nil, fmt.Errorf("ThreatFox: all %d rows malformed", malformed)
	}
	if malformed > 0 {
		slog.Warn("threatfox: skipped malformed rows", "malformed", malformed, "rows", rows)
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

// threatFoxEntry mirrors one get_iocs row as documented at
// https://threatfox.abuse.ch/api/ (first_seen / last_seen are
// "YYYY-MM-DD HH:MM:SS UTC"; last_seen, reference and tags may be null).
// The client used to read first_seen_utc / last_seen_utc, which the API
// does not send, so every ThreatFox indicator arrived undated. Only the
// fields used are declared: a field of an unexpected type marks the whole
// row malformed.
type threatFoxEntry struct {
	IoC              string   `json:"ioc"`
	IoCType          string   `json:"ioc_type"`
	MalwarePrintable string   `json:"malware_printable"`
	ConfidenceLevel  int      `json:"confidence_level"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	Reference        string   `json:"reference"`
	Tags             []string `json:"tags"`
}
