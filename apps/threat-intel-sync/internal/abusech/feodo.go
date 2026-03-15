package abusech

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// FeodoClient fetches C2 botnet IPs from Feodo Tracker (abuse.ch).
type FeodoClient struct {
	csvURL string
	http   *http.Client
}

func NewFeodoClient() *FeodoClient {
	return &FeodoClient{
		csvURL: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.csv",
		http:   &http.Client{Timeout: 60 * time.Second},
	}
}

// Fetch downloads the Feodo Tracker CSV blocklist and returns IP indicators.
// CSV columns: first_seen_utc, dst_ip, dst_port, last_online, malware
func (c *FeodoClient) Fetch(ctx context.Context) ([]ioc.Indicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.csvURL, nil)
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
		return nil, fmt.Errorf("Feodo %d: %s", resp.StatusCode, body)
	}

	return parseFeodoCSV(resp.Body)
}

func parseFeodoCSV(r io.Reader) ([]ioc.Indicator, error) {
	var indicators []ioc.Indicator
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.SplitN(line, ",", 5)
		if len(fields) < 5 {
			slog.Debug("feodo: skipping malformed line", "line", line)
			continue
		}

		firstSeen := parseAbusechTime(strings.TrimSpace(fields[0]))
		ip := strings.TrimSpace(fields[1])
		port := strings.TrimSpace(fields[2])
		lastOnline := parseAbusechTime(strings.TrimSpace(fields[3]))
		malware := strings.TrimSpace(fields[4])

		value := ip
		if port != "" {
			value = ip + ":" + port
		}

		indicators = append(indicators, ioc.Indicator{
			Type:       ioc.TypeIP,
			Value:      value,
			Source:     "feodo",
			Threat:     malware,
			Confidence: 90,
			FirstSeen:  firstSeen,
			LastSeen:   lastOnline,
			Tags:       []string{"c2", "botnet"},
		})
	}

	if err := scanner.Err(); err != nil {
		return indicators, fmt.Errorf("read CSV: %w", err)
	}
	return indicators, nil
}
