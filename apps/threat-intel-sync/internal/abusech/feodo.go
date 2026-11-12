package abusech

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// FeodoClient fetches C2 botnet IPs from Feodo Tracker (abuse.ch).
type FeodoClient struct {
	csvURL string
	http   *http.Client
	opts   options
}

// NewFeodoClient fetches the CSV dataset listed on
// https://feodotracker.abuse.ch/blocklist/. The "recommended" blocklist is
// published only as .txt and .json; the CSV carries every C2 seen in the
// past 30 days with its c2_status, so only rows still "online" are kept —
// the same set the recommended list contains, without the recycled
// addresses of C2s that have gone away.
func NewFeodoClient(opts ...Option) *FeodoClient {
	return &FeodoClient{
		csvURL: "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
		http:   &http.Client{Timeout: 60 * time.Second},
		opts:   buildOptions(opts),
	}
}

// Fetch downloads the Feodo Tracker CSV blocklist and returns IP indicators.
func (c *FeodoClient) Fetch(ctx context.Context) ([]ioc.Indicator, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.csvURL, nil)
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
		return nil, feedhttp.StatusError("Feodo", resp)
	}

	return parseFeodoCSV(feedhttp.LimitBody(resp.Body, c.opts.maxBytes))
}

// feodoColumns locates the fields used, by header name.
type feodoColumns struct {
	firstSeen, ip, port, status, lastOnline, malware int
}

// parseFeodoHeader recognises the column header, quoted or not, and with or
// without the leading "# " the feed has used to comment it out.
func parseFeodoHeader(line string) (feodoColumns, bool) {
	line = strings.TrimSpace(strings.TrimLeft(line, "# "))
	fields, err := csv.NewReader(strings.NewReader(line)).Read()
	if err != nil {
		return feodoColumns{}, false
	}
	cols := feodoColumns{firstSeen: -1, ip: -1, port: -1, status: -1, lastOnline: -1, malware: -1}
	for i, f := range fields {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "first_seen_utc", "first_seen":
			cols.firstSeen = i
		case "dst_ip", "ip_address":
			cols.ip = i
		case "dst_port", "port":
			cols.port = i
		case "c2_status", "status":
			cols.status = i
		case "last_online":
			cols.lastOnline = i
		case "malware":
			cols.malware = i
		}
	}
	return cols, cols.ip >= 0
}

// parseFeodoCSV parses the Feodo CSV with encoding/csv, line by line. The
// columns are located from the header row; a body without one is refused
// rather than parsed by guessing the column order — the old hand-rolled
// splitter assumed five unquoted columns, so the quoted six-column dialect
// produced values like `"203.0.113.10":"443"` that were all rejected while
// the source still counted as successful.
//
// A header with no data rows is a valid empty list (the feed's datasets are
// empty at times). Malformed data rows are skipped and counted; if every
// data row is malformed the parse fails.
func parseFeodoCSV(r io.Reader) ([]ioc.Indicator, error) {
	var (
		indicators []ioc.Indicator
		cols       feodoColumns
		haveHeader bool
		rows       int
		malformed  int
		offline    int
	)
	errNoHeader := errors.New("Feodo CSV: data before a recognisable header")
	err := feedhttp.Lines(r, func(line string) error {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return nil
		}
		if !haveHeader {
			if c, ok := parseFeodoHeader(trimmed); ok {
				cols, haveHeader = c, true
				return nil
			}
			if strings.HasPrefix(trimmed, "#") {
				return nil
			}
			return fmt.Errorf("%w: %q", errNoHeader, truncate(trimmed, 80))
		}
		if strings.HasPrefix(trimmed, "#") {
			return nil
		}

		rows++
		cr := csv.NewReader(strings.NewReader(trimmed))
		cr.TrimLeadingSpace = true
		fields, perr := cr.Read()
		if perr != nil || cols.ip >= len(fields) {
			malformed++
			return nil
		}
		field := func(i int) string {
			if i < 0 || i >= len(fields) {
				return ""
			}
			return strings.TrimSpace(fields[i])
		}
		if s := field(cols.status); s != "" && !strings.EqualFold(s, "online") {
			offline++
			return nil
		}

		value := field(cols.ip)
		if port := field(cols.port); port != "" {
			value = joinHostPort(value, port)
		}
		indicators = append(indicators, ioc.Indicator{
			Type:       ioc.TypeIP,
			Value:      value,
			Source:     "feodo",
			Threat:     field(cols.malware),
			Confidence: 90,
			FirstSeen:  parseAbusechTime(field(cols.firstSeen)),
			LastSeen:   parseAbusechTime(field(cols.lastOnline)),
			Tags:       []string{"c2", "botnet"},
		})
		return nil
	})
	if errors.Is(err, errNoHeader) {
		return nil, err
	}
	if err != nil {
		return indicators, fmt.Errorf("read CSV after %d rows: %w", rows, err)
	}
	if !haveHeader {
		return nil, fmt.Errorf("Feodo CSV: no header row found")
	}
	if malformed > 0 {
		if malformed == rows {
			return nil, fmt.Errorf("Feodo CSV: all %d rows malformed", malformed)
		}
		slog.Warn("feodo: skipped malformed rows", "malformed", malformed, "rows", rows)
	}
	if offline > 0 {
		slog.Debug("feodo: skipped C2s no longer online", "count", offline)
	}
	return indicators, nil
}

func joinHostPort(ip, port string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + port
	}
	return ip + ":" + port
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
