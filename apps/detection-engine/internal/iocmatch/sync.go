package iocmatch

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// SyncLoop periodically fetches IoCs from the threat-intel-sync service
// and loads them into the matcher.
func SyncLoop(ctx context.Context, matcher *Matcher, url string, interval time.Duration) {
	slog.Info("ioc sync started", "url", url, "interval", interval)
	syncOnce(ctx, matcher, url)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce(ctx, matcher, url)
		}
	}
}

func syncOnce(ctx context.Context, matcher *Matcher, url string) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url+"/export/json", nil)
	if err != nil {
		slog.Warn("ioc sync request failed", "error", err)
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		slog.Debug("ioc sync fetch failed", "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("ioc sync bad status", "status", resp.StatusCode)
		return
	}

	var raw []struct {
		Type       string   `json:"Type"`
		Value      string   `json:"Value"`
		Source     string   `json:"Source"`
		Threat     string   `json:"Threat"`
		Confidence int      `json:"Confidence"`
		Tags       []string `json:"Tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		slog.Warn("ioc sync decode failed", "error", err)
		return
	}

	iocs := make([]IoC, 0, len(raw))
	for _, r := range raw {
		iocs = append(iocs, IoC{
			Value:      r.Value,
			Type:       r.Type,
			Source:     r.Source,
			Threat:     r.Threat,
			Confidence: r.Confidence,
			Tags:       r.Tags,
		})
	}

	matcher.Add(iocs)
	slog.Info("ioc sync complete", "fetched", len(iocs), "matcher_total", matcher.Size())
}
