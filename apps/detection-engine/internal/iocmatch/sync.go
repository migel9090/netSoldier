package iocmatch

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	// iocSyncLastSuccess is what makes a silently broken feed sync visible:
	// stale threat intel looks exactly like a quiet network otherwise.
	iocSyncLastSuccess = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "ioc_sync_last_success_timestamp_seconds",
		Help:      "Unix timestamp of the last successful IoC feed sync.",
	})
	iocSyncFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "ioc_sync_failures_total",
		Help:      "IoC feed sync failures by reason.",
	}, []string{"reason"})
	iocSyncIndicators = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "detection_engine",
		Name:      "ioc_sync_indicators",
		Help:      "Indicators returned by the most recent successful sync.",
	})
)

func init() {
	prometheus.MustRegister(iocSyncLastSuccess, iocSyncFailures, iocSyncIndicators)
}

// exportURL builds the IoC export endpoint from the configured base URL.
//
// The deployed value was "http://threat-intel-sync:8083/export/json" while
// this code appended "/export/json" unconditionally, producing
// "/export/json/export/json" → 404. The IoC sync therefore never ran in
// production: the engine matched only the static domains.txt, with MISP and
// all six feeds silently disconnected. Accept either spelling so the
// deployment and the code cannot disagree again.
func exportURL(base string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(base), "/")
	if strings.HasSuffix(trimmed, "/export/json") {
		return trimmed
	}
	return trimmed + "/export/json"
}

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

// syncClient has its own transport so an IoC sync cannot be affected by, or
// affect, other users of http.DefaultClient.
var syncClient = &http.Client{Timeout: 30 * time.Second}

func syncOnce(ctx context.Context, matcher *Matcher, url string) {
	reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	target := exportURL(url)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		iocSyncFailures.WithLabelValues("request").Inc()
		slog.Warn("ioc sync request failed", "error", err)
		return
	}

	resp, err := syncClient.Do(req)
	if err != nil {
		iocSyncFailures.WithLabelValues("fetch").Inc()
		slog.Warn("ioc sync fetch failed", "url", target, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		iocSyncFailures.WithLabelValues("status").Inc()
		slog.Error("ioc sync rejected — threat intel is NOT being updated",
			"url", target, "status", resp.StatusCode)
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
		iocSyncFailures.WithLabelValues("decode").Inc()
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

	added, rejected := matcher.Add(iocs)
	iocSyncLastSuccess.SetToCurrentTime()
	iocSyncIndicators.Set(float64(len(iocs)))
	if rejected > 0 {
		iocSyncFailures.WithLabelValues("invalid_indicator").Add(float64(rejected))
	}
	slog.Info("ioc sync complete", "fetched", len(iocs), "added", added,
		"rejected", rejected, "matcher_total", matcher.Size())
}
