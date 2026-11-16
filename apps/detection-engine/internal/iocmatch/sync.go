package iocmatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		Help:      "Indicators in the feed set currently loaded by the matcher.",
	})
	iocSyncUnsupported = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "ioc_sync_unsupported_total",
		Help:      "Valid indicators skipped because the matcher has no lookup for their type.",
	}, []string{"type"})
)

func init() {
	prometheus.MustRegister(iocSyncLastSuccess, iocSyncFailures, iocSyncIndicators, iocSyncUnsupported)
}

// maxSyncBytes caps the JSON export body. threat-intel-sync's default store
// cap of 100k indicators exports to roughly 40 MiB; anything past the cap is
// refused rather than decoded into memory. A variable only so tests can
// exercise the cap without streaming 64 MiB.
var maxSyncBytes int64 = 64 << 20

var errSyncTooLarge = errors.New("IoC export exceeds size limit")

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

// syncOnce fetches the export and, if it holds a usable set, swaps it in as
// the matcher's feed set. Anything short of that — the service not ready
// (503), an empty list, a list of which nothing validates, a truncated or
// oversized body — keeps the current set and counts a failure: replacing a
// good set with nothing is how a feed outage became a detection outage.
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

	switch {
	case resp.StatusCode == http.StatusServiceUnavailable:
		// threat-intel-sync has no set worth serving yet (fresh start, feeds
		// unreachable). Keep matching against what we have.
		iocSyncFailures.WithLabelValues("not_ready").Inc()
		slog.Warn("threat intel not ready yet — keeping the current indicator set",
			"url", target, "matcher_total", matcher.Size())
		return
	case resp.StatusCode != http.StatusOK:
		iocSyncFailures.WithLabelValues("status").Inc()
		slog.Error("ioc sync rejected — threat intel is NOT being updated",
			"url", target, "status", resp.StatusCode)
		return
	}

	iocs, err := decodeExport(resp.Body)
	if err != nil {
		reason := "decode"
		if errors.Is(err, errSyncTooLarge) {
			reason = "too_large"
		}
		iocSyncFailures.WithLabelValues(reason).Inc()
		slog.Warn("ioc sync decode failed — keeping the current indicator set", "error", err)
		return
	}
	if len(iocs) == 0 {
		iocSyncFailures.WithLabelValues("empty").Inc()
		slog.Error("ioc sync returned an empty list — keeping the current indicator set",
			"url", target, "matcher_total", matcher.Size())
		return
	}

	set, st := buildSet(iocs)
	if st.Invalid > 0 {
		iocSyncFailures.WithLabelValues("invalid_indicator").Add(float64(st.Invalid))
	}
	for typ, n := range st.UnsupportedByType {
		iocSyncUnsupported.WithLabelValues(typ).Add(float64(n))
	}
	if st.Accepted == 0 {
		iocSyncFailures.WithLabelValues("nothing_accepted").Inc()
		slog.Error("ioc sync: no indicator in the export was usable — keeping the current set",
			"fetched", len(iocs), "invalid", st.Invalid, "unsupported", st.Unsupported)
		return
	}
	matcher.feed.Store(set)
	iocSyncLastSuccess.SetToCurrentTime()
	iocSyncIndicators.Set(float64(set.size()))
	slog.Info("ioc sync complete", "fetched", len(iocs), "loaded", st.Accepted,
		"invalid", st.Invalid, "unsupported", st.Unsupported, "matcher_total", matcher.Size())
}

// exportRow is one element of the threat-intel-sync JSON export.
type exportRow struct {
	Type       string   `json:"Type"`
	Value      string   `json:"Value"`
	Source     string   `json:"Source"`
	Threat     string   `json:"Threat"`
	Confidence int      `json:"Confidence"`
	Tags       []string `json:"Tags"`
}

// decodeExport streams the export array element by element under a size
// cap, so memory follows the rows rather than the body.
func decodeExport(r io.Reader) ([]IoC, error) {
	lr := &io.LimitedReader{R: r, N: maxSyncBytes + 1}
	dec := json.NewDecoder(lr)
	tok, err := dec.Token()
	if err != nil {
		return nil, wrapLimit(lr, err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, fmt.Errorf("export is not a JSON array")
	}
	var iocs []IoC
	for dec.More() {
		var row exportRow
		if err := dec.Decode(&row); err != nil {
			return nil, wrapLimit(lr, err)
		}
		iocs = append(iocs, IoC{
			Value:      row.Value,
			Type:       row.Type,
			Source:     row.Source,
			Threat:     row.Threat,
			Confidence: row.Confidence,
			Tags:       row.Tags,
		})
	}
	if _, err := dec.Token(); err != nil {
		return nil, wrapLimit(lr, err)
	}
	if lr.N <= 0 {
		return nil, fmt.Errorf("%w (%d bytes)", errSyncTooLarge, maxSyncBytes)
	}
	return iocs, nil
}

func wrapLimit(lr *io.LimitedReader, err error) error {
	if lr.N <= 0 {
		return fmt.Errorf("%w (%d bytes)", errSyncTooLarge, maxSyncBytes)
	}
	return err
}
