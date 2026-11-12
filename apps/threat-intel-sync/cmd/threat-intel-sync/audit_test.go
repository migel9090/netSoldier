package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func names(cfg config) map[string]string {
	out := map[string]string{}
	for _, s := range cfg.sources {
		out[s.name] = "enabled"
	}
	for _, d := range cfg.disabled {
		out[d.name] = d.reason
	}
	return out
}

// TestAuditZeroIntervalPanics (TI-9): SYNC_INTERVAL <= 0 used to reach
// time.NewTicker and panic; "6" (no unit) silently became 6h. Bad global
// settings now refuse to start, with the reason.
func TestAuditZeroIntervalPanics(t *testing.T) {
	for _, env := range []map[string]string{
		{"SYNC_INTERVAL": "0"},
		{"SYNC_INTERVAL": "0s"},
		{"SYNC_INTERVAL": "-1h"},
		{"SYNC_INTERVAL": "6"},
		{"SYNC_INTERVAL": "1m"},
		{"INDICATOR_TTL": "1h"},
		{"INDICATOR_TTL": "forever"},
		{"INDICATOR_STORE_MAX": "0"},
		{"FEED_MAX_BODY_BYTES": "10"},
		{"SOURCE_TIMEOUT": "1s"},
		{"SOURCE_TIMEOUT": "7h"},
	} {
		if _, err := loadConfig(envMap(env)); err == nil {
			t.Errorf("loadConfig(%v) accepted an unusable setting", env)
		}
	}
	cfg, err := loadConfig(envMap(nil))
	if err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
	if cfg.syncInterval != 6*time.Hour || cfg.indicatorTTL != 720*time.Hour || cfg.storeMax != ioc.DefaultMaxIndicators {
		t.Errorf("defaults = %+v", cfg)
	}
}

// TestAuditCommercialModeFailsClosed (TI-9): an unrecognised COMMERCIAL_MODE
// left the non-commercial abuse.ch feeds enabled.
func TestAuditCommercialModeFailsClosed(t *testing.T) {
	for v, wantCommercial := range map[string]bool{
		"": false, "false": false, "0": false, "no": false, "OFF": false,
		"true": true, "TRUE": true, "1": true, "yes": true, " true": true, "true ": true, "on": true,
		"enabled": true, "y": true, "t": true, "flase": true, "commercial": true,
	} {
		cfg, err := loadConfig(envMap(map[string]string{"COMMERCIAL_MODE": v, "ABUSECH_AUTH_KEY": "k"}))
		if err != nil {
			t.Fatal(err)
		}
		n := names(cfg)
		abuseOn := n["threatfox"] == "enabled" || n["urlhaus"] == "enabled" || n["feodo"] == "enabled"
		if cfg.commercial != wantCommercial || abuseOn == wantCommercial {
			t.Errorf("COMMERCIAL_MODE=%q: commercial=%v, sources=%v", v, cfg.commercial, n)
		}
		if n["spamhaus"] != "enabled" {
			t.Errorf("COMMERCIAL_MODE=%q: Spamhaus must stay enabled", v)
		}
	}
}

// TestAuditMISPMissingKeyDisablesOnlyMISP (TI-3 code half, TI-9): MISP_URL
// without MISP_API_KEY used to exit the process, taking every other feed
// down; a plain-HTTP MISP_URL sent the key in clear text.
func TestAuditMISPMissingKeyDisablesOnlyMISP(t *testing.T) {
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"MISP_URL": "http://misp.netsoldier.svc"}, "missing_api_key"},
		{map[string]string{"MISP_URL": "http://misp.netsoldier.svc", "MISP_API_KEY": "k"}, "insecure_url"},
		{map[string]string{"MISP_URL": "http://misp.netsoldier.svc", "MISP_API_KEY": "k", "MISP_ALLOW_INSECURE_HTTP": "maybe"}, "insecure_url"},
		{map[string]string{"MISP_URL": "http://misp.netsoldier.svc", "MISP_API_KEY": "k", "MISP_ALLOW_INSECURE_HTTP": "true"}, "enabled"},
		{map[string]string{"MISP_URL": "https://misp.example", "MISP_API_KEY": "k"}, "enabled"},
		{map[string]string{"MISP_URL": "ftp://misp.example", "MISP_API_KEY": "k"}, "invalid_url"},
		{map[string]string{"MISP_URL": "https://misp.example", "MISP_API_KEY": "k", "MISP_LOOKBACK": "7 days"}, "invalid_lookback"},
		{map[string]string{"MISP_URL": "https://misp.example", "MISP_API_KEY": "k", "MISP_MAX_PAGES": "0"}, "invalid_limits"},
		{map[string]string{}, ""},
	} {
		cfg, err := loadConfig(envMap(c.env))
		if err != nil {
			t.Fatalf("%v: a per-source problem must not stop the service: %v", c.env, err)
		}
		n := names(cfg)
		if n["misp"] != c.want {
			t.Errorf("%v: misp = %q, want %q", c.env, n["misp"], c.want)
		}
		if n["spamhaus"] != "enabled" {
			t.Errorf("%v: other sources must keep running", c.env)
		}
	}
}

// TestAbuseCHAuthKey (TI-8): ThreatFox and URLhaus document Auth-Key as
// mandatory; without one they are disabled up front instead of failing
// every cycle. Feodo documents no key and stays enabled.
func TestAbuseCHAuthKey(t *testing.T) {
	cfg, _ := loadConfig(envMap(nil))
	n := names(cfg)
	if n["threatfox"] != "missing_auth_key" || n["urlhaus"] != "missing_auth_key" || n["feodo"] != "enabled" {
		t.Errorf("without ABUSECH_AUTH_KEY: %v", n)
	}
	cfg, _ = loadConfig(envMap(map[string]string{"ABUSECH_AUTH_KEY": "k", "THREATFOX_DAYS": "30", "URLHAUS_LIMIT": "5000"}))
	n = names(cfg)
	if n["threatfox"] != "invalid_days" || n["urlhaus"] != "invalid_limit" || n["feodo"] != "enabled" {
		t.Errorf("with out-of-range limits: %v", n)
	}
	cfg, _ = loadConfig(envMap(map[string]string{"ABUSECH_AUTH_KEY": "k"}))
	if n = names(cfg); n["threatfox"] != "enabled" || n["urlhaus"] != "enabled" {
		t.Errorf("with a key: %v", n)
	}
}

// TestAuditPartialAndEmptyAreSuccessOrLoss (TI-6, TI-8): the auditor's three
// sources — partial data with an error, a 200 that parses to nothing, and a
// 200 whose every row is rejected. The old loop discarded the partial data
// and counted the other two as successes.
func TestAuditPartialAndEmptyAreSuccessOrLoss(t *testing.T) {
	store := ioc.NewStore()
	sources := []source{
		{name: "audit-partial", fetch: func(context.Context) ([]ioc.Indicator, error) {
			return []ioc.Indicator{{Type: ioc.TypeIP, Value: "198.51.100.0/24", Source: "spamhaus-drop"}},
				errors.New("EDROP: Spamhaus 404")
		}},
		{name: "audit-empty", fetch: func(context.Context) ([]ioc.Indicator, error) { return nil, nil }},
		{name: "audit-allrejected", fetch: func(context.Context) ([]ioc.Indicator, error) {
			return []ioc.Indicator{{Type: ioc.TypeIP, Value: `"203.0.113.10":"443"`, Source: "feodo"}}, nil
		}},
	}
	cfg := config{sources: sources}
	initSourceMetrics(cfg, nil)
	results := map[string]sourceResult{}
	for _, src := range sources {
		results[src.name] = syncSource(context.Background(), store, src, time.Minute)
	}

	if !has(store, "198.51.100.0/24") {
		t.Error("partial policy: what validated must be kept")
	}
	for name, want := range map[string]struct {
		success  bool
		failures float64
	}{
		"audit-partial":     {false, 1},
		"audit-empty":       {true, 0},
		"audit-allrejected": {false, 1},
	} {
		got := results[name]
		lastSuccess := metricValue("threat_intel_source_last_success_timestamp_seconds", "source", name)
		failures := metricValue("threat_intel_source_failures_total", "source", name)
		if got.success != want.success || failures != want.failures || (lastSuccess > 0) != want.success {
			t.Errorf("%s: success=%v failures=%v last_success=%v, want success=%v failures=%v",
				name, got.success, failures, lastSuccess, want.success, want.failures)
		}
	}
	if _, ok := store.FeedSuccess()["audit-partial"]; ok {
		t.Error("a partial fetch must not count as the feed answering (it would age out its other indicators)")
	}
}

// TestOutageAfterSuccessNeverExpiresIndicators (TI-7): the rows of a feed's
// latest successful answer must survive any outage that follows. Only a
// later successful answer that leaves a row out can start its expiry.
func TestOutageAfterSuccessNeverExpiresIndicators(t *testing.T) {
	store := ioc.NewStore()
	src := source{name: "misp", fetch: func(context.Context) ([]ioc.Indicator, error) {
		return []ioc.Indicator{{Type: ioc.TypeDomain, Value: "apt.c2.example", Source: "misp"}}, nil
	}}
	initSourceMetrics(config{sources: []source{src}}, nil)
	if !syncSource(context.Background(), store, src, time.Minute).success {
		t.Fatal("fetch failed")
	}
	// The feed is now unreachable for longer than the TTL.
	if n := store.PruneExpired(time.Now().Add(90 * 24 * time.Hour)); n != 0 || !has(store, "apt.c2.example") {
		t.Fatalf("an outage after a successful fetch aged out its indicators (pruned %d)", n)
	}
	// The feed answers again, without the indicator: now it may expire.
	src.fetch = func(context.Context) ([]ioc.Indicator, error) {
		return []ioc.Indicator{{Type: ioc.TypeDomain, Value: "other.example", Source: "misp"}}, nil
	}
	syncSource(context.Background(), store, src, time.Minute)
	if n := store.PruneExpired(time.Now().Add(time.Hour)); n != 1 || has(store, "apt.c2.example") || !has(store, "other.example") {
		t.Errorf("withdrawn indicator not expired, or the current one pruned (pruned %d)", n)
	}
}

// TestAuditSourceMetricsPreinitialised (TI-6): a source that never worked
// had no source_last_success series, so the staleness alert could not fire.
func TestAuditSourceMetricsPreinitialised(t *testing.T) {
	cfg := config{
		sources:  []source{{name: "never-worked"}, {name: "restored"}},
		disabled: []disabledSource{{name: "off", reason: "missing_auth_key"}},
	}
	restored := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	initSourceMetrics(cfg, map[string]time.Time{"restored": restored})

	if !seriesExists("threat_intel_source_last_success_timestamp_seconds", "never-worked") ||
		!seriesExists("threat_intel_source_failures_total", "never-worked") {
		t.Error("a never-successful source has no series")
	}
	if seriesExists("threat_intel_source_last_success_timestamp_seconds", "off") {
		t.Error("a disabled source must not get a last-success series (the staleness alert would fire for it)")
	}
	if got := metricValue("threat_intel_source_last_success_timestamp_seconds", "source", "never-worked"); got != 0 {
		t.Errorf("never-worked last success = %v, want 0", got)
	}
	if got := metricValue("threat_intel_source_last_success_timestamp_seconds", "source", "restored"); got != float64(restored.Unix()) {
		t.Errorf("restored last success = %v", got)
	}
	if metricValue("threat_intel_source_enabled", "source", "off") != 0 ||
		metricValue("threat_intel_source_enabled", "source", "never-worked") != 1 {
		t.Error("source_enabled wrong")
	}
}

// TestExportsAnswer503UntilReady (TI-5): exports and /healthz used to answer
// 200 before any sync had succeeded, so consumers replaced their good lists
// with empty ones. /healthz stays a liveness probe; /readyz and every export
// answer 503 until there is a set worth serving.
func TestExportsAnswer503UntilReady(t *testing.T) {
	store := ioc.NewStore()
	ready := newReadiness(store)
	mux := routes(store, ready)
	exports := []string{"/export/json", "/export/zeek/intel.dat", "/export/csv", "/export/adguard",
		"/export/suricata/domains", "/export/suricata/ips", "/export/suricata/domains.json",
		"/export/suricata/ips.json", "/export/suricata/md5", "/export/suricata/sha256"}

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	if get("/healthz").Code != 200 {
		t.Error("/healthz is liveness and must answer 200")
	}
	for _, p := range append(exports, "/readyz") {
		if rec := get(p); rec.Code != http.StatusServiceUnavailable {
			t.Errorf("before any sync: %s -> %d %q", p, rec.Code, rec.Body.String())
		}
	}

	// A failed cycle does not make it ready.
	src := source{name: "spamhaus", fetch: func(context.Context) ([]ioc.Indicator, error) {
		return nil, errors.New("network is unreachable")
	}}
	s := testScheduler(store, ready, src)
	s.runDue(context.Background(), time.Now())
	if get("/export/json").Code != http.StatusServiceUnavailable {
		t.Error("ready after a failed cycle")
	}

	src.fetch = func(context.Context) ([]ioc.Indicator, error) {
		return []ioc.Indicator{{Type: ioc.TypeIP, Value: "198.51.100.0/24", Source: "spamhaus-drop"}}, nil
	}
	s = testScheduler(store, ready, src)
	s.runDue(context.Background(), time.Now())
	for _, p := range append(exports, "/readyz") {
		if rec := get(p); rec.Code != 200 {
			t.Errorf("after a successful cycle: %s -> %d", p, rec.Code)
		}
	}
	if body := get("/export/json").Body.String(); !strings.Contains(body, "198.51.100.0/24") {
		t.Errorf("/export/json = %q", body)
	}
}

// TestAuditRestartWhileOffline (TI-5): with a persisted set, a restart
// during a feed outage serves the last good set at once.
func TestAuditRestartWhileOffline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	cfg := config{dbPath: path, storeMax: 1000, sources: []source{{name: "spamhaus"}}}
	store, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store.UpsertFeed("spamhaus", []ioc.Indicator{{Type: ioc.TypeIP, Value: "198.51.100.0/24", Source: "spamhaus-drop"}})
	store.UpsertFeed("threatfox", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "c2.evil.example"}})
	store.Close()

	// Restarted with abuse.ch now disabled, and every feed unreachable.
	store, err = openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ready := newReadiness(store)
	if store.Len() > 0 {
		ready.trust()
	}
	rec := httptest.NewRecorder()
	routes(store, ready).ServeHTTP(rec, httptest.NewRequest("GET", "/export/json", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "198.51.100.0/24") {
		t.Errorf("after restart: %d %q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "c2.evil.example") {
		t.Error("a disabled source's persisted indicators are still served")
	}
}

// TestSchedulerBackoff (TI-5): a failed first cycle was retried only after
// SYNC_INTERVAL (6 h). Failures now back off from one minute, doubling up to
// min(SYNC_INTERVAL, 1h), never below a feed's own floor.
func TestSchedulerBackoff(t *testing.T) {
	store := ioc.NewStore()
	failing := source{name: "threatfox", fetch: func(context.Context) ([]ioc.Indicator, error) {
		return nil, errors.New("down")
	}}
	spamhaus := source{name: "spamhaus", minInterval: time.Hour, fetch: failing.fetch}
	s := testScheduler(store, newReadiness(store), failing, spamhaus)

	now := time.Now()
	var delays []time.Duration
	for i := 0; i < 8; i++ {
		s.runDue(context.Background(), s.next["threatfox"])
		delays = append(delays, s.next["threatfox"].Sub(time.Now()).Round(time.Minute))
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	for i, d := range delays {
		if d != want[i]*time.Minute {
			t.Errorf("retry %d after %s, want %s (all: %v)", i+1, d, want[i]*time.Minute, delays)
			break
		}
	}
	if got := s.next["spamhaus"].Sub(now); got < 59*time.Minute {
		t.Errorf("Spamhaus retried after %s; its rule is at least an hour apart", got)
	}

	s.sources[0].fetch = func(context.Context) ([]ioc.Indicator, error) {
		return []ioc.Indicator{{Type: ioc.TypeDomain, Value: "c2.evil.example"}}, nil
	}
	s.runDue(context.Background(), s.next["threatfox"])
	if got := s.next["threatfox"].Sub(time.Now()).Round(time.Minute); got != 6*time.Hour || s.failures["threatfox"] != 0 {
		t.Errorf("after a success: next in %s, failures %d", got, s.failures["threatfox"])
	}
}

// TestSchedulerHonoursPersistedSuccess: after a restart, a source that
// succeeded recently is not fetched again at once.
func TestSchedulerHonoursPersistedSuccess(t *testing.T) {
	store := ioc.NewStore()
	store.MarkFeedSuccess("spamhaus", time.Now().Add(-10*time.Minute))
	cfg := config{syncInterval: time.Hour, indicatorTTL: 2 * time.Hour, sourceTimeout: time.Minute,
		sources: []source{{name: "spamhaus", minInterval: time.Hour}, {name: "misp"}}}
	s := newScheduler(cfg, store, newReadiness(store))
	if d := time.Until(s.next["spamhaus"]); d < 45*time.Minute {
		t.Errorf("spamhaus due in %s, want ~50m", d)
	}
	if time.Until(s.next["misp"]) > time.Second {
		t.Error("a source with no recorded success is due immediately")
	}
	if d := s.untilNext(time.Now()); d > time.Second {
		t.Errorf("untilNext = %s", d)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	store := ioc.NewStore()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	s := testScheduler(store, newReadiness(store), source{name: "x", fetch: func(context.Context) ([]ioc.Indicator, error) {
		calls++
		cancel()
		return nil, nil
	}})
	done := make(chan struct{})
	go func() { s.run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop on cancel")
	}
	if calls != 1 {
		t.Errorf("calls = %d", calls)
	}
}

func TestMISPMapping(t *testing.T) {
	cfg, err := loadConfig(envMap(map[string]string{"MISP_URL": "https://127.0.0.1:1", "MISP_API_KEY": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range cfg.sources {
		if src.name == "misp" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			inds, err := src.fetch(ctx)
			cancel()
			if err == nil || len(inds) != 0 {
				t.Errorf("unreachable MISP: %d, %v", len(inds), err)
			}
		}
	}
	for misp, want := range map[string]string{
		"domain": ioc.TypeDomain, "hostname": ioc.TypeDomain, "ip-dst": ioc.TypeIP, "ip-src": ioc.TypeIP,
		"url": ioc.TypeURL, "md5": ioc.TypeMD5, "sha256": ioc.TypeSHA256, "ja3-fingerprint-md5": ioc.TypeJA3,
		"x509-fingerprint-sha1": ioc.TypeCertSHA1, "x509-fingerprint-sha256": ioc.TypeCertSHA256, "email": "",
	} {
		if got := mapMISPType(misp); got != want {
			t.Errorf("mapMISPType(%q) = %q", misp, got)
		}
	}
}

func testScheduler(store *ioc.Store, ready *readiness, sources ...source) *scheduler {
	cfg := config{syncInterval: 6 * time.Hour, indicatorTTL: 720 * time.Hour, sourceTimeout: time.Minute, sources: sources}
	initSourceMetrics(cfg, nil)
	return newScheduler(cfg, store, ready)
}

func seriesExists(name, source string) bool {
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "source" && lp.GetValue() == source {
					return true
				}
			}
		}
	}
	return false
}

func has(s *ioc.Store, v string) bool {
	for _, i := range s.All() {
		if i.Value == v {
			return true
		}
	}
	return false
}

// metricValue reads one series from the default registry. It stands in for
// prometheus/testutil, which would add a module dependency for tests only.
func metricValue(name string, labels ...string) float64 {
	mfs, _ := prometheus.DefaultGatherer.Gather()
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	next:
		for _, m := range mf.GetMetric() {
			for i := 0; i+1 < len(labels); i += 2 {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == labels[i] && lp.GetValue() == labels[i+1] {
						found = true
					}
				}
				if !found {
					continue next
				}
			}
			if c := m.GetCounter(); c != nil {
				return c.GetValue()
			}
			if g := m.GetGauge(); g != nil {
				return g.GetValue()
			}
		}
	}
	return 0
}
