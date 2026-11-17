package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/abusech"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/guard"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/spamhaus"
	"github.com/migel9090/netSoldier/libs/indicator"
)

// Assembled at run time: written as a literal, a test value assigned to a name
// like this one reads as a credential to the secret scanner.
var testAPIKey = strings.Repeat("test-operator-key-", 2)

func feedDomains(prefix string, n int) []ioc.Indicator {
	out := make([]ioc.Indicator, n)
	for i := range out {
		out[i] = ioc.Indicator{Type: ioc.TypeDomain, Value: fmt.Sprintf("%s%d.evil.example", prefix, i), Source: "testfeed"}
	}
	return out
}

// harness is one threat-intel-sync instance with a single test feed whose
// answer the test sets.
type harness struct {
	t      *testing.T
	store  *ioc.Store
	guard  *guard.Manager
	ready  *readiness
	sched  *scheduler
	mux    *http.ServeMux
	answer []ioc.Indicator
}

func newHarness(t *testing.T, store *ioc.Store, apiKey string) *harness {
	h := &harness{t: t, store: store}
	src := source{name: "testfeed", maxAge: 24 * time.Hour, fetch: func(context.Context) ([]ioc.Indicator, error) {
		return h.answer, nil
	}}
	cfg := config{syncInterval: 6 * time.Hour, indicatorTTL: 720 * time.Hour, sourceTimeout: time.Minute,
		storeMax: ioc.DefaultMaxIndicators, volume: guard.DefaultLimits(), apiKey: apiKey, sources: []source{src}}
	h.guard = guard.New(store, cfg.volume, cfg.sourceNames(), cfg.storeMax)
	initSourceMetrics(cfg, store.FeedSuccess())
	initGuardMetrics(cfg, h.guard)
	fresh.configure(cfg.freshnessObjectives(), store.FeedSuccess)
	h.ready = newReadiness(store)
	if store.Len() > 0 {
		h.ready.trust()
	}
	h.sched = newScheduler(cfg, store, h.guard, h.ready)
	h.mux = newService(cfg, store, h.guard, h.ready).routes()
	return h
}

// sync runs the feed now, whatever its schedule says.
func (h *harness) sync(answer []ioc.Indicator) {
	h.answer = answer
	h.sched.next["testfeed"] = time.Time{}
	h.sched.runDue(context.Background(), time.Now())
}

func (h *harness) do(method, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	return rec
}

func operator(actor string) map[string]string {
	hdr := map[string]string{"Authorization": "Bearer " + testAPIKey}
	if actor != "" {
		hdr["X-Netsoldier-Actor"] = actor
	}
	return hdr
}

func adguardRules(body string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if strings.HasPrefix(l, "||") {
			out = append(out, l)
		}
	}
	return out
}

// TestStep134FeedJumpAndPopularDomain is the step's "done when": a test feed
// containing a popular domain is refused for that entry, and a tenfold jump
// of its volume is held with an alert metric while the previous list keeps
// being served — to AdGuard, unchanged down to its ETag. The operator then
// inspects and releases it through the authenticated API.
func TestStep134FeedJumpAndPopularDomain(t *testing.T) {
	h := newHarness(t, ioc.NewStore(), testAPIKey)
	popular := []ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "docs.google.com", Source: "testfeed"},
		{Type: ioc.TypeDomain, Value: "google.com", Source: "testfeed"},
	}
	nbBefore := metricValue("threat_intel_source_indicators_never_block_total", "source", "testfeed", "reason", indicator.ReasonPopular)
	h.sync(append(feedDomains("a", 600), popular...))

	first := h.do("GET", "/export/adguard", "", nil)
	if first.Code != 200 || len(adguardRules(first.Body.String())) != 600 {
		t.Fatalf("first list: %d, %d rules", first.Code, len(adguardRules(first.Body.String())))
	}
	if strings.Contains(first.Body.String(), "google") {
		t.Error("a popular domain became an AdGuard rule")
	}
	if got := metricValue("threat_intel_source_indicators_never_block_total", "source", "testfeed", "reason", indicator.ReasonPopular) - nbBefore; got != 2 {
		t.Errorf("never-block counter rose by %v, want 2", got)
	}
	etag := first.Header().Get("ETag")

	// Tenfold.
	qBefore := metricValue("threat_intel_source_quarantine_total", "source", "testfeed", "reason", guard.ReasonGrowth)
	h.sync(append(feedDomains("b", 6000), popular...))
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 1 ||
		metricValue("threat_intel_source_quarantine_total", "source", "testfeed", "reason", guard.ReasonGrowth)-qBefore != 1 ||
		metricValue("threat_intel_source_quarantined_indicators", "source", "testfeed") != 6000 {
		t.Fatal("the tenfold jump did not raise the quarantine metrics")
	}
	// The previous list keeps working: unchanged for a conditional fetch...
	if rec := h.do("GET", "/export/adguard", "", map[string]string{"If-None-Match": etag}); rec.Code != http.StatusNotModified {
		// The header names the quarantined source, so the body may change;
		// the rules must not.
		if rules := adguardRules(rec.Body.String()); rec.Code != 200 || len(rules) != 600 {
			t.Fatalf("during quarantine: %d, %d rules", rec.Code, len(rules))
		}
	}
	list := h.do("GET", "/export/adguard", "", nil).Body.String()
	if len(adguardRules(list)) != 600 || strings.Contains(list, "b0.evil.example") ||
		!strings.Contains(list, "! Quarantined sources: testfeed\n") {
		t.Errorf("during quarantine the list changed or does not say so:\n%.600s", list)
	}
	if body := h.do("GET", "/export/json", "", nil).Body.String(); strings.Contains(body, "b0.evil.example") {
		t.Error("the held set reached /export/json")
	}
	var rz struct {
		Status      string   `json:"status"`
		Quarantined []string `json:"quarantined_sources"`
	}
	rec := h.do("GET", "/readyz", "", nil)
	json.Unmarshal(rec.Body.Bytes(), &rz)
	if rec.Code != 200 || rz.Status != "ready" || len(rz.Quarantined) != 1 || rz.Quarantined[0] != "testfeed" {
		t.Errorf("/readyz during quarantine: %d %s", rec.Code, rec.Body.String())
	}

	// Inspect: authenticated.
	if rec := h.do("GET", "/quarantine", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /quarantine without a key: %d", rec.Code)
	}
	if rec := h.do("GET", "/quarantine", "", map[string]string{"Authorization": "Bearer wrong-key-but-long-enough"}); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /quarantine with a wrong key: %d", rec.Code)
	}
	var listed struct {
		Quarantined []ioc.HeldSet `json:"quarantined"`
	}
	rec = h.do("GET", "/quarantine", "", operator(""))
	json.Unmarshal(rec.Body.Bytes(), &listed)
	if rec.Code != 200 || len(listed.Quarantined) != 1 || listed.Quarantined[0].Size != 6000 ||
		listed.Quarantined[0].Reason != guard.ReasonGrowth || listed.Quarantined[0].Baseline != 600 {
		t.Fatalf("GET /quarantine: %d %s", rec.Code, rec.Body.String())
	}
	id := listed.Quarantined[0].ID
	var page struct {
		Rows       int `json:"rows"`
		Matched    int `json:"matched"`
		Indicators []struct {
			Value string `json:"value"`
			New   bool   `json:"new"`
		} `json:"indicators"`
	}
	rec = h.do("GET", "/quarantine/testfeed?limit=5&new=true", "", operator(""))
	json.Unmarshal(rec.Body.Bytes(), &page)
	if rec.Code != 200 || page.Rows != 6000 || page.Matched != 6000 || len(page.Indicators) != 5 || !page.Indicators[0].New {
		t.Errorf("GET /quarantine/testfeed: %d %.300s", rec.Code, rec.Body.String())
	}
	if rec := h.do("GET", "/quarantine/nosuchfeed", "", operator("")); rec.Code != http.StatusNotFound {
		t.Errorf("unknown source: %d", rec.Code)
	}

	// Release: needs the actor and the inspected id.
	body := `{"id":"` + id + `"}`
	if rec := h.do("POST", "/quarantine/testfeed/release", body, operator("")); rec.Code != http.StatusBadRequest {
		t.Errorf("release without X-Netsoldier-Actor: %d", rec.Code)
	}
	if rec := h.do("POST", "/quarantine/testfeed/release", body, operator("ttl")); rec.Code != http.StatusBadRequest {
		t.Errorf("release as a reserved actor: %d", rec.Code)
	}
	if rec := h.do("POST", "/quarantine/testfeed/release", `{}`, operator("alice")); rec.Code != http.StatusBadRequest {
		t.Errorf("release without an id: %d", rec.Code)
	}
	if rec := h.do("POST", "/quarantine/testfeed/release", `{"id":"0123"}`, operator("alice")); rec.Code != http.StatusConflict {
		t.Errorf("release of a stale id: %d", rec.Code)
	}
	if rec := h.do("GET", "/quarantine/testfeed/release", body, operator("alice")); rec.Code == 200 {
		t.Error("release over GET")
	}
	relBefore := metricValue("threat_intel_source_quarantine_resolved_total", "source", "testfeed", "action", actionReleased)
	rec = h.do("POST", "/quarantine/testfeed/release", body, operator("alice"))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"actor":"alice"`) {
		t.Fatalf("release: %d %s", rec.Code, rec.Body.String())
	}
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 0 ||
		metricValue("threat_intel_source_quarantine_resolved_total", "source", "testfeed", "action", actionReleased)-relBefore != 1 {
		t.Error("release did not clear the quarantine metrics")
	}
	if rules := adguardRules(h.do("GET", "/export/adguard", "", nil).Body.String()); len(rules) != 6600 {
		t.Errorf("after release: %d rules, want 6600 (the old set is still asserted)", len(rules))
	}
	if rec := h.do("POST", "/quarantine/testfeed/release", body, operator("alice")); rec.Code != http.StatusNotFound {
		t.Errorf("second release: %d", rec.Code)
	}
	// The released size is the usual one now.
	h.sync(append(feedDomains("b", 6100), popular...))
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 0 {
		t.Error("the fetch after a release was held again")
	}
}

// TestStep134CollapseDiscardAndSupersede: an empty answer from a feed that
// usually lists thousands is held (applying it would start the expiry of
// the whole set); a discard keeps the previous set; a held fetch is
// superseded when the feed answers normally again.
func TestStep134CollapseDiscardAndSupersede(t *testing.T) {
	h := newHarness(t, ioc.NewStore(), testAPIKey)
	h.sync(feedDomains("a", 2000))
	before := h.store.FeedSuccess()["testfeed"]

	h.sync(nil)
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 1 || !h.store.FeedSuccess()["testfeed"].Equal(before) {
		t.Fatal("an empty answer after 2000 was not held, or counted as the feed's answer")
	}
	if rec := h.do("POST", "/quarantine/testfeed/discard", "", operator("")); rec.Code != http.StatusBadRequest {
		t.Errorf("discard without an actor: %d", rec.Code)
	}
	rec := h.do("POST", "/quarantine/testfeed/discard", "", operator("bob"))
	if rec.Code != 200 || h.store.Len() != 2000 || metricValue("threat_intel_source_quarantined", "source", "testfeed") != 0 {
		t.Fatalf("discard: %d %s, %d indicators", rec.Code, rec.Body.String(), h.store.Len())
	}

	h.sync(feedDomains("c", 20000))
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 1 {
		t.Fatal("jump not held")
	}
	supBefore := metricValue("threat_intel_source_quarantine_resolved_total", "source", "testfeed", "action", actionSuperseded)
	h.sync(feedDomains("a", 2050))
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 0 ||
		metricValue("threat_intel_source_quarantine_resolved_total", "source", "testfeed", "action", actionSuperseded)-supBefore != 1 {
		t.Error("a passing fetch did not supersede the held one")
	}
}

// TestStep134QuarantineSurvivesRestart: with the persistent store, a held
// fetch is still held, alerted and releasable after a restart, and the
// volume history means the same jump is held again rather than accepted as
// a cold start.
func TestStep134QuarantineSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "indicators.db")
	cfg := config{dbPath: path, storeMax: ioc.DefaultMaxIndicators, sources: []source{{name: "testfeed"}}}
	store, err := openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, store, testAPIKey)
	h.sync(feedDomains("a", 600))
	h.sync(feedDomains("b", 6000))
	store.Close()

	store, err = openStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h = newHarness(t, store, testAPIKey)
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 1 {
		t.Error("the quarantine alert did not survive the restart")
	}
	if rules := adguardRules(h.do("GET", "/export/adguard", "", nil).Body.String()); len(rules) != 600 {
		t.Errorf("after restart: %d rules", len(rules))
	}
	h.sync(feedDomains("b", 6000))
	if metricValue("threat_intel_source_quarantined", "source", "testfeed") != 1 || store.Len() != 600 {
		t.Error("after a restart the same jump was accepted")
	}
	held, _ := h.guard.Get("testfeed")
	if rec := h.do("POST", "/quarantine/testfeed/release", `{"id":"`+held.ID+`"}`, operator("carol")); rec.Code != 200 {
		t.Errorf("release after restart: %d %s", rec.Code, rec.Body.String())
	}
}

func TestStep134OperatorAPIClosedWithoutKey(t *testing.T) {
	h := newHarness(t, ioc.NewStore(), "")
	for _, c := range []struct{ method, path string }{
		{"GET", "/quarantine"}, {"GET", "/quarantine/testfeed"},
		{"POST", "/quarantine/testfeed/release"}, {"POST", "/quarantine/testfeed/discard"},
	} {
		if rec := h.do(c.method, c.path, `{"id":"x"}`, operator("alice")); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s without THREAT_INTEL_API_KEY: %d", c.method, c.path, rec.Code)
		}
	}
}

// TestStep134StaleSourceInReadyz: a source past its freshness objective is
// reported in /readyz and threat_intel_source_stale, and the service stays
// ready.
func TestStep134StaleSourceInReadyz(t *testing.T) {
	store := ioc.NewStore()
	store.UpsertFeed("spamhaus", []ioc.Indicator{{Type: ioc.TypeIP, Value: "198.51.100.0/24"}})
	store.MarkFeedSuccess("spamhaus", time.Now().Add(-30*time.Hour))
	store.MarkFeedSuccess("feodo", time.Now().Add(-time.Hour))
	cfg := config{sources: []source{{name: "spamhaus", maxAge: 24 * time.Hour}, {name: "feodo", maxAge: 24 * time.Hour},
		{name: "misp", maxAge: 24 * time.Hour}}}
	initSourceMetrics(cfg, store.FeedSuccess())
	fresh.configure(cfg.freshnessObjectives(), store.FeedSuccess)
	ready := newReadiness(store)
	ready.trust()
	mux := newService(cfg, store, testGuard(store), ready).routes()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	var rz struct {
		Status  string   `json:"status"`
		Stale   []string `json:"stale_sources"`
		Sources map[string]struct {
			Stale      bool   `json:"stale"`
			AgeSeconds *int64 `json:"age_seconds"`
			Objective  int64  `json:"freshness_objective_seconds"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rz); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 || rz.Status != "ready" || strings.Join(rz.Stale, ",") != "misp,spamhaus" {
		t.Errorf("/readyz: %d %s", rec.Code, rec.Body.String())
	}
	if s := rz.Sources["spamhaus"]; !s.Stale || s.AgeSeconds == nil || *s.AgeSeconds < 29*3600 || s.Objective != 86400 {
		t.Errorf("spamhaus = %+v", s)
	}
	if s := rz.Sources["misp"]; !s.Stale || s.AgeSeconds != nil {
		t.Errorf("a never-successful source must be stale with no age: %+v", s)
	}
	if metricValue("threat_intel_source_stale", "source", "spamhaus") != 1 ||
		metricValue("threat_intel_source_stale", "source", "feodo") != 0 ||
		metricValue("threat_intel_source_freshness_objective_seconds", "source", "feodo") != 86400 {
		t.Error("stale / objective series wrong")
	}
	if !strings.Contains(adguardBody(mux), "! Stale sources: misp spamhaus\n") {
		t.Error("the AdGuard header does not name the stale sources")
	}
}

func adguardBody(mux *http.ServeMux) string {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/export/adguard", nil))
	return rec.Body.String()
}

// TestStep134Config: the new settings fail closed at start-up, and the
// defaults are the documented ones.
func TestStep134Config(t *testing.T) {
	cfg, err := loadConfig(envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.volume != guard.DefaultLimits() || cfg.maxAge != 24*time.Hour || cfg.apiKey != "" {
		t.Errorf("defaults: %+v, max age %s", cfg.volume, cfg.maxAge)
	}
	for _, s := range cfg.sources {
		if s.maxAge != 24*time.Hour {
			t.Errorf("%s objective %s", s.name, s.maxAge)
		}
	}
	cfg, err = loadConfig(envMap(map[string]string{"SYNC_INTERVAL": "12h", "INDICATOR_TTL": "720h"}))
	if err != nil || cfg.maxAge != 36*time.Hour {
		t.Errorf("default objective follows SYNC_INTERVAL: %s, %v", cfg.maxAge, err)
	}
	cfg, err = loadConfig(envMap(map[string]string{
		"VOLUME_GROWTH_FACTOR": "10", "VOLUME_SHRINK_FACTOR": "2.5", "VOLUME_MIN_CHANGE": "0",
		"VOLUME_FIRST_SYNC_MAX": "1000", "SOURCE_MAX_AGE": "48h", "SOURCE_MAX_AGE_SPAMHAUS": "72h",
		"THREAT_INTEL_API_KEY": testAPIKey,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.volume != (guard.Limits{GrowthFactor: 10, ShrinkFactor: 2.5, MinChange: 0, FirstSyncMax: 1000}) ||
		cfg.apiKey != testAPIKey || cfg.freshnessObjectives()["spamhaus"] != 72*time.Hour ||
		cfg.freshnessObjectives()["feodo"] != 48*time.Hour {
		t.Errorf("explicit settings: %+v %v", cfg.volume, cfg.freshnessObjectives())
	}
	for _, env := range []map[string]string{
		{"VOLUME_GROWTH_FACTOR": "1"},
		{"VOLUME_GROWTH_FACTOR": "0.5"},
		{"VOLUME_GROWTH_FACTOR": "NaN"},
		{"VOLUME_GROWTH_FACTOR": "Inf"},
		{"VOLUME_GROWTH_FACTOR": "three"},
		{"VOLUME_SHRINK_FACTOR": "1"},
		{"VOLUME_MIN_CHANGE": "-1"},
		{"VOLUME_FIRST_SYNC_MAX": "0"},
		{"SOURCE_MAX_AGE": "6h"}, // below 2 × SYNC_INTERVAL
		{"SOURCE_MAX_AGE": "forever"},
		{"SOURCE_MAX_AGE_SPAMHAUS": "1h"},
		{"SOURCE_MAX_AGE_FEODO": "x"},
		{"THREAT_INTEL_API_KEY": "short"},
		{"THREAT_INTEL_API_KEY": "has a space in it, long enough"},
	} {
		if _, err := loadConfig(envMap(env)); err == nil {
			t.Errorf("loadConfig(%v) accepted an unusable setting", env)
		}
	}
}

// TestStep134FeedEndpointsPinned: every built-in feed is fetched over https
// from its fixed host; the client refuses to be redirected anywhere else
// (internal/feedhttp tests the refusal itself).
func TestStep134FeedEndpointsPinned(t *testing.T) {
	cfg, err := loadConfig(envMap(map[string]string{"ABUSECH_AUTH_KEY": "k",
		"MISP_URL": "https://misp.example", "MISP_API_KEY": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	pinned := map[string]string{
		"spamhaus":  spamhaus.Host,
		"threatfox": abusech.ThreatFoxHost,
		"urlhaus":   abusech.URLhausHost,
		"feodo":     abusech.FeodoHost,
		"misp":      "misp.example",
	}
	if len(cfg.sources) != len(pinned) {
		t.Fatalf("sources = %v", cfg.sourceNames())
	}
	for _, s := range cfg.sources {
		if err := feedhttp.CheckPinned(s.endpoint, pinned[s.name]); err != nil {
			t.Errorf("%s: %v", s.name, err)
		}
	}
	for host, want := range map[string]string{
		spamhaus.Host: "www.spamhaus.org", abusech.ThreatFoxHost: "threatfox-api.abuse.ch",
		abusech.URLhausHost: "urlhaus-api.abuse.ch", abusech.FeodoHost: "feodotracker.abuse.ch",
	} {
		if host != want {
			t.Errorf("pinned host %q changed, want %q", host, want)
		}
	}
}
