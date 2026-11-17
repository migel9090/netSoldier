package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/abusech"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/guard"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/misp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/spamhaus"
)

// Configuration, all from the environment. Every value is validated at
// start-up and the service fails closed:
//
//   - A global setting with no safe interpretation (SYNC_INTERVAL,
//     INDICATOR_TTL, INDICATOR_STORE_MAX, FEED_MAX_BODY_BYTES,
//     SOURCE_TIMEOUT) stops the process with every problem listed, instead
//     of panicking (SYNC_INTERVAL=0 used to crash time.NewTicker) or
//     silently falling back to a default.
//
//   - A setting that belongs to one source (its credentials, its URL, its
//     limits) disables that source, loudly — an ERROR log line and
//     threat_intel_source_enabled{source}=0 — and leaves the others running.
//     A MISP_URL without MISP_API_KEY used to exit the whole service and take
//     every other feed down with it.
//
//   - COMMERCIAL_MODE with a value that is not recognised is treated as on:
//     the flag exists so a commercial deployment ships without the
//     non-commercial abuse.ch feeds (COMPLIANCE.md), and a typo must not
//     quietly re-enable them.
//
// Variables, defaults and bounds:
//
//	LISTEN_ADDR              :8083
//	SYNC_INTERVAL            6h      at least 5m
//	INDICATOR_TTL            720h    at least 2 × SYNC_INTERVAL, measured from
//	                                 the last time a feed asserted an indicator
//	INDICATOR_DB_PATH        ""      SQLite file of the durable store; empty
//	                                 keeps it in memory only (logged as a warning)
//	INDICATOR_STORE_MAX      100000  distinct indicators
//	FEED_MAX_BODY_BYTES      32 MiB  per response, 1 MiB – 1 GiB
//	SOURCE_TIMEOUT           5m      per source and cycle, all MISP pages included
//	COMMERCIAL_MODE          off     true/1/yes/on or false/0/no/off
//	ABUSECH_AUTH_KEY         ""      ThreatFox and URLhaus are disabled without it
//	THREATFOX_DAYS           7       1–7
//	URLHAUS_LIMIT            1000    1–1000
//	MISP_URL                 ""      MISP is enabled when set
//	MISP_API_KEY             ""
//	MISP_ALLOW_INSECURE_HTTP false   required for an http:// MISP_URL
//	MISP_LOOKBACK            7d
//	MISP_MAX_PAGES           20
//	MISP_PAGE_SIZE           5000
//
// Volume guard (internal/guard; a fetch beyond these is held in
// quarantine and the previous set keeps being served):
//
//	VOLUME_GROWTH_FACTOR     3       hold a fetch above 3 × the usual size;
//	                                 above 1, at most 1000
//	VOLUME_SHRINK_FACTOR     4       hold a complete fetch below usual / 4;
//	                                 above 1, at most 1000
//	VOLUME_MIN_CHANGE        500     ... only when it differs from usual by
//	                                 at least this many; 0 – 10 000 000
//	VOLUME_FIRST_SYNC_MAX    50000   hold a source's first fetch above this;
//	                                 1 – 10 000 000
//
// Freshness and the operator API:
//
//	SOURCE_MAX_AGE           max(24h, 3 × SYNC_INTERVAL)  freshness objective
//	                                 of every source: past it, the source is
//	                                 stale (metric, /readyz); at least
//	                                 2 × SYNC_INTERVAL
//	SOURCE_MAX_AGE_<SOURCE>  SOURCE_MAX_AGE  per source (SPAMHAUS, THREATFOX,
//	                                 URLHAUS, FEODO, MISP); at least
//	                                 2 × max(SYNC_INTERVAL, the feed's own
//	                                 minimum interval)
//	THREAT_INTEL_API_KEY     ""      bearer token of the quarantine API; at
//	                                 least 16 printable characters. Unset:
//	                                 the API answers 403 (inspection and
//	                                 release need it), everything else runs
type config struct {
	listenAddr    string
	syncInterval  time.Duration
	indicatorTTL  time.Duration
	dbPath        string
	storeMax      int
	maxBodyBytes  int64
	sourceTimeout time.Duration
	commercial    bool
	volume        guard.Limits
	maxAge        time.Duration // default freshness objective
	apiKey        string

	sources  []source
	disabled []disabledSource
}

// source is one feed the sync loop fetches.
type source struct {
	name  string
	fetch func(context.Context) ([]ioc.Indicator, error)
	// minInterval is the feed's own floor between downloads, honoured by
	// retries too (Spamhaus: one hour).
	minInterval time.Duration
	// endpoint is where the feed is fetched from, for the start-up log and
	// the pinning test. The client refuses any redirect off its origin.
	endpoint string
	// maxAge is the source's freshness objective; 0 means none.
	maxAge time.Duration
}

// minAPIKeyLen keeps a placeholder ("changeme", "x") from being an API key.
const minAPIKeyLen = 16

type disabledSource struct {
	name, reason string
}

const (
	minSyncInterval = 5 * time.Minute
	minBodyBytes    = 1 << 20
	maxBodyBytes    = 1 << 30
)

func loadConfig(getenv func(string) string) (config, error) {
	var errs []error
	env := func(key, fallback string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	fatal := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	cfg := config{
		listenAddr: env("LISTEN_ADDR", ":8083"),
		dbPath:     env("INDICATOR_DB_PATH", ""),
	}

	var err error
	if cfg.syncInterval, err = time.ParseDuration(env("SYNC_INTERVAL", "6h")); err != nil {
		fatal("SYNC_INTERVAL: %v", err)
	} else if cfg.syncInterval < minSyncInterval {
		fatal("SYNC_INTERVAL=%s: must be at least %s", cfg.syncInterval, minSyncInterval)
	}
	if cfg.indicatorTTL, err = time.ParseDuration(env("INDICATOR_TTL", "720h")); err != nil {
		fatal("INDICATOR_TTL: %v", err)
	} else if cfg.syncInterval > 0 && cfg.indicatorTTL < 2*cfg.syncInterval {
		fatal("INDICATOR_TTL=%s: must be at least twice SYNC_INTERVAL (%s), or one missed "+
			"cycle would expire live intel", cfg.indicatorTTL, cfg.syncInterval)
	}
	if cfg.storeMax, err = strconv.Atoi(env("INDICATOR_STORE_MAX", strconv.Itoa(ioc.DefaultMaxIndicators))); err != nil || cfg.storeMax < 1 {
		fatal("INDICATOR_STORE_MAX=%q: must be a positive integer", getenv("INDICATOR_STORE_MAX"))
	}
	if cfg.maxBodyBytes, err = strconv.ParseInt(env("FEED_MAX_BODY_BYTES", strconv.FormatInt(feedhttp.DefaultMaxBodyBytes, 10)), 10, 64); err != nil ||
		cfg.maxBodyBytes < minBodyBytes || cfg.maxBodyBytes > maxBodyBytes {
		fatal("FEED_MAX_BODY_BYTES=%q: must be between %d and %d", getenv("FEED_MAX_BODY_BYTES"), minBodyBytes, maxBodyBytes)
	}
	if cfg.sourceTimeout, err = time.ParseDuration(env("SOURCE_TIMEOUT", "5m")); err != nil || cfg.sourceTimeout < 10*time.Second {
		fatal("SOURCE_TIMEOUT=%q: must be a duration of at least 10s", getenv("SOURCE_TIMEOUT"))
	} else if cfg.syncInterval > 0 && cfg.sourceTimeout > cfg.syncInterval {
		fatal("SOURCE_TIMEOUT=%s: must not exceed SYNC_INTERVAL (%s)", cfg.sourceTimeout, cfg.syncInterval)
	}

	cfg.volume = guard.DefaultLimits()
	parseFactor := func(key string, dst *float64) {
		if v := env(key, ""); v != "" {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil || !(f > guard.MinFactor && f <= guard.MaxFactor) {
				fatal("%s=%q: must be a number above %v and at most %v", key, v, guard.MinFactor, guard.MaxFactor)
				return
			}
			*dst = f
		}
	}
	parseCount := func(key string, dst *int, lo, hi int) {
		if v := env(key, ""); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < lo || n > hi {
				fatal("%s=%q: must be an integer from %d to %d", key, v, lo, hi)
				return
			}
			*dst = n
		}
	}
	parseFactor("VOLUME_GROWTH_FACTOR", &cfg.volume.GrowthFactor)
	parseFactor("VOLUME_SHRINK_FACTOR", &cfg.volume.ShrinkFactor)
	parseCount("VOLUME_MIN_CHANGE", &cfg.volume.MinChange, 0, guard.MaxMinChange)
	parseCount("VOLUME_FIRST_SYNC_MAX", &cfg.volume.FirstSyncMax, 1, guard.MaxFirstSyncMax)
	if err := cfg.volume.Validate(); err != nil {
		fatal("volume guard: %v", err)
	}

	cfg.maxAge = max(24*time.Hour, 3*cfg.syncInterval)
	if v := env("SOURCE_MAX_AGE", ""); v != "" {
		if cfg.maxAge, err = time.ParseDuration(v); err != nil {
			fatal("SOURCE_MAX_AGE: %v", err)
		}
	}
	if cfg.syncInterval > 0 && cfg.maxAge < 2*cfg.syncInterval {
		fatal("SOURCE_MAX_AGE=%s: must be at least twice SYNC_INTERVAL (%s), or every source "+
			"would be stale between two cycles", cfg.maxAge, cfg.syncInterval)
	}

	cfg.apiKey = strings.TrimSpace(getenv("THREAT_INTEL_API_KEY"))
	if cfg.apiKey != "" && !validAPIKey(cfg.apiKey) {
		fatal("THREAT_INTEL_API_KEY: must be at least %d printable ASCII characters without spaces",
			minAPIKeyLen)
	}
	if len(errs) > 0 {
		return cfg, errors.Join(errs...)
	}

	commercial, cerr := parseCommercialMode(getenv("COMMERCIAL_MODE"))
	if cerr != nil {
		slog.Error("COMMERCIAL_MODE not recognised: treating it as ON, abuse.ch feeds disabled (fail closed)",
			"value", getenv("COMMERCIAL_MODE"), "error", cerr)
	}
	cfg.commercial = commercial

	cfg.configureMISP(env)
	cfg.configureAbuseCH(env)

	spClient := spamhaus.NewClient(cfg.maxBodyBytes)
	// Spamhaus DROP is free for commercial use too (attribution required,
	// see COMPLIANCE.md), so it stays enabled regardless of COMMERCIAL_MODE.
	cfg.sources = append(cfg.sources, source{
		name:        "spamhaus",
		fetch:       spClient.FetchAll,
		minInterval: spamhaus.MinFetchInterval,
		endpoint:    spamhaus.DROPURL,
	})

	// Freshness objectives, per source.
	for i := range cfg.sources {
		src := &cfg.sources[i]
		src.maxAge = cfg.maxAge
		key := "SOURCE_MAX_AGE_" + strings.ToUpper(src.name)
		if v := env(key, ""); v != "" {
			if src.maxAge, err = time.ParseDuration(v); err != nil {
				fatal("%s: %v", key, err)
				continue
			}
		}
		if floor := 2 * max(cfg.syncInterval, src.minInterval); src.maxAge < floor {
			fatal("%s=%s: must be at least %s (twice the source's interval)", key, src.maxAge, floor)
		}
	}
	if len(errs) > 0 {
		return cfg, errors.Join(errs...)
	}
	return cfg, nil
}

// validAPIKey: long enough, and printable ASCII without spaces, so it can
// only ever be compared, never smuggle anything into a header or a log.
func validAPIKey(k string) bool {
	if len(k) < minAPIKeyLen {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] <= 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// freshnessObjectives returns every enabled source's objective.
func (cfg config) freshnessObjectives() map[string]time.Duration {
	out := make(map[string]time.Duration, len(cfg.sources))
	for _, s := range cfg.sources {
		if s.maxAge > 0 {
			out[s.name] = s.maxAge
		}
	}
	return out
}

func (cfg *config) disable(name, reason string, args ...any) {
	cfg.disabled = append(cfg.disabled, disabledSource{name: name, reason: reason})
	slog.Error("source disabled", append([]any{"source", name, "reason", reason}, args...)...)
}

var mispLookback = regexp.MustCompile(`^([1-9][0-9]*[smhdwy]|[0-9]{9,11})$`)

func (cfg *config) configureMISP(env func(string, string) string) {
	mispURL := env("MISP_URL", "")
	if mispURL == "" {
		return
	}
	u, err := url.Parse(mispURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		cfg.disable("misp", "invalid_url", "url", mispURL)
		return
	}
	key := env("MISP_API_KEY", "")
	if key == "" {
		cfg.disable("misp", "missing_api_key", "hint", "set MISP_API_KEY or unset MISP_URL")
		return
	}
	if u.Scheme == "http" {
		allow, err := parseBool(env("MISP_ALLOW_INSECURE_HTTP", "false"))
		if err != nil || !allow {
			cfg.disable("misp", "insecure_url", "url", mispURL,
				"hint", "the API key would be sent in clear text; use https or set "+
					"MISP_ALLOW_INSECURE_HTTP=true for a network-policy-protected in-cluster MISP")
			return
		}
		slog.Warn("MISP over plain HTTP: the API key is sent unencrypted", "url", mispURL)
	}
	lookback := env("MISP_LOOKBACK", "7d")
	if !mispLookback.MatchString(lookback) {
		cfg.disable("misp", "invalid_lookback", "value", lookback)
		return
	}
	maxPages, err1 := strconv.Atoi(env("MISP_MAX_PAGES", strconv.Itoa(misp.DefaultMaxPages)))
	pageSize, err2 := strconv.Atoi(env("MISP_PAGE_SIZE", strconv.Itoa(misp.DefaultPageSize)))
	if err1 != nil || err2 != nil || maxPages < 1 || maxPages > 1000 || pageSize < 100 || pageSize > 50000 {
		cfg.disable("misp", "invalid_limits", "max_pages", env("MISP_MAX_PAGES", ""),
			"page_size", env("MISP_PAGE_SIZE", ""))
		return
	}

	client := misp.NewClient(mispURL, key)
	client.SetLimits(cfg.maxBodyBytes, maxPages, pageSize)
	cfg.sources = append(cfg.sources, source{
		name:     "misp",
		endpoint: u.Scheme + "://" + u.Host,
		fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
			attrs, err := client.FetchAllAttributes(ctx, misp.SearchRequest{
				Types: []string{
					misp.TypeDomain, misp.TypeHostname,
					misp.TypeIPDst, misp.TypeIPSrc,
					misp.TypeURL, misp.TypeMD5, misp.TypeSHA256, misp.TypeJA3,
					misp.TypeX509SHA1, misp.TypeX509SHA256,
				},
				Published: true,
				Timestamp: lookback,
				ToIDs:     true,
			})
			return mispToIndicators(attrs), err
		},
	})
	slog.Info("source configured", "source", "misp", "url", mispURL)
}

func (cfg *config) configureAbuseCH(env func(string, string) string) {
	// abuse.ch feeds (ThreatFox / URLhaus / Feodo) dropped their CC0
	// dedication in 2025; the current terms of use restrict free access to
	// non-commercial use (commercial use needs a paid Spamhaus subscription).
	// They are ON by default for the project's primary home/non-commercial
	// use, and disabled when COMMERCIAL_MODE=true so a commercial deployment
	// ships clean. See COMPLIANCE.md.
	if cfg.commercial {
		slog.Info("COMMERCIAL_MODE on: abuse.ch feeds (ThreatFox/URLhaus/Feodo) disabled (non-commercial terms)")
		for _, name := range []string{"threatfox", "urlhaus", "feodo"} {
			cfg.disabled = append(cfg.disabled, disabledSource{name: name, reason: "commercial_mode"})
		}
		return
	}
	slog.Warn("abuse.ch feeds enabled (ThreatFox/URLhaus/Feodo): non-commercial use only — set COMMERCIAL_MODE=true to disable for commercial deployments")

	opts := []abusech.Option{abusech.WithMaxBodyBytes(cfg.maxBodyBytes)}
	key := env("ABUSECH_AUTH_KEY", "")
	if key != "" {
		opts = append(opts, abusech.WithAuthKey(key))
	}

	// ThreatFox and URLhaus document the Auth-Key header as mandatory on
	// every API request; without a key every call would fail, so they are
	// disabled up front rather than counted as failing every cycle.
	if key == "" {
		cfg.disable("threatfox", "missing_auth_key", "hint", "set ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/)")
		cfg.disable("urlhaus", "missing_auth_key", "hint", "set ABUSECH_AUTH_KEY (free key from https://auth.abuse.ch/)")
	} else {
		tfDays, err := strconv.Atoi(env("THREATFOX_DAYS", "7"))
		if err != nil || tfDays < abusech.ThreatFoxMinDays || tfDays > abusech.ThreatFoxMaxDays {
			cfg.disable("threatfox", "invalid_days", "value", env("THREATFOX_DAYS", ""),
				"allowed", fmt.Sprintf("%d-%d", abusech.ThreatFoxMinDays, abusech.ThreatFoxMaxDays))
		} else {
			tfClient := abusech.NewThreatFoxClient(opts...)
			cfg.sources = append(cfg.sources, source{
				name:     "threatfox",
				endpoint: abusech.ThreatFoxURL,
				fetch:    func(ctx context.Context) ([]ioc.Indicator, error) { return tfClient.Fetch(ctx, tfDays) },
			})
		}

		uhLimit, err := strconv.Atoi(env("URLHAUS_LIMIT", "1000"))
		if err != nil || uhLimit < 1 || uhLimit > abusech.URLhausMaxLimit {
			cfg.disable("urlhaus", "invalid_limit", "value", env("URLHAUS_LIMIT", ""),
				"allowed", fmt.Sprintf("1-%d", abusech.URLhausMaxLimit))
		} else {
			uhClient := abusech.NewURLhausClient(opts...)
			cfg.sources = append(cfg.sources, source{
				name:     "urlhaus",
				endpoint: abusech.URLhausURL,
				fetch:    func(ctx context.Context) ([]ioc.Indicator, error) { return uhClient.Fetch(ctx, uhLimit) },
			})
		}
	}

	feClient := abusech.NewFeodoClient(opts...)
	cfg.sources = append(cfg.sources, source{name: "feodo", endpoint: abusech.FeodoURL, fetch: feClient.Fetch})
}

// parseCommercialMode accepts the documented spellings. Anything else is an
// error and reported as ON: this flag fails closed.
func parseCommercialMode(v string) (bool, error) {
	if strings.TrimSpace(v) == "" {
		return false, nil
	}
	b, err := parseBool(v)
	if err != nil {
		return true, err
	}
	return b, nil
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%q is not one of true/1/yes/on or false/0/no/off", v)
	}
}

func (cfg config) sourceNames() []string {
	names := make([]string, 0, len(cfg.sources))
	for _, s := range cfg.sources {
		names = append(names, s.name)
	}
	return names
}
