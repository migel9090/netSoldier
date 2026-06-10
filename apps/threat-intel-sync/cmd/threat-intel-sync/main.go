package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/abusech"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/export"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/misp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/spamhaus"
)

type source struct {
	name  string
	fetch func(context.Context) ([]ioc.Indicator, error)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	store := ioc.NewStore()
	sources := configureSources()

	syncInterval := parseDuration(envOr("SYNC_INTERVAL", "6h"), 6*time.Hour)
	go runSyncLoop(ctx, store, sources, syncInterval)

	addr := envOr("LISTEN_ADDR", ":8083")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("GET /export/adguard", export.HandleAdGuard(store))
	mux.HandleFunc("GET /export/suricata/domains", export.HandleSuricataDataset(store, true, ioc.TypeDomain))
	mux.HandleFunc("GET /export/suricata/ips", export.HandleSuricataDataset(store, false, ioc.TypeIP))
	mux.HandleFunc("GET /export/suricata/domains.json", export.HandleSuricataJSONDataset(store, "domain", ioc.TypeDomain))
	mux.HandleFunc("GET /export/suricata/ips.json", export.HandleSuricataJSONDataset(store, "ip", ioc.TypeIP))
	mux.HandleFunc("GET /export/suricata/md5", export.HandleSuricataDataset(store, false, ioc.TypeMD5))
	mux.HandleFunc("GET /export/suricata/sha256", export.HandleSuricataDataset(store, false, ioc.TypeSHA256))
	mux.HandleFunc("GET /export/zeek/intel.dat", export.HandleZeekIntel(store))
	mux.HandleFunc("GET /export/json", export.HandleJSON(store))

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting threat-intel-sync", "addr", addr, "sync_interval", syncInterval)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server failed", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down", "ioc_count", store.Len())

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("shutdown error", "error", err)
	}
}

func configureSources() []source {
	var sources []source

	if mispURL := os.Getenv("MISP_URL"); mispURL != "" {
		key := envOr("MISP_API_KEY", "")
		if key == "" {
			slog.Error("MISP_URL set but MISP_API_KEY is empty")
			os.Exit(1)
		}
		client := misp.NewClient(mispURL, key)
		sources = append(sources, source{
			name: "misp",
			fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
				attrs, err := client.FetchAllAttributes(ctx, misp.SearchRequest{
					Types: []string{
						misp.TypeDomain, misp.TypeHostname,
						misp.TypeIPDst, misp.TypeIPSrc,
						misp.TypeURL, misp.TypeMD5, misp.TypeSHA256, misp.TypeJA3,
					},
					Published: true,
					Timestamp: envOr("MISP_LOOKBACK", "7d"),
					ToIDs:     true,
				})
				if err != nil {
					return nil, err
				}
				return mispToIndicators(attrs), nil
			},
		})
		slog.Info("source configured", "source", "misp", "url", mispURL)
	}

	tfClient := abusech.NewThreatFoxClient()
	tfDays := parseIntOr(envOr("THREATFOX_DAYS", "7"), 7)
	sources = append(sources, source{
		name: "threatfox",
		fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
			return tfClient.Fetch(ctx, tfDays)
		},
	})

	uhClient := abusech.NewURLhausClient()
	uhLimit := parseIntOr(envOr("URLHAUS_LIMIT", "1000"), 1000)
	sources = append(sources, source{
		name: "urlhaus",
		fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
			return uhClient.Fetch(ctx, uhLimit)
		},
	})

	feClient := abusech.NewFeodoClient()
	sources = append(sources, source{
		name: "feodo",
		fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
			return feClient.Fetch(ctx)
		},
	})

	spClient := spamhaus.NewClient()
	sources = append(sources, source{
		name: "spamhaus",
		fetch: func(ctx context.Context) ([]ioc.Indicator, error) {
			return spClient.FetchAll(ctx)
		},
	})

	slog.Info("sources ready", "count", len(sources))
	return sources
}

func runSyncLoop(ctx context.Context, store *ioc.Store, sources []source, interval time.Duration) {
	slog.Info("sync loop started", "interval", interval, "sources", len(sources))
	syncOnce(ctx, store, sources)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce(ctx, store, sources)
		}
	}
}

func syncOnce(ctx context.Context, store *ioc.Store, sources []source) {
	slog.Info("sync cycle starting")
	for _, src := range sources {
		indicators, err := src.fetch(ctx)
		if err != nil {
			slog.Error("source failed", "source", src.name, "error", err)
			continue
		}
		store.UpsertAll(indicators)
		slog.Info("source synced", "source", src.name, "fetched", len(indicators), "store_total", store.Len())
	}
	slog.Info("sync cycle complete", "store_total", store.Len())
}

func mispToIndicators(attrs []misp.Attribute) []ioc.Indicator {
	indicators := make([]ioc.Indicator, 0, len(attrs))
	for _, a := range attrs {
		iocType := mapMISPType(a.Type)
		if iocType == "" {
			continue
		}
		var tags []string
		for _, t := range a.Tags {
			tags = append(tags, t.Name)
		}
		indicators = append(indicators, ioc.Indicator{
			Type:      iocType,
			Value:     a.Value,
			Source:    "misp",
			Threat:    a.Comment,
			FirstSeen: a.Time(),
			Tags:      tags,
		})
	}
	return indicators
}

func mapMISPType(t string) string {
	switch t {
	case misp.TypeDomain, misp.TypeHostname:
		return ioc.TypeDomain
	case misp.TypeIPDst, misp.TypeIPSrc:
		return ioc.TypeIP
	case misp.TypeURL:
		return ioc.TypeURL
	case misp.TypeMD5:
		return ioc.TypeMD5
	case misp.TypeSHA256:
		return ioc.TypeSHA256
	case misp.TypeJA3:
		return ioc.TypeJA3
	default:
		return ""
	}
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

func parseIntOr(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}
