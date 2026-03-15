package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/abusech"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/misp"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	store := ioc.NewStore()
	configureSources(store)

	addr := envOr("LISTEN_ADDR", ":8083")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("starting threat-intel-sync", "addr", addr)
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

func configureSources(store *ioc.Store) {
	if url := os.Getenv("MISP_URL"); url != "" {
		key := envOr("MISP_API_KEY", "")
		if key == "" {
			slog.Error("MISP_URL set but MISP_API_KEY is empty")
			os.Exit(1)
		}
		_ = misp.NewClient(url, key)
		slog.Info("source configured", "source", "misp", "url", url)
	}

	_ = abusech.NewThreatFoxClient()
	slog.Info("source configured", "source", "threatfox")

	_ = abusech.NewURLhausClient()
	slog.Info("source configured", "source", "urlhaus")

	_ = abusech.NewFeodoClient()
	slog.Info("source configured", "source", "feodo")

	_ = store
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
