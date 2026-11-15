package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
)

const (
	// DefaultAlertRetention matches the 30-day retention the project
	// promises for per-device data.
	DefaultAlertRetention = 30 * 24 * time.Hour
	// DefaultMaxAlerts bounds the table (a stored alert is about 1 KiB).
	DefaultMaxAlerts = 20000
	// DefaultListLimit is what GET /alerts returns without ?limit=, the
	// same ceiling the in-memory ring had.
	DefaultListLimit = 1000
	// MaxListLimit caps ?limit=.
	MaxListLimit = 5000
	// pruneEvery is how many inserts pass between size checks, so the table
	// overshoots the cap by at most this much.
	pruneEvery = 100
)

// Alerts is the persisted alert history. Safe for concurrent use.
type Alerts struct {
	db      *sql.DB
	maxAge  time.Duration
	maxRows int
	now     func() time.Time

	mu          sync.Mutex
	sinceChecks int
}

// Alerts returns the alert history, keeping alerts for maxAge and at most
// maxRows of them (defaults for values <= 0).
func (s *Store) Alerts(maxAge time.Duration, maxRows int) *Alerts {
	if maxAge <= 0 {
		maxAge = DefaultAlertRetention
	}
	if maxRows <= 0 {
		maxRows = DefaultMaxAlerts
	}
	return &Alerts{db: s.db, maxAge: maxAge, maxRows: maxRows, now: time.Now}
}

// Add records one alert (single-signal or composite). Retention is measured
// from when the engine recorded it, never from the alert's own timestamp,
// which comes from sensors and can lie.
func (a *Alerts) Add(al detection.Alert) error {
	body, err := json.Marshal(al)
	if err != nil {
		return fmt.Errorf("encode alert: %w", err)
	}
	if _, err := a.db.Exec(
		`INSERT OR IGNORE INTO alerts (id, recorded_at, sev_rank, body) VALUES (?, ?, ?, ?)`,
		al.ID, unixMilli(a.now()), severityRank(al.Severity), body); err != nil {
		storeErrors.WithLabelValues("alert_insert").Inc()
		return fmt.Errorf("insert alert: %w", err)
	}

	a.mu.Lock()
	a.sinceChecks++
	due := a.sinceChecks >= pruneEvery
	if due {
		a.sinceChecks = 0
	}
	a.mu.Unlock()
	if due {
		if _, err := a.Prune(); err != nil {
			slog.Warn("alert retention failed", "error", err)
		}
	}
	return nil
}

// Prune applies retention: alerts older than the retention period go, then,
// over the row cap, the least severe and oldest go first — so a flood of
// low-severity noise cannot push yesterday's critical detection out of the
// history.
func (a *Alerts) Prune() (int64, error) {
	res, err := a.db.Exec(`DELETE FROM alerts WHERE recorded_at < ?`,
		unixMilli(a.now().Add(-a.maxAge)))
	if err != nil {
		storeErrors.WithLabelValues("alert_prune").Inc()
		return 0, err
	}
	aged, _ := res.RowsAffected()

	var n int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM alerts`).Scan(&n); err != nil {
		storeErrors.WithLabelValues("alert_prune").Inc()
		return aged, err
	}
	if n <= a.maxRows {
		return aged, nil
	}
	res, err = a.db.Exec(`DELETE FROM alerts WHERE seq IN (
		SELECT seq FROM alerts ORDER BY sev_rank ASC, seq ASC LIMIT ?)`, n-a.maxRows)
	if err != nil {
		storeErrors.WithLabelValues("alert_prune").Inc()
		return aged, err
	}
	over, _ := res.RowsAffected()
	return aged + over, nil
}

// Recent returns up to limit alerts, most recently recorded first.
func (a *Alerts) Recent(limit int) ([]detection.Alert, error) {
	rows, err := a.db.Query(`SELECT body FROM alerts ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		storeErrors.WithLabelValues("alert_read").Inc()
		return nil, err
	}
	defer rows.Close()
	out := make([]detection.Alert, 0, min(limit, 256))
	for rows.Next() {
		var body []byte
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var al detection.Alert
		if err := json.Unmarshal(body, &al); err != nil {
			storeErrors.WithLabelValues("alert_decode").Inc()
			continue
		}
		out = append(out, al)
	}
	return out, rows.Err()
}

// ByID returns the stored alert with that id.
func (a *Alerts) ByID(id string) (detection.Alert, bool) {
	var body []byte
	err := a.db.QueryRow(`SELECT body FROM alerts WHERE id = ?`, id).Scan(&body)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			storeErrors.WithLabelValues("alert_read").Inc()
		}
		return detection.Alert{}, false
	}
	var al detection.Alert
	if err := json.Unmarshal(body, &al); err != nil {
		return detection.Alert{}, false
	}
	return al, true
}

// HandleList serves GET /alerts?limit=N: a JSON array, newest first.
func (a *Alerts) HandleList(w http.ResponseWriter, r *http.Request) {
	limit := DefaultListLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = min(n, MaxListLimit)
	}
	alerts, err := a.Recent(limit)
	if err != nil {
		slog.Error("reading alerts failed", "error", err)
		writeJSONError(w, http.StatusInternalServerError, "alerts unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(alerts)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
