package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/guard"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/migel9090/netSoldier/libs/indicator"
)

// The quarantine API: an operator inspects a fetch the volume guard held
// back and releases or discards it.
//
//	GET  /quarantine                    every held fetch, without rows
//	GET  /quarantine/{source}           one held fetch, its rows paged:
//	                                    ?offset=0&limit=100 (at most 1000),
//	                                    &new=true for rows the store lacks
//	POST /quarantine/{source}/release   body {"id": "<held id>"}: apply it
//	POST /quarantine/{source}/discard   forget it; body {"id": ...} optional
//
// Every call needs "Authorization: Bearer <THREAT_INTEL_API_KEY>", compared
// in constant time, like the other services' operator endpoints. Without a
// configured key the API answers 403: a release applies thousands of
// indicators as household blocks, so it is never open. A release or discard
// also needs X-Netsoldier-Actor naming the operator — the web UI's proxy
// sets it from the signed-in session — under the rules the killswitch and
// the detection-engine apply (events.ParseActor), and is logged with that
// name. The release must name the id that was inspected, so a fetch that
// replaced it in the meantime is never released unseen (409).
type operatorAPI struct {
	key     string
	guard   *guard.Manager
	store   *ioc.Store
	ready   *readiness
	sources map[string]bool
}

const (
	maxOperatorBody   = 4 << 10
	defaultPageLimit  = 100
	maxPageLimit      = 1000
	errAPIKeyDisabled = "operator API disabled: THREAT_INTEL_API_KEY is not set"
)

func (o *operatorAPI) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /quarantine", o.auth(false, o.list))
	mux.HandleFunc("GET /quarantine/{source}", o.auth(false, o.get))
	mux.HandleFunc("POST /quarantine/{source}/release", o.auth(true, o.release))
	mux.HandleFunc("POST /quarantine/{source}/discard", o.auth(true, o.discard))
}

type operatorHandler func(w http.ResponseWriter, r *http.Request, actor string)

func (o *operatorAPI) auth(write bool, next operatorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o.key == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": errAPIKeyDisabled})
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), []byte(o.key)) != 1 {
			slog.Warn("rejected unauthenticated operator request",
				"path", indicator.Text(r.URL.Path, 128), "method", r.Method, "remote", r.RemoteAddr)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		actor := ""
		if write {
			a, err := events.ParseActor(r.Header.Values(events.ActorHeader))
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			actor = a
		}
		next(w, r, actor)
	}
}

// source resolves {source}: only an enabled source can have a held fetch.
func (o *operatorAPI) source(w http.ResponseWriter, r *http.Request) (string, bool) {
	name := r.PathValue("source")
	if !o.sources[name] {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such source"})
		return "", false
	}
	return name, true
}

func (o *operatorAPI) list(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, http.StatusOK, map[string]any{"quarantined": o.guard.Held(), "limits": limitsJSON(o.guard.Limits())})
}

type heldRow struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	Source     string   `json:"source,omitempty"`
	Threat     string   `json:"threat,omitempty"`
	Confidence int      `json:"confidence"`
	Tags       []string `json:"tags,omitempty"`
	New        bool     `json:"new"` // not in the store now: applying it adds this indicator
}

func (o *operatorAPI) get(w http.ResponseWriter, r *http.Request, _ string) {
	name, ok := o.source(w, r)
	if !ok {
		return
	}
	h, ok := o.guard.Get(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": guard.ErrNotHeld.Error()})
		return
	}
	q := r.URL.Query()
	offset, err1 := atoiDefault(q.Get("offset"), 0)
	limit, err2 := atoiDefault(q.Get("limit"), defaultPageLimit)
	onlyNew := q.Get("new") == "true"
	if err1 != nil || err2 != nil || offset < 0 || limit < 1 || limit > maxPageLimit {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "offset must be >= 0 and limit between 1 and " + strconv.Itoa(maxPageLimit)})
		return
	}

	byType, newByType := map[string]int{}, map[string]int{}
	page := []heldRow{}
	matched := 0
	for _, ind := range h.Rows {
		isNew := !o.store.Contains(ind.Key())
		byType[ind.Type]++
		if isNew {
			newByType[ind.Type]++
		}
		if onlyNew && !isNew {
			continue
		}
		if matched >= offset && len(page) < limit {
			page = append(page, heldRow{Type: ind.Type, Value: ind.Value, Source: ind.Source,
				Threat: ind.Threat, Confidence: ind.Confidence, Tags: ind.Tags, New: isNew})
		}
		matched++
	}
	rows := h.Rows
	h.Rows = nil
	writeJSON(w, http.StatusOK, map[string]any{
		"held": h, "rows": len(rows), "by_type": byType, "new_by_type": newByType,
		"offset": offset, "limit": limit, "matched": matched, "indicators": page,
	})
}

type decisionRequest struct {
	ID string `json:"id"`
}

func readDecision(w http.ResponseWriter, r *http.Request, required bool) (string, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxOperatorBody+1))
	if err != nil || len(body) > maxOperatorBody {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body unreadable or too large"})
		return "", false
	}
	var req decisionRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON: {\"id\": \"<held id>\"}"})
			return "", false
		}
	}
	if required && req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "the held fetch's id is required (see GET /quarantine/{source})"})
		return "", false
	}
	return req.ID, true
}

func (o *operatorAPI) release(w http.ResponseWriter, r *http.Request, actor string) {
	name, ok := o.source(w, r)
	if !ok {
		return
	}
	id, ok := readDecision(w, r, true)
	if !ok {
		return
	}
	rel, err := o.guard.Release(name, id)
	if guardError(w, err) {
		return
	}
	if err != nil {
		storePersistErrors.Inc()
		slog.Error("indicator database write failed during a release", "source", name, "error", err)
	}
	h := rel.Held
	quarantineResolved.WithLabelValues(name, actionReleased).Inc()
	quarantined.WithLabelValues(name).Set(0)
	quarantinedIndicators.WithLabelValues(name).Set(0)
	volumeBaseline.WithLabelValues(name).Set(float64(rel.Baseline))
	indicatorsDropped.WithLabelValues(name).Add(float64(rel.Stats.Dropped))
	if !h.Partial {
		syncLastSuccess.WithLabelValues(name).Set(float64(h.Started.Unix()))
		indicatorsFetched.WithLabelValues(name).Set(float64(rel.Stats.Accepted))
	}
	storeSize.Set(float64(o.store.Len()))
	o.ready.trust()
	slog.Warn("quarantine released by operator: the held fetch is applied",
		"actor", actor, "source", name, "id", h.ID, "reason", h.Reason, "size", h.Size,
		"applied", rel.Stats.Accepted, "dropped", rel.Stats.Dropped, "new_baseline", rel.Baseline,
		"held_at", h.HeldAt, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{
		"action": actionReleased, "actor": actor, "source": name, "id": h.ID,
		"applied": rel.Stats.Accepted, "dropped": rel.Stats.Dropped, "baseline": rel.Baseline,
	})
}

func (o *operatorAPI) discard(w http.ResponseWriter, r *http.Request, actor string) {
	name, ok := o.source(w, r)
	if !ok {
		return
	}
	id, ok := readDecision(w, r, false)
	if !ok {
		return
	}
	if cur, held := o.guard.Get(name); held && id != "" && id != cur.ID {
		guardError(w, guard.ErrStale)
		return
	}
	h, err := o.guard.Discard(name)
	if guardError(w, err) {
		return
	}
	if err != nil {
		storePersistErrors.Inc()
		slog.Error("indicator database write failed during a discard", "source", name, "error", err)
	}
	quarantineResolved.WithLabelValues(name, actionDiscarded).Inc()
	quarantined.WithLabelValues(name).Set(0)
	quarantinedIndicators.WithLabelValues(name).Set(0)
	slog.Warn("quarantine discarded by operator: the previous set stays, the next fetch is judged afresh",
		"actor", actor, "source", name, "id", h.ID, "reason", h.Reason, "size", h.Size,
		"held_at", h.HeldAt, "remote", r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{
		"action": actionDiscarded, "actor": actor, "source": name, "id": h.ID,
	})
}

// guardError answers the guard's operator errors and reports whether it
// did; it leaves nil and persistence errors (the operation is done in
// memory) to the caller.
func guardError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, guard.ErrNotHeld):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return true
	case errors.Is(err, guard.ErrStale):
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": err.Error() + ": inspect GET /quarantine/{source} again and use the current id"})
		return true
	}
	return false
}

func limitsJSON(l guard.Limits) map[string]any {
	return map[string]any{
		"growth_factor": l.GrowthFactor, "shrink_factor": l.ShrinkFactor,
		"min_change": l.MinChange, "first_sync_max": l.FirstSyncMax, "history": guard.HistoryLen,
	}
}

func atoiDefault(s string, def int) (int, error) {
	if s == "" {
		return def, nil
	}
	return strconv.Atoi(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck // the client went away
}
