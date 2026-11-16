package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/actions"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/enforce"
	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/policy"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// responseWait is how long a mutation waits for its driver before
// answering with the action as it stands (202). It stays below the web
// UI's upstream timeout so the operator sees an outcome rather than a
// proxy error; the operation itself is not cut short by it.
const responseWait = 9 * time.Second

// actorHeader names who is acting. The web UI's proxy sets it from the
// signed-in session and never forwards a client's value (contract §7);
// identity fields in request bodies are ignored.
const actorHeader = "X-Netsoldier-Actor"

// List bounds (contract §4).
const (
	defaultListLimit = 100
	maxListLimit     = 500
)

type server struct {
	pol          *policy.Policy
	engine       *enforce.Engine
	store        *actions.Store
	ledger       *evaluationLedger
	responseWait time.Duration
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc(healthRoute, handleHealthz)
	mux.Handle(metricsRoute, promhttp.Handler())
	mux.HandleFunc("GET /policy", s.handleGetPolicy)
	mux.HandleFunc("GET /allowlist", s.handleGetAllowlist)
	mux.HandleFunc(evaluateRoute, s.handleEvaluate)
	mux.HandleFunc("GET /actions/pending", s.list(s.store.ListPending))
	mux.HandleFunc("GET /actions/active", s.list(s.store.ListEnforced))
	mux.HandleFunc("GET /actions/failed", s.list(s.store.ListFailed))
	mux.HandleFunc("GET /actions/history", s.handleHistory)
	mux.HandleFunc("GET /actions/{id}", s.handleGetAction)
	mux.HandleFunc("POST /actions/{id}/approve", s.handleApprove)
	mux.HandleFunc("POST /actions/{id}/reject", s.handleReject)
	mux.HandleFunc("POST /actions/{id}/revert", s.handleRevert)
	mux.HandleFunc("GET /audit", s.handleAudit)
	mux.HandleFunc(agentRoute, s.handleAgentPoll)
	return mux
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) handleGetPolicy(w http.ResponseWriter, _ *http.Request) {
	pol := s.pol
	hold, _ := pol.AutoBlockHold()
	writeJSON(w, http.StatusOK, map[string]any{
		"auto_min_confidence": pol.AutoMinConfidence,
		"auto_min_severity":   pol.AutoMinSeverity,
		"auto_min_signals":    pol.AutoMinSignals,
		// Always true: auto-block needs a known-bad signal that attests
		// the blocked domain. Kept for readers of the 1.x response.
		"auto_require_known_bad":      true,
		"auto_action_type":            events.ActionDNSSinkhole,
		"pend_min_confidence":         pol.PendMinConfidence,
		"pend_min_severity":           pol.PendMinSeverity,
		"default_ttl":                 pol.DefaultTTL,
		"default_action":              pol.DefaultAction,
		"auto_block":                  autoBlockSetting(pol), // off by choice, told apart from held back
		"auto_block_allowed":          hold == "",
		"auto_block_disabled_reason":  hold,
		"allowlist_entries":           pol.Allowlist.Len(),
		"rejected_protection_entries": len(pol.RejectedEntries),
		// What an operator may choose in an approve right now.
		"available_action_types": s.engine.Available(),
		"pending_ttl_seconds":    int(s.store.PendingTTL().Seconds()),
	})
}

func (s *server) handleGetAllowlist(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"macs": s.pol.Allowlist.MACs(),
		"ips":  s.pol.Allowlist.IPs(),
	})
}

// handleEvaluate decides on one detection event.
//
// The event is validated before anything else looks at it: a detection that
// does not say what it is, who it is about, or what evidence it rests on is
// refused with the reasons, not half-evaluated. It is then evaluated at most
// once per event id (see evaluationLedger). Enforcement acts on the event's
// typed target only, never on its domain or summary.
func (s *server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var ev events.DetectionEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := ev.Validate(); err != nil {
		rejectedRequests.WithLabelValues("invalid_event").Inc()
		slog.Warn("rejected invalid detection event", "id", ev.ID, "error", err)
		writeJSONError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	digest := sha256.Sum256(body)
	entry, first, err := s.ledger.claim(ev.ID, digest)
	if err != nil {
		slog.Error("evaluation ledger unavailable", "id", ev.ID, "error", err)
		writeJSONError(w, http.StatusServiceUnavailable, "evaluation ledger unavailable; retry")
		return
	}
	if !first {
		s.respondToRepeat(w, r, entry, ev.ID, digest)
		return
	}
	finished := false
	defer func() {
		if !finished {
			s.ledger.abandon(ev.ID, entry)
		}
	}()

	decision := s.pol.Evaluate(ev)
	if decision.Withheld != "" {
		autoBlockWithheld.WithLabelValues(decision.Withheld).Inc()
		slog.Warn("auto-block withheld: the detection met every auto-block condition, "+
			"but automatic enforcement is disabled for this service",
			"id", ev.ID, "withheld", decision.Withheld, "reason", decision.Reason)
	}

	var actionID string
	if decision.Action == "auto_block" || decision.Action == "pending" {
		res, err := s.engine.Submit(ev, enforce.Decision{
			Auto:       decision.Action == "auto_block",
			ActionType: decision.ActionType,
			PolicyRule: decision.Reason,
			TTLSeconds: decision.TTLSeconds,
		})
		if err != nil {
			slog.Error("could not record the decision", "id", ev.ID, "error", err)
			writeJSONError(w, http.StatusServiceUnavailable, "could not record the decision; retry")
			return
		}
		actionID = res.Record.ID
	}
	if err := s.ledger.finish(ev.ID, entry, digest, decision, actionID); err != nil {
		// The action is recorded; a repeat is still deduplicated by its
		// detection id, it only gets re-evaluated.
		slog.Error("evaluation ledger write failed", "id", ev.ID, "error", err)
	}
	finished = true

	if actionID != "" {
		s.engine.Wait(r.Context(), actionID, s.responseWait)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision": decision,
		"action":   s.actionOrNil(actionID),
	})
}

// respondToRepeat answers a second delivery of an event id with the first
// delivery's decision and the current state of its action, creating nothing.
// The same id with different content is not a repeat but a producer reusing
// ids, which would silently swallow a detection; that is refused.
func (s *server) respondToRepeat(w http.ResponseWriter, r *http.Request, entry *evaluation, id string,
	digest [sha256.Size]byte) {
	if entry.digest != digest {
		rejectedRequests.WithLabelValues("event_id_reused").Inc()
		slog.Error("detection event id reused with different content — refusing it; "+
			"the producer is not generating unique ids", "id", id)
		writeJSONError(w, http.StatusConflict,
			"event id "+id+" was already evaluated with different content")
		return
	}
	select {
	case <-entry.done:
	case <-r.Context().Done():
		return
	}
	decision, actID, ok := s.ledger.outcome(entry)
	if !ok {
		writeJSONError(w, http.StatusServiceUnavailable,
			"the first delivery of this event did not complete; retry")
		return
	}
	duplicateEvents.Inc()
	slog.Info("repeated detection event answered from the ledger", "id", id, "action_id", actID)
	if actID != "" {
		s.engine.Wait(r.Context(), actID, s.responseWait)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"decision":  decision,
		"action":    s.actionOrNil(actID),
		"duplicate": true,
	})
}

func (s *server) actionOrNil(id string) *events.EnforcementAction {
	if id == "" {
		return nil
	}
	rec, err := s.store.Get(id)
	if err != nil {
		return nil
	}
	a := rec.Action()
	return &a
}

func (s *server) list(fetch func() ([]actions.Record, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		recs, err := fetch()
		if err != nil {
			s.storeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, wire(recs))
	}
}

func (s *server) handleHistory(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	recs, err := s.store.ListHistory(limit)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire(recs))
}

// wire returns the contract form of a list: a JSON array, never null.
func wire(recs []actions.Record) []events.EnforcementAction {
	out := make([]events.EnforcementAction, len(recs))
	for i, r := range recs {
		out[i] = r.Action()
	}
	return out
}

func limitParam(r *http.Request) (int, error) {
	v := r.URL.Query().Get("limit")
	if v == "" {
		return defaultListLimit, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("limit must be a positive integer, got %q", v)
	}
	return min(n, maxListLimit), nil
}

func (s *server) handleGetAction(w http.ResponseWriter, r *http.Request) {
	rec, err := s.store.Get(r.PathValue("id"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec.Action())
}

// actorFrom returns the operator named by X-Netsoldier-Actor. It must be
// present exactly once, printable ASCII of 1–64 characters (what the web
// UI accepts at sign-in), and not one of the names this service uses for
// itself — an operator called "ttl" would make a manual revert look like
// the reaper's.
func actorFrom(r *http.Request) (string, error) {
	vals := r.Header.Values(actorHeader)
	if len(vals) != 1 {
		return "", fmt.Errorf("exactly one %s header naming the operator is required", actorHeader)
	}
	a := vals[0]
	if len(a) < 1 || len(a) > 64 {
		return "", fmt.Errorf("%s must be 1-64 characters", actorHeader)
	}
	for i := 0; i < len(a); i++ {
		if a[i] < 0x20 || a[i] > 0x7e {
			return "", fmt.Errorf("%s must be printable ASCII", actorHeader)
		}
	}
	if actions.IsSystemActor(a) {
		return "", fmt.Errorf("%s %q is reserved for the controller itself", actorHeader, a)
	}
	return a, nil
}

// decodeBody decodes an optional JSON body; an empty body is fine.
func decodeBody(r *http.Request, dst any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	if len(b) == 0 {
		return nil
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("invalid body: %w", err)
	}
	return nil
}

func (s *server) operatorRequest(w http.ResponseWriter, r *http.Request, body any) (string, bool) {
	actor, err := actorFrom(r)
	if err != nil {
		rejectedRequests.WithLabelValues("no_actor").Inc()
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	if err := decodeBody(r, body); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return actor, true
}

// handleApprove approves a pending action and answers with it once the
// driver has answered: active, or apply_failed (200 either way — callers
// must read state). An optional action_type chooses the enforcement; it
// must be one the controller can carry out now. 202 means the driver has
// not answered within responseWait and the action is still approved.
func (s *server) handleApprove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ActionType string `json:"action_type"`
	}
	actor, ok := s.operatorRequest(w, r, &req)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if _, err := s.engine.Approve(id, actor, req.ActionType); err != nil {
		s.writeErr(w, err)
		return
	}
	s.answer(w, r, id, false)
}

func (s *server) handleReject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	actor, ok := s.operatorRequest(w, r, &req)
	if !ok {
		return
	}
	if req.Reason == "" {
		req.Reason = "rejected by " + actor
	}
	rec, err := s.engine.Reject(r.PathValue("id"), actor, req.Reason)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec.Action())
}

// handleRevert lifts an enforcement and answers with the action: reverted
// (200), revert_failed — still enforced — with 502, or, while the revert is
// still under way (the driver has not answered within responseWait, or the
// netagent has not confirmed the release yet), the action as it stands with
// 202.
func (s *server) handleRevert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason string `json:"reason"`
	}
	actor, ok := s.operatorRequest(w, r, &req)
	if !ok {
		return
	}
	if req.Reason == "" {
		req.Reason = "reverted by " + actor
	}
	id := r.PathValue("id")
	if _, err := s.engine.Revert(r.Context(), id, actor, req.Reason); err != nil {
		s.writeErr(w, err)
		return
	}
	s.answer(w, r, id, true)
}

// answer waits for the action's driver call and writes the action.
//
// "Still under way" is decided before the state is read: a retried revert
// of a revert_failed action stays revert_failed until the retry answers, so
// reading the state first reported the previous attempt's failure for a
// retry that had not finished.
func (s *server) answer(w http.ResponseWriter, r *http.Request, id string, revert bool) {
	settled := s.engine.Wait(r.Context(), id, s.responseWait)
	rec, err := s.store.Get(id)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	switch {
	case !settled || rec.Op != actions.OpNone:
		writeJSON(w, http.StatusAccepted, rec.Action())
	case revert && rec.State == events.StateRevertFailed:
		writeJSON(w, http.StatusBadGateway, actionResponse{rec.Action(),
			"revert failed, the enforcement is STILL IN FORCE and is being retried: " + rec.FailureReason})
	default:
		writeJSON(w, http.StatusOK, rec.Action())
	}
}

// actionResponse is an action with the reason a request did not do what
// it asked for; callers that understand actions read the state, others the
// error.
type actionResponse struct {
	events.EnforcementAction
	Error string `json:"error,omitempty"`
}

func (s *server) writeErr(w http.ResponseWriter, err error) {
	var c *actions.ConflictError
	var u *enforce.UnavailableError
	switch {
	case errors.Is(err, actions.ErrNotFound):
		writeJSONError(w, http.StatusNotFound, "not found")
	case errors.As(err, &c):
		writeJSON(w, http.StatusConflict, actionResponse{c.Current.Action(), c.Msg})
	case errors.As(err, &u):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":                  u.Error(),
			"available_action_types": u.Available,
		})
	default:
		s.storeError(w, err)
	}
}

func (s *server) storeError(w http.ResponseWriter, err error) {
	slog.Error("request failed", "error", err)
	writeJSONError(w, http.StatusInternalServerError, "internal error")
}

// handleAudit serves the local audit log, newest first: ?limit= (default
// 100, max 500), ?before=<seq> to page, ?action_id= for one action.
func (s *server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, err := limitParam(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	q := actions.AuditQuery{Limit: limit, ActionID: r.URL.Query().Get("action_id")}
	if v := r.URL.Query().Get("before"); v != "" {
		if q.Before, err = strconv.ParseInt(v, 10, 64); err != nil || q.Before < 1 {
			writeJSONError(w, http.StatusBadRequest, "before must be a positive audit sequence number")
			return
		}
	}
	entries, err := s.store.Audit(q)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleAgentPoll serves the netagent (contract §8.2).
func (s *server) handleAgentPoll(w http.ResponseWriter, r *http.Request) {
	var req drivers.PollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		rejectedRequests.WithLabelValues("invalid_agent_poll").Inc()
		writeJSONError(w, http.StatusBadRequest, "invalid body")
		return
	}
	resp, err := s.engine.AgentPoll(req)
	if err != nil {
		s.storeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// writeJSONError builds the body with encoding/json so an error message
// containing a quote cannot produce malformed JSON.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		slog.Debug("response encode failed", "error", err)
	}
}
