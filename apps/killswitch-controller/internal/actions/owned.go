package actions

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/migel9090/netSoldier/apps/killswitch-controller/internal/drivers"
)

// The store also holds what the drivers own: the sinkhole's rule claims
// (drivers.RuleLedger) and the netagent command queue
// (drivers.CommandStore). Both live here so they survive a restart with
// the actions they belong to.
var (
	_ drivers.RuleLedger   = (*Store)(nil)
	_ drivers.CommandStore = (*Store)(nil)
)

// Evaluation is the durable outcome of one detection event id, which is
// what makes POST /evaluate idempotent across restarts.
type Evaluation struct {
	DetectionID string
	Digest      []byte
	Decision    []byte // the policy decision, JSON
	ActionID    string
	EvaluatedAt time.Time
}

// GetEvaluation returns the recorded outcome for a detection id.
func (s *Store) GetEvaluation(id string) (Evaluation, bool, error) {
	e := Evaluation{DetectionID: id}
	var at int64
	err := s.db.QueryRow(`SELECT digest, decision, action_id, evaluated_at FROM evaluations
		WHERE detection_id = ?`, id).Scan(&e.Digest, &e.Decision, &e.ActionID, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return e, false, nil
	}
	e.EvaluatedAt = fromMS(at)
	return e, err == nil, err
}

// PutEvaluation records the outcome for a detection id.
func (s *Store) PutEvaluation(e Evaluation) error {
	if e.EvaluatedAt.IsZero() {
		e.EvaluatedAt = s.now()
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO evaluations (detection_id, digest, decision, action_id,
		evaluated_at) VALUES (?, ?, ?, ?, ?)`, e.DetectionID, e.Digest, string(e.Decision), e.ActionID,
		ms(e.EvaluatedAt))
	if err != nil {
		storeErrors.WithLabelValues("evaluation").Inc()
	}
	return err
}

// SinkholeRef implements drivers.RuleLedger.
func (s *Store) SinkholeRef(actionID string) (string, bool, error) {
	var rule string
	err := s.db.QueryRow("SELECT rule FROM sinkhole_refs WHERE action_id = ?", actionID).Scan(&rule)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return rule, err == nil, err
}

// SinkholeRefs implements drivers.RuleLedger.
func (s *Store) SinkholeRefs() ([]drivers.RuleRef, error) {
	rows, err := s.db.Query("SELECT action_id, rule FROM sinkhole_refs ORDER BY action_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []drivers.RuleRef{}
	for rows.Next() {
		var r drivers.RuleRef
		if err := rows.Scan(&r.ActionID, &r.Rule); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SinkholeRule implements drivers.RuleLedger.
func (s *Store) SinkholeRule(rule string) (drivers.OwnedRule, int, bool, error) {
	r := drivers.OwnedRule{Rule: rule}
	var owned, refs int
	err := s.db.QueryRow(`SELECT owned, (SELECT COUNT(*) FROM sinkhole_refs WHERE rule = ?)
		FROM sinkhole_rules WHERE rule = ?`, rule, rule).Scan(&owned, &refs)
	if errors.Is(err, sql.ErrNoRows) {
		err = s.db.QueryRow("SELECT COUNT(*) FROM sinkhole_refs WHERE rule = ?", rule).Scan(&refs)
		return r, refs, false, err
	}
	r.Owned = owned == 1
	return r, refs, err == nil, err
}

// SinkholeRules implements drivers.RuleLedger.
func (s *Store) SinkholeRules() ([]drivers.OwnedRule, error) {
	rows, err := s.db.Query("SELECT rule, owned FROM sinkhole_rules ORDER BY rule")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []drivers.OwnedRule{}
	for rows.Next() {
		var r drivers.OwnedRule
		var owned int
		if err := rows.Scan(&r.Rule, &owned); err != nil {
			return nil, err
		}
		r.Owned = owned == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClaimSinkholeRule implements drivers.RuleLedger.
func (s *Store) ClaimSinkholeRule(actionID, rule string, adding bool) error {
	return s.inTx("sinkhole_claim", func(tx *sql.Tx) error {
		q := "INSERT INTO sinkhole_rules (rule, owned, added_at) VALUES (?, 0, ?) ON CONFLICT(rule) DO NOTHING"
		if adding {
			q = "INSERT INTO sinkhole_rules (rule, owned, added_at) VALUES (?, 1, ?) ON CONFLICT(rule) DO UPDATE SET owned = 1"
		}
		if _, err := tx.Exec(q, rule, ms(s.now())); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT OR REPLACE INTO sinkhole_refs (action_id, rule) VALUES (?, ?)", actionID, rule)
		return err
	})
}

// ReleaseSinkholeRef implements drivers.RuleLedger.
func (s *Store) ReleaseSinkholeRef(actionID string, forget bool) error {
	return s.inTx("sinkhole_release", func(tx *sql.Tx) error {
		var rule string
		err := tx.QueryRow("SELECT rule FROM sinkhole_refs WHERE action_id = ?", actionID).Scan(&rule)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM sinkhole_refs WHERE action_id = ?", actionID); err != nil {
			return err
		}
		if !forget {
			return nil
		}
		_, err = tx.Exec(`DELETE FROM sinkhole_rules WHERE rule = ?
			AND NOT EXISTS (SELECT 1 FROM sinkhole_refs WHERE rule = ?)`, rule, rule)
		return err
	})
}

// ForgetSinkholeRule implements drivers.RuleLedger.
func (s *Store) ForgetSinkholeRule(rule string) error {
	_, err := s.db.Exec(`DELETE FROM sinkhole_rules WHERE rule = ?
		AND NOT EXISTS (SELECT 1 FROM sinkhole_refs WHERE rule = ?)`, rule, rule)
	if err != nil {
		storeErrors.WithLabelValues("sinkhole_forget").Inc()
	}
	return err
}

func (s *Store) inTx(op string, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err == nil {
		if err = fn(tx); err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	if err != nil {
		storeErrors.WithLabelValues(op).Inc()
	}
	return err
}

const commandCols = "id, type, action_id, mac, ip, ttl_seconds, state, created_at, sent_at, error"

func scanCommand(sc scanner) (drivers.AgentCommand, error) {
	var c drivers.AgentCommand
	var created, sent int64
	err := sc.Scan(&c.ID, &c.Type, &c.ActionID, &c.MAC, &c.IP, &c.TTLSeconds, &c.State, &created, &sent, &c.Error)
	c.CreatedAt, c.SentAt = fromMS(created), fromMS(sent)
	return c, err
}

func queryCommands(q querier, where string, args ...any) ([]drivers.AgentCommand, error) {
	rows, err := q.Query("SELECT "+commandCols+" FROM agent_commands WHERE "+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []drivers.AgentCommand{}
	for rows.Next() {
		c, err := scanCommand(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// EnqueueCommand implements drivers.CommandStore. Ids carry the database's
// instance id, so a result for a command issued before the database was
// lost can never confirm a new one.
func (s *Store) EnqueueCommand(c drivers.AgentCommand) (drivers.AgentCommand, error) {
	c.State, c.CreatedAt = drivers.CommandQueued, s.now()
	err := s.inTx("command_enqueue", func(tx *sql.Tx) error {
		res, err := tx.Exec(`INSERT INTO agent_commands (id, type, action_id, mac, ip, ttl_seconds, state,
			created_at) VALUES ('', ?, ?, ?, ?, ?, ?, ?)`, c.Type, c.ActionID, c.MAC, c.IP, c.TTLSeconds,
			c.State, ms(c.CreatedAt))
		if err != nil {
			return err
		}
		seq, err := res.LastInsertId()
		if err != nil {
			return err
		}
		c.ID = fmt.Sprintf("i-%s-%d", s.instance, seq)
		_, err = tx.Exec("UPDATE agent_commands SET id = ? WHERE seq = ?", c.ID, seq)
		return err
	})
	return c, err
}

// TakeCommands implements drivers.CommandStore.
func (s *Store) TakeCommands(limit int) ([]drivers.AgentCommand, error) {
	var out []drivers.AgentCommand
	err := s.inTx("command_take", func(tx *sql.Tx) error {
		var err error
		if out, err = queryCommands(tx, "state = ? ORDER BY seq LIMIT ?", drivers.CommandQueued, limit); err != nil {
			return err
		}
		now := s.now()
		for i := range out {
			out[i].State, out[i].SentAt = drivers.CommandSent, now
			if _, err := tx.Exec("UPDATE agent_commands SET state = ?, sent_at = ? WHERE id = ?",
				drivers.CommandSent, ms(now), out[i].ID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// CompleteCommand implements drivers.CommandStore.
func (s *Store) CompleteCommand(id string, ok bool, errText string) (drivers.AgentCommand, bool, error) {
	var c drivers.AgentCommand
	changed := false
	err := s.inTx("command_complete", func(tx *sql.Tx) error {
		cmds, err := queryCommands(tx, "id = ?", id)
		if err != nil || len(cmds) == 0 {
			return err
		}
		c = cmds[0]
		if c.State != drivers.CommandQueued && c.State != drivers.CommandSent {
			return nil
		}
		c.State, c.Error = drivers.CommandDone, ""
		if !ok {
			c.State, c.Error = drivers.CommandFailed, errText
		}
		changed = true
		_, err = tx.Exec("UPDATE agent_commands SET state = ?, error = ?, finished_at = ? WHERE id = ?",
			c.State, c.Error, ms(s.now()), id)
		return err
	})
	return c, changed, err
}

// CancelCommand implements drivers.CommandStore.
func (s *Store) CancelCommand(id string) (bool, error) {
	res, err := s.db.Exec("UPDATE agent_commands SET state = ?, finished_at = ? WHERE id = ? AND state = ?",
		drivers.CommandCancelled, ms(s.now()), id, drivers.CommandQueued)
	if err != nil {
		storeErrors.WithLabelValues("command_cancel").Inc()
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// OpenCommands implements drivers.CommandStore.
func (s *Store) OpenCommands() ([]drivers.AgentCommand, error) {
	return queryCommands(s.db, "state IN (?, ?) ORDER BY seq", drivers.CommandQueued, drivers.CommandSent)
}
