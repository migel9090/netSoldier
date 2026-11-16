package drivers

import (
	"sort"
	"sync"
	"time"
)

// RuleRef is one action's claim on a sinkhole rule.
type RuleRef struct {
	ActionID string
	Rule     string
}

// OwnedRule is a rule the sinkhole has seen. Owned is true when this
// service added it to AdGuard and may therefore remove it; a rule that was
// already there belongs to the operator and is never removed.
type OwnedRule struct {
	Rule  string
	Owned bool
}

// RuleLedger is the sinkhole's durable memory of which rules it owns and
// which actions hold them. The controller's store implements it; it must
// survive a restart, or the sinkhole would forget what it added.
type RuleLedger interface {
	// SinkholeRef returns the rule an action holds.
	SinkholeRef(actionID string) (rule string, ok bool, err error)
	// SinkholeRefs returns every claim.
	SinkholeRefs() ([]RuleRef, error)
	// SinkholeRule returns what is known about one rule and how many
	// actions hold it.
	SinkholeRule(rule string) (r OwnedRule, refs int, known bool, err error)
	// SinkholeRules returns every known rule.
	SinkholeRules() ([]OwnedRule, error)
	// ClaimSinkholeRule records that an action holds rule. adding says the
	// sinkhole is about to write the rule itself, which makes it owned; a
	// rule first seen already present is recorded as not owned.
	ClaimSinkholeRule(actionID, rule string, adding bool) error
	// ReleaseSinkholeRef drops an action's claim; with forget, the rule is
	// forgotten as well once nobody holds it.
	ReleaseSinkholeRef(actionID string, forget bool) error
	// ForgetSinkholeRule drops a rule nobody holds.
	ForgetSinkholeRule(rule string) error
}

// memoryLedger is a RuleLedger that does not survive a restart. It exists
// for tests and for callers that construct a sinkhole without a store.
type memoryLedger struct {
	mu    sync.Mutex
	rules map[string]bool   // rule -> owned
	refs  map[string]string // action -> rule
}

func newMemoryLedger() *memoryLedger {
	return &memoryLedger{rules: map[string]bool{}, refs: map[string]string{}}
}

func (m *memoryLedger) SinkholeRef(actionID string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.refs[actionID]
	return r, ok, nil
}

func (m *memoryLedger) SinkholeRefs() ([]RuleRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RuleRef, 0, len(m.refs))
	for a, r := range m.refs {
		out = append(out, RuleRef{ActionID: a, Rule: r})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ActionID < out[j].ActionID })
	return out, nil
}

func (m *memoryLedger) SinkholeRule(rule string) (OwnedRule, int, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	owned, known := m.rules[rule]
	return OwnedRule{Rule: rule, Owned: owned}, m.countLocked(rule), known, nil
}

func (m *memoryLedger) SinkholeRules() ([]OwnedRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]OwnedRule, 0, len(m.rules))
	for r, owned := range m.rules {
		out = append(out, OwnedRule{Rule: r, Owned: owned})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Rule < out[j].Rule })
	return out, nil
}

func (m *memoryLedger) ClaimSinkholeRule(actionID, rule string, adding bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if owned, known := m.rules[rule]; !known || adding {
		m.rules[rule] = adding || owned
	}
	m.refs[actionID] = rule
	return nil
}

func (m *memoryLedger) ReleaseSinkholeRef(actionID string, forget bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rule, ok := m.refs[actionID]
	delete(m.refs, actionID)
	if ok && forget && m.countLocked(rule) == 0 {
		delete(m.rules, rule)
	}
	return nil
}

func (m *memoryLedger) ForgetSinkholeRule(rule string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.countLocked(rule) == 0 {
		delete(m.rules, rule)
	}
	return nil
}

func (m *memoryLedger) countLocked(rule string) int {
	n := 0
	for _, r := range m.refs {
		if r == rule {
			n++
		}
	}
	return n
}

// Agent command types (contract §8.2).
const (
	CommandIsolate = "arp_isolate"
	CommandRelease = "arp_release"
)

// Agent command states, as the controller tracks them.
const (
	CommandQueued    = "queued"
	CommandSent      = "sent"
	CommandDone      = "done"
	CommandFailed    = "failed"
	CommandCancelled = "cancelled"
)

// AgentCommand is one instruction for the netagent. The JSON form is the
// wire form of contract §8.2; the rest is the controller's bookkeeping.
type AgentCommand struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	MAC        string `json:"mac"`
	IP         string `json:"ip"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`

	// ActionID is the action the command serves; empty for a release
	// issued by reconciliation for an isolation nobody owns.
	ActionID  string    `json:"-"`
	State     string    `json:"-"`
	CreatedAt time.Time `json:"-"`
	SentAt    time.Time `json:"-"`
	Error     string    `json:"-"`
}

// CommandStore is the durable queue between the controller and the agent.
type CommandStore interface {
	// EnqueueCommand stores a new queued command and assigns its id.
	EnqueueCommand(c AgentCommand) (AgentCommand, error)
	// TakeCommands marks up to limit queued commands sent and returns them.
	TakeCommands(limit int) ([]AgentCommand, error)
	// CompleteCommand records the agent's result. changed is false for an
	// unknown id or a command that already had one.
	CompleteCommand(id string, ok bool, errText string) (cmd AgentCommand, changed bool, err error)
	// CancelCommand withdraws a command that has not been sent yet and
	// reports whether it was still queued.
	CancelCommand(id string) (bool, error)
	// OpenCommands returns the queued and sent commands, oldest first.
	OpenCommands() ([]AgentCommand, error)
}
