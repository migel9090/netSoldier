package policy

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/migel9090/netSoldier/libs/events"
)

// Decision is the outcome of evaluating a detection event against the policy.
type Decision struct {
	Action     string // "auto_block", "pending", "ignore"
	ActionType string // events.ActionDNSSinkhole, etc.
	TTLSeconds int
	Reason     string
}

// Policy defines thresholds for automated and pending enforcement,
// plus an allowlist of critical devices that are never blocked.
type Policy struct {
	AutoMinConfidence int
	AutoMinSeverity   string
	PendMinConfidence int
	PendMinSeverity   string
	DefaultTTL        int
	DefaultAction     string
	// AutoMinSignals is the composite-confidence gate (step 117): auto-block
	// requires at least this many corroborating signal classes UNLESS the
	// detection is a single high-confidence known-bad IoC (see Evaluate).
	// Default 1 preserves single-strong-IoC auto-block.
	AutoMinSignals int
	Allowlist      Allowlist
}

// DefaultPolicy returns a production-safe policy with conservative thresholds.
func DefaultPolicy() *Policy {
	return &Policy{
		AutoMinConfidence: 90,
		AutoMinSeverity:   events.SeverityCritical,
		PendMinConfidence: 50,
		PendMinSeverity:   events.SeverityMedium,
		DefaultTTL:        3600,
		DefaultAction:     events.ActionDNSSinkhole,
		AutoMinSignals:    1,
	}
}

// LoadFromEnv reads policy parameters from environment variables,
// falling back to defaults for any missing value.
func LoadFromEnv() *Policy {
	p := DefaultPolicy()

	if v := os.Getenv("POLICY_AUTO_CONFIDENCE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.AutoMinConfidence = n
		}
	}
	if v := os.Getenv("POLICY_AUTO_SEVERITY"); v != "" {
		p.AutoMinSeverity = v
	}
	if v := os.Getenv("POLICY_PENDING_CONFIDENCE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.PendMinConfidence = n
		}
	}
	if v := os.Getenv("POLICY_PENDING_SEVERITY"); v != "" {
		p.PendMinSeverity = v
	}
	if v := os.Getenv("POLICY_DEFAULT_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			p.DefaultTTL = n
		}
	}
	if v := os.Getenv("POLICY_DEFAULT_ACTION"); v != "" {
		p.DefaultAction = v
	}
	if v := os.Getenv("POLICY_AUTO_MIN_SIGNALS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			p.AutoMinSignals = n
		}
	}

	if v := os.Getenv("ALLOWLIST_MACS"); v != "" {
		for _, m := range strings.Split(v, ",") {
			if m = strings.TrimSpace(m); m != "" {
				p.Allowlist.AddMAC(m)
			}
		}
	}
	if v := os.Getenv("ALLOWLIST_IPS"); v != "" {
		for _, ip := range strings.Split(v, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				p.Allowlist.AddIP(ip)
			}
		}
	}

	return p
}

// Evaluate decides what enforcement action (if any) should be taken
// for a detection event. Allowlisted devices always return "ignore".
func (p *Policy) Evaluate(ev events.DetectionEvent) Decision {
	if p.Allowlist.Contains(ev.ClientMAC, ev.ClientIP) {
		return Decision{
			Action: "ignore",
			Reason: fmt.Sprintf("allowlisted device %s / %s", ev.ClientMAC, ev.ClientIP),
		}
	}

	evRank := severityRank(ev.Severity)

	if ev.Confidence >= p.AutoMinConfidence && evRank >= severityRank(p.AutoMinSeverity) {
		// Composite-confidence gate (step 117): when the operator requires
		// corroboration for auto-block, a detection carrying multiple signal
		// classes qualifies. A single-signal detection still auto-blocks
		// only if it is a genuine known-bad IoC (feed match at/above the
		// critical bar) — heuristics alone (beacon, volumetric, TLS) never
		// reach AutoMinConfidence on their own, so they always fall through
		// to pending here. This blocks known-bad instantly while keeping
		// heuristic-driven blocks human-in-the-loop unless corroborated.
		if p.corroborated(ev) {
			return Decision{
				Action:     "auto_block",
				ActionType: p.DefaultAction,
				TTLSeconds: p.DefaultTTL,
				Reason: fmt.Sprintf("auto: confidence=%d severity=%s signals=%d",
					ev.Confidence, ev.Severity, signalCount(ev)),
			}
		}
		return Decision{
			Action:     "pending",
			ActionType: p.DefaultAction,
			TTLSeconds: p.DefaultTTL,
			Reason: fmt.Sprintf("pending (needs %d signals, has %d): confidence=%d severity=%s",
				p.AutoMinSignals, signalCount(ev), ev.Confidence, ev.Severity),
		}
	}

	if ev.Confidence >= p.PendMinConfidence && evRank >= severityRank(p.PendMinSeverity) {
		return Decision{
			Action:     "pending",
			ActionType: p.DefaultAction,
			TTLSeconds: p.DefaultTTL,
			Reason:     fmt.Sprintf("pending: confidence=%d severity=%s", ev.Confidence, ev.Severity),
		}
	}

	return Decision{
		Action: "ignore",
		Reason: fmt.Sprintf("below thresholds: confidence=%d severity=%s", ev.Confidence, ev.Severity),
	}
}

// corroborated reports whether the event satisfies the AutoMinSignals gate.
// A single known-bad IoC feed match (no composite signal metadata) counts
// as sufficient on its own regardless of AutoMinSignals — that is the
// classic "block this C2 domain now" case. Composite detections must carry
// at least AutoMinSignals distinct signal classes.
func (p *Policy) corroborated(ev events.DetectionEvent) bool {
	if p.AutoMinSignals <= 1 {
		return true
	}
	if ev.SignalCount == 0 {
		return true // single-signal known-bad IoC; not a composite
	}
	return ev.SignalCount >= p.AutoMinSignals
}

func signalCount(ev events.DetectionEvent) int {
	if ev.SignalCount == 0 {
		return 1
	}
	return ev.SignalCount
}

func severityRank(s string) int {
	switch s {
	case events.SeverityCritical:
		return 4
	case events.SeverityHigh:
		return 3
	case events.SeverityMedium:
		return 2
	case events.SeverityLow:
		return 1
	default:
		return 0
	}
}
