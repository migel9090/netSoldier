package policy

import (
	"fmt"
	"log/slog"
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
	// requires at least this many corroborating signal classes.
	AutoMinSignals int
	// AutoRequireKnownBad gates auto-block on at least one externally
	// attested known-bad signal class (threat-feed match or IDS signature).
	//
	// Why this exists (step 124): composite confidence combines signals with
	// a noisy-OR, so a lone beacon (max 75) plus a lone volumetric anomaly
	// (max 70) combine to 93 → severity "critical" → it cleared the 90 /
	// critical auto-block bar with TWO signal classes and therefore also
	// satisfied AutoMinSignals=2. Two local heuristics could quarantine a
	// household device with no human in the loop and nothing external
	// saying the destination was malicious — and NTP, telemetry and update
	// checks all look like beaconing. Counting signals is not enough; their
	// KIND is what separates "known bad" from "unusual".
	AutoRequireKnownBad bool
	Allowlist           Allowlist
}

// DefaultPolicy returns a production-safe policy with conservative thresholds.
func DefaultPolicy() *Policy {
	return &Policy{
		AutoMinConfidence:   90,
		AutoMinSeverity:     events.SeverityCritical,
		PendMinConfidence:   50,
		PendMinSeverity:     events.SeverityMedium,
		DefaultTTL:          3600,
		DefaultAction:       events.ActionDNSSinkhole,
		AutoMinSignals:      1,
		AutoRequireKnownBad: true,
	}
}

// validSeverities are the only severity strings the policy may be configured
// with. An unrecognised value ranks 0, which would make the severity test
// `evRank >= severityRank(p.AutoMinSeverity)` trivially true and silently
// degrade the auto-block gate to a bare confidence threshold — a typo in an
// env var must never WIDEN enforcement.
var validSeverities = map[string]struct{}{
	events.SeverityCritical: {},
	events.SeverityHigh:     {},
	events.SeverityMedium:   {},
	events.SeverityLow:      {},
}

// validActions are the enforcement action types a driver exists for.
var validActions = map[string]struct{}{
	events.ActionDNSSinkhole: {},
	events.ActionARPIsolate:  {},
	events.ActionSwitchACL:   {},
}

// LoadFromEnv reads policy parameters from environment variables,
// falling back to defaults for any missing OR INVALID value. Every rejected
// value is logged at warn level: silently running a weaker policy than the
// operator believes they configured is the failure mode to avoid.
func LoadFromEnv() *Policy {
	p := DefaultPolicy()

	if v := os.Getenv("POLICY_AUTO_CONFIDENCE"); v != "" {
		if n, ok := parseConfidence("POLICY_AUTO_CONFIDENCE", v); ok {
			p.AutoMinConfidence = n
		}
	}
	if v := os.Getenv("POLICY_AUTO_SEVERITY"); v != "" {
		if s, ok := parseSeverity("POLICY_AUTO_SEVERITY", v); ok {
			p.AutoMinSeverity = s
		}
	}
	if v := os.Getenv("POLICY_PENDING_CONFIDENCE"); v != "" {
		if n, ok := parseConfidence("POLICY_PENDING_CONFIDENCE", v); ok {
			p.PendMinConfidence = n
		}
	}
	if v := os.Getenv("POLICY_PENDING_SEVERITY"); v != "" {
		if s, ok := parseSeverity("POLICY_PENDING_SEVERITY", v); ok {
			p.PendMinSeverity = s
		}
	}
	if v := os.Getenv("POLICY_DEFAULT_TTL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			p.DefaultTTL = n
		} else {
			slog.Warn("invalid POLICY_DEFAULT_TTL, keeping default",
				"value", v, "default", p.DefaultTTL)
		}
	}
	if v := os.Getenv("POLICY_DEFAULT_ACTION"); v != "" {
		if _, ok := validActions[v]; ok {
			p.DefaultAction = v
		} else {
			slog.Warn("invalid POLICY_DEFAULT_ACTION, keeping default",
				"value", v, "default", p.DefaultAction)
		}
	}
	if v := os.Getenv("POLICY_AUTO_MIN_SIGNALS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			p.AutoMinSignals = n
		} else {
			slog.Warn("invalid POLICY_AUTO_MIN_SIGNALS, keeping default",
				"value", v, "default", p.AutoMinSignals)
		}
	}
	// Opt-out exists for lab/tuning use only, and says so loudly.
	if v := os.Getenv("POLICY_AUTO_REQUIRE_KNOWN_BAD"); v != "" {
		switch strings.ToLower(v) {
		case "0", "false", "no":
			p.AutoRequireKnownBad = false
			slog.Warn("POLICY_AUTO_REQUIRE_KNOWN_BAD disabled — corroborated heuristics " +
				"(beaconing + volumetric) can now auto-block with no human in the loop")
		case "1", "true", "yes":
			p.AutoRequireKnownBad = true
		default:
			slog.Warn("invalid POLICY_AUTO_REQUIRE_KNOWN_BAD, keeping default",
				"value", v, "default", p.AutoRequireKnownBad)
		}
	}

	if v := os.Getenv("ALLOWLIST_MACS"); v != "" {
		for _, m := range strings.Split(v, ",") {
			if m = strings.TrimSpace(m); m != "" {
				if err := p.Allowlist.AddMAC(m); err != nil {
					slog.Error("ALLOWLIST_MACS entry rejected — this device is NOT protected",
						"entry", m, "error", err)
				}
			}
		}
	}
	if v := os.Getenv("ALLOWLIST_IPS"); v != "" {
		for _, ip := range strings.Split(v, ",") {
			if ip = strings.TrimSpace(ip); ip != "" {
				if err := p.Allowlist.AddIP(ip); err != nil {
					slog.Error("ALLOWLIST_IPS entry rejected — this device is NOT protected",
						"entry", ip, "error", err)
				}
			}
		}
	}

	return p
}

func parseConfidence(key, v string) (int, bool) {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 100 {
		slog.Warn("invalid confidence threshold, keeping default", "key", key, "value", v)
		return 0, false
	}
	return n, true
}

func parseSeverity(key, v string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(v))
	if _, ok := validSeverities[s]; !ok {
		slog.Warn("invalid severity, keeping default", "key", key, "value", v)
		return "", false
	}
	return s, true
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
		// Two independent gates stand between "confident" and "cut this
		// device off without asking": enough distinct corroborating signal
		// classes (step 117), and at least one of them being externally
		// attested known-bad rather than a local heuristic (step 124).
		if reason, ok := p.autoBlockBlockedBy(ev); !ok {
			return Decision{
				Action:     "pending",
				ActionType: p.DefaultAction,
				TTLSeconds: p.DefaultTTL,
				Reason: fmt.Sprintf("pending (%s): confidence=%d severity=%s signals=%d",
					reason, ev.Confidence, ev.Severity, signalCount(ev)),
			}
		}
		return Decision{
			Action:     "auto_block",
			ActionType: p.DefaultAction,
			TTLSeconds: p.DefaultTTL,
			Reason: fmt.Sprintf("auto: confidence=%d severity=%s signals=%d known_bad=%v",
				ev.Confidence, ev.Severity, signalCount(ev), ev.KnownBadSignals()),
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

// autoBlockBlockedBy reports whether the event may auto-block. On refusal it
// returns the human-readable reason that goes into the pending action's
// policy_rule, so an operator reviewing the queue sees WHY it needed them.
func (p *Policy) autoBlockBlockedBy(ev events.DetectionEvent) (string, bool) {
	if p.AutoRequireKnownBad && !ev.HasKnownBadSignal() {
		return "no known-bad signal: heuristics alone never auto-block", false
	}
	if !p.corroborated(ev) {
		return fmt.Sprintf("needs %d signals, has %d", p.AutoMinSignals, signalCount(ev)), false
	}
	return "", true
}

// corroborated reports whether the event satisfies the AutoMinSignals gate.
// A single known-bad IoC feed match (no composite signal metadata) counts
// as sufficient on its own regardless of AutoMinSignals — that is the
// classic "block this C2 domain now" case. Composite detections must carry
// at least AutoMinSignals distinct signal classes.
//
// The SignalCount==0 shortcut is only safe because autoBlockBlockedBy has
// already established that a known-bad class is present: an unlabelled event
// cannot reach here with AutoRequireKnownBad on.
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
