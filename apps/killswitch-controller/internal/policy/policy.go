package policy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
	// Withheld is set when the event met every per-event condition for
	// auto-block and only the service-wide state kept it pending (one of the
	// Withheld* labels). The caller counts and logs these: an operator who
	// started the service in a degraded mode has to be able to see what it
	// is costing them.
	Withheld string `json:",omitempty"`
}

// Labels for Decision.Withheld, also used as metric label values.
const (
	WithheldAutoBlockOff      = "auto_block_off"
	WithheldEmptyAllowlist    = "empty_allowlist"
	WithheldInvalidProtection = "invalid_protection_config"
)

// POLICY_AUTO_BLOCK values. Unset means AutoBlockOff.
const (
	AutoBlockOn  = "on"
	AutoBlockOff = "off"
)

// OnInvalidPendingOnly is the ALLOWLIST_ON_INVALID value that lets the
// service start with rejected protection entries, auto-block disabled.
const OnInvalidPendingOnly = "pending-only"

// Policy defines thresholds for automated and pending enforcement,
// plus an allowlist of critical devices that are never blocked.
//
// The auto-block rule lives here and nowhere else. An event is enforced
// without a human only when ALL of these hold:
//
//  1. its target is a domain;
//  2. a known-bad signal (feed match or IDS signature) names exactly that
//     domain and on its own clears AutoMinConfidence (AttestedSignal);
//  3. the event clears AutoMinConfidence / AutoMinSeverity and carries at
//     least AutoMinSignals distinct signal classes when it is a composite;
//  4. the client is neither allowlisted nor protected infrastructure;
//  5. the operator switched auto-block on (POLICY_AUTO_BLOCK=on) and nothing
//     holds it service-wide (AutoBlockHold).
//
// The automatic path always enforces through the DNS sinkhole. Everything
// else that clears the thresholds becomes a pending action whose
// policy_rule names the conditions that failed.
type Policy struct {
	AutoMinConfidence int
	AutoMinSeverity   string
	PendMinConfidence int
	PendMinSeverity   string
	DefaultTTL        int
	// DefaultAction is the enforcement type a PENDING action is created
	// with, i.e. what a human approves. It never changes what the automatic
	// path does: that is always a DNS sinkhole.
	DefaultAction string
	// AutoMinSignals is the composite-confidence gate (step 117): a
	// composite must carry at least this many distinct signal classes.
	AutoMinSignals int

	// AutoBlock is POLICY_AUTO_BLOCK=on: the operator's explicit consent to
	// enforcement without a human. Nothing else turns automation on. It used
	// to follow from a non-empty allowlist, so "never touch this server" —
	// or an installer protecting the host's own address — switched it on as
	// a side effect.
	AutoBlock bool

	// Allowlist is the operator's list of devices that must never be
	// enforced against. While it is empty auto-block is disabled, unless
	// AllowEmptyAllowlist says otherwise; a non-empty one never enables it.
	Allowlist           Allowlist
	AllowEmptyAllowlist bool

	// Infrastructure holds the devices the service protects on its own
	// account — the configured gateway, the DNS server it enforces through,
	// the sensor's own interfaces. Events from them are ignored like
	// allowlisted ones, but they do not count towards "the allowlist is not
	// empty": discovering the sensor's own address says nothing about
	// whether the operator has protected the router.
	Infrastructure Allowlist

	// GatewayIP / GatewayMAC are the pinned gateway identity from
	// GATEWAY_IP / GATEWAY_MAC (zero / empty when not configured).
	GatewayIP  netip.Addr
	GatewayMAC string

	// RejectedEntries lists protection settings that did not parse. It is
	// only ever non-empty when the service was told to start anyway
	// (ALLOWLIST_ON_INVALID=pending-only), and while it is, auto-block is
	// disabled: the device the operator meant to protect is not protected.
	RejectedEntries []string
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

// LoadFromEnv reads policy parameters from environment variables.
//
// Thresholds fall back to their defaults on a missing or invalid value, with
// a warning: every such fallback is at least as strict as what was asked
// for. Protection settings are different. A rejected ALLOWLIST_* entry or
// GATEWAY_* value means a device the operator believes is protected is not,
// so it is an error that names the entry and stops the service — unless
// ALLOWLIST_ON_INVALID=pending-only, in which case the policy loads with
// auto-block disabled and RejectedEntries says why.
//
// POLICY_AUTO_BLOCK is the one switch that is neither: a value other than
// on or off is an error, because falling back to either would guess at the
// one decision the operator has to make on purpose.
func LoadFromEnv() (*Policy, error) {
	p := DefaultPolicy()

	switch v := os.Getenv("POLICY_AUTO_BLOCK"); v {
	case "", AutoBlockOff:
	case AutoBlockOn:
		p.AutoBlock = true
	default:
		return nil, fmt.Errorf("POLICY_AUTO_BLOCK=%q: want %q or %q (unset means %q)",
			v, AutoBlockOn, AutoBlockOff, AutoBlockOff)
	}

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
	// The opt-out let corroborated heuristics auto-block. Auto-block now
	// always rests on a known-bad signal that names the blocked domain, so
	// there is nothing left to opt out of; say so rather than ignore it.
	if v := os.Getenv("POLICY_AUTO_REQUIRE_KNOWN_BAD"); v != "" {
		slog.Warn("POLICY_AUTO_REQUIRE_KNOWN_BAD is no longer read: auto-block always requires "+
			"a known-bad signal that attests the blocked domain", "value", v)
	}
	switch strings.ToLower(os.Getenv("POLICY_ALLOW_EMPTY_ALLOWLIST")) {
	case "1", "true", "yes":
		p.AllowEmptyAllowlist = true
	}

	var rejected []string
	reject := func(key, entry string, err error) {
		rejected = append(rejected, fmt.Sprintf("%s entry %q: %v", key, entry, err))
	}
	for _, m := range splitList(os.Getenv("ALLOWLIST_MACS")) {
		if err := p.Allowlist.AddMAC(m); err != nil {
			reject("ALLOWLIST_MACS", m, err)
		}
	}
	for _, ip := range splitList(os.Getenv("ALLOWLIST_IPS")) {
		if err := p.Allowlist.AddIP(ip); err != nil {
			reject("ALLOWLIST_IPS", ip, err)
		}
	}
	if v := os.Getenv("GATEWAY_IP"); v != "" {
		if addr, err := ParseHostAddr(v); err != nil {
			reject("GATEWAY_IP", v, err)
		} else {
			p.GatewayIP = addr
			_ = p.Infrastructure.AddIP(addr.String())
		}
	}
	if v := os.Getenv("GATEWAY_MAC"); v != "" {
		if mac, err := ParseUnicastMAC(v); err != nil {
			reject("GATEWAY_MAC", v, err)
		} else {
			p.GatewayMAC = mac
			_ = p.Infrastructure.AddMAC(mac)
		}
	}
	// The old name enabled the ARP driver and trusted whatever MAC the
	// neighbour table reported for that address. Ignoring it would leave the
	// gateway unprotected while the operator believes it is configured.
	if v := os.Getenv("ARP_GATEWAY_IP"); v != "" {
		reject("ARP_GATEWAY_IP", v, errors.New("renamed: set GATEWAY_IP and pin the gateway's MAC with GATEWAY_MAC"))
	}

	if len(rejected) > 0 {
		switch mode := os.Getenv("ALLOWLIST_ON_INVALID"); mode {
		case OnInvalidPendingOnly:
			p.RejectedEntries = rejected
			for _, r := range rejected {
				slog.Error("protection entry rejected — this device is NOT protected; "+
					"auto-block is disabled (ALLOWLIST_ON_INVALID=pending-only)", "entry", r)
			}
		case "", "fail":
			return nil, fmt.Errorf("%s; the device would NOT be protected — fix the entry, or set "+
				"ALLOWLIST_ON_INVALID=%s to start with auto-block disabled",
				strings.Join(rejected, "; "), OnInvalidPendingOnly)
		default:
			return nil, fmt.Errorf("%s; and ALLOWLIST_ON_INVALID=%q is not %q",
				strings.Join(rejected, "; "), mode, OnInvalidPendingOnly)
		}
	}

	return p, nil
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ParseHostAddr parses one device address strictly: no prefix, no zone,
// and none of the spellings netip refuses (leading zeros, hex, octal).
// IPv4-mapped IPv6 is unmapped.
func ParseHostAddr(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("not a single IP address: %w", err)
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("zoned address names a local interface, not a device")
	}
	return addr.Unmap(), nil
}

// ParseUnicastMAC normalizes a MAC like NormalizeMAC and refuses group
// (broadcast/multicast) and all-zero addresses, which cannot be one device.
func ParseUnicastMAC(s string) (string, error) {
	mac, err := NormalizeMAC(s)
	if err != nil {
		return "", err
	}
	hw, _ := net.ParseMAC(mac)
	if hw[0]&1 == 1 {
		return "", fmt.Errorf("%s is a group (broadcast/multicast) address, not a device", mac)
	}
	if mac == "00:00:00:00:00:00" {
		return "", fmt.Errorf("all-zero MAC is not a device")
	}
	return mac, nil
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

// AutoBlockHold returns why auto-block is disabled for every event, with the
// matching Withheld label, or two empty strings when it is enabled.
//
// The switch comes first: while it is off, that is the reason, and the
// conditions below only say what would still hold automation back once it is
// switched on. (Rejected entries stay visible on their own: the start-up log,
// GET /policy and the protection_entries_rejected gauge report them.)
func (p *Policy) AutoBlockHold() (reason, label string) {
	if !p.AutoBlock {
		return "auto-block disabled: POLICY_AUTO_BLOCK=" + AutoBlockOff, WithheldAutoBlockOff
	}
	if n := len(p.RejectedEntries); n > 0 {
		reason = fmt.Sprintf("auto-block disabled: %d protection entr%s rejected at start-up, ALLOWLIST_ON_INVALID=%s",
			n, plural(n, "y was", "ies were"), OnInvalidPendingOnly)
		return reason, WithheldInvalidProtection
	}
	if p.Allowlist.Len() == 0 && !p.AllowEmptyAllowlist {
		return "auto-block disabled: allowlist is empty", WithheldEmptyAllowlist
	}
	return "", ""
}

// AutoBlockEnabled reports whether any event can be enforced without a human.
func (p *Policy) AutoBlockEnabled() bool {
	reason, _ := p.AutoBlockHold()
	return reason == ""
}

// Evaluate decides what enforcement action (if any) should be taken
// for a detection event. Protected devices always return "ignore".
func (p *Policy) Evaluate(ev events.DetectionEvent) Decision {
	if who := p.protectedClient(ev); who != "" {
		return Decision{Action: "ignore", Reason: who}
	}

	evRank := severityRank(ev.Severity)

	if ev.Confidence >= p.AutoMinConfidence && evRank >= autoSeverityBar(p.AutoMinSeverity) {
		if refusals := p.autoBlockRefusals(ev); len(refusals) > 0 {
			return p.pending(ev, "pending ("+strings.Join(refusals, "; ")+")", "")
		}
		attested, _ := ev.AttestedSignal(p.AutoMinConfidence)
		if hold, label := p.AutoBlockHold(); hold != "" {
			return p.pending(ev, "pending ("+hold+"; every other auto-block condition held)", label)
		}
		return Decision{
			Action:     "auto_block",
			ActionType: events.ActionDNSSinkhole,
			TTLSeconds: p.DefaultTTL,
			Reason: fmt.Sprintf("auto: confidence=%d severity=%s signals=%d attested_by=%s:%s@%d target=%s",
				ev.Confidence, ev.Severity, signalCount(ev), attested.Class, attested.Source,
				attested.Confidence, ev.Target.Value),
		}
	}

	if ev.Confidence >= p.PendMinConfidence && evRank >= severityRank(p.PendMinSeverity) {
		reason := "pending"
		if problem := targetProblem(ev); problem != "" {
			reason += " (" + problem + ")"
		}
		return p.pending(ev, reason, "")
	}

	return Decision{
		Action: "ignore",
		Reason: fmt.Sprintf("below thresholds: confidence=%d severity=%s", ev.Confidence, ev.Severity),
	}
}

func (p *Policy) pending(ev events.DetectionEvent, reason, withheld string) Decision {
	return Decision{
		Action:     "pending",
		ActionType: p.DefaultAction,
		TTLSeconds: p.DefaultTTL,
		Reason: fmt.Sprintf("%s: confidence=%d severity=%s signals=%d",
			reason, ev.Confidence, ev.Severity, signalCount(ev)),
		Withheld: withheld,
	}
}

func (p *Policy) protectedClient(ev events.DetectionEvent) string {
	if p.Allowlist.Contains(ev.ClientMAC, ev.ClientIP) {
		return fmt.Sprintf("allowlisted device %s / %s", ev.ClientMAC, ev.ClientIP)
	}
	if p.Infrastructure.Contains(ev.ClientMAC, ev.ClientIP) {
		return fmt.Sprintf("protected infrastructure %s / %s", ev.ClientMAC, ev.ClientIP)
	}
	return ""
}

// autoBlockRefusals lists every per-event auto-block condition the event
// fails, phrased for the operator who will read it as the pending action's
// policy_rule. Empty means the event itself is fit for auto-block.
func (p *Policy) autoBlockRefusals(ev events.DetectionEvent) []string {
	var out []string
	if problem := targetProblem(ev); problem != "" {
		out = append(out, problem)
	} else if _, ok := ev.AttestedSignal(p.AutoMinConfidence); !ok {
		out = append(out, attestationProblem(ev, p.AutoMinConfidence))
	}
	if !p.corroborated(ev) {
		out = append(out, fmt.Sprintf("needs %d signals, has %d", p.AutoMinSignals, signalCount(ev)))
	}
	return out
}

// targetProblem explains why the event cannot be enforced automatically by
// name, or returns "" when its target is a domain.
//
// The target is the ONLY thing enforcement may act on. Domain and Summary
// are what was observed and how to describe it.
func targetProblem(ev events.DetectionEvent) string {
	switch {
	case ev.Target == nil:
		return "no enforceable target: the detection names no domain or address to block"
	case ev.Target.Type != events.TargetDomain:
		return fmt.Sprintf("target is %s %s: only a domain can be blocked automatically",
			ev.Target.Type, ev.Target.Value)
	default:
		return ""
	}
}

// attestationProblem explains why no known-bad signal vouches for the
// domain target strongly enough. The distinction matters to the operator:
// "nothing external says this is bad" and "a feed says so, but weakly" call
// for different judgements.
func attestationProblem(ev events.DetectionEvent, minConfidence int) string {
	if !ev.HasKnownBadSignal() {
		return "no known-bad signal: heuristics alone never auto-block"
	}
	if s, ok := ev.AttestedSignal(0); ok {
		return fmt.Sprintf("the known-bad signal for %s is too weak on its own: %s confidence %d < %d",
			ev.Target.Value, s.Class, s.Confidence, minConfidence)
	}
	var evidence []string
	for _, s := range ev.Signals {
		if !events.IsKnownBadSignal(s.Class) {
			continue
		}
		if len(evidence) == 3 {
			evidence = append(evidence, "…")
			break
		}
		evidence = append(evidence, describeSignal(s))
	}
	return fmt.Sprintf("no known-bad signal names the target %s (known-bad evidence: %s)",
		ev.Target.Value, strings.Join(evidence, ", "))
}

// describeSignal renders a signal for a policy_rule. The indicator comes
// from the event, so it is quoted and truncated rather than trusted as text.
func describeSignal(s events.Signal) string {
	ind := s.Indicator
	if len(ind) > 64 {
		ind = ind[:64] + "…"
	}
	if ind == "" {
		return fmt.Sprintf("%s without an indicator at %d", s.Class, s.Confidence)
	}
	return fmt.Sprintf("%s %s %q at %d", s.Class, s.IndicatorType, ind, s.Confidence)
}

// corroborated reports whether the event satisfies the AutoMinSignals gate.
// A single-class detection (an IoC feed match) counts as sufficient on its
// own — the classic "block this C2 domain now" case, and safe because the
// attestation check has already required that signal to name the target and
// clear the bar alone. Composites must carry at least AutoMinSignals
// distinct signal classes.
//
// The count is taken from Signals, not from the event's self-declared
// signal_class, so a mislabelled composite cannot skip the gate.
func (p *Policy) corroborated(ev events.DetectionEvent) bool {
	if p.AutoMinSignals <= 1 {
		return true
	}
	classes := len(ev.ContributingClasses())
	return classes <= 1 || classes >= p.AutoMinSignals
}

// signalCount is the number of distinct signal classes behind the event,
// counting an event that lists none as one.
func signalCount(ev events.DetectionEvent) int {
	if n := len(ev.ContributingClasses()); n > 0 {
		return n
	}
	return 1
}

// autoSeverityBar is the rank an event needs for auto-block. A bar that is
// not a known severity can only come from a Policy built in code (LoadFromEnv
// validates it); it is treated as unreachable rather than as rank 0, which
// would let every severity through.
func autoSeverityBar(s string) int {
	if r := severityRank(s); r > 0 {
		return r
	}
	return severityRank(events.SeverityCritical) + 1
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

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
