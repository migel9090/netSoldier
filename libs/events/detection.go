// Package events defines versioned event schemas shared across netSoldier
// services. All producers and consumers of detection events MUST use these
// types to ensure wire compatibility.
//
// The JSON schemas in /schemas describe the same shapes; schema_test.go
// fails when the two drift apart, so neither can be edited alone.
package events

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DetectionSchemaVersion is the current version of the DetectionEvent schema.
// Bump the major on any breaking field change (rename, type change, removal):
// receivers refuse a major they do not speak (see Validate). Additive changes
// (new optional fields) bump the minor only.
//
// 2.0 separates what a detection SAYS from what enforcement may DO about it.
// In 1.x `domain` was both the display string and the thing the killswitch
// sinkholed, so a decorated "cdn.x (→203.0.113.7)", a Suricata rule message
// or the device's own IP ended up as a filter rule. 2.0 adds a display-only
// `summary`, a typed `target`, and per-signal evidence in `signals`.
const DetectionSchemaVersion = "2.0"

// detectionSchemaMajor is the major version this package can decode.
const detectionSchemaMajor = 2

// Severity constants.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// severities is the closed severity vocabulary, mirrored by the schema enum.
var severities = []string{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow}

// Signal classes label where a detection came from. They live in the shared
// contract (not just in the detection-engine) because the killswitch policy
// has to tell corroborating evidence apart by KIND, not just by count: a
// feed/signature hit is externally attested "known bad", while beaconing,
// volumetric and TLS signals are local heuristics. Auto-enforcement keys off
// that distinction (see IsKnownBadSignal).
const (
	SignalIoC        = "ioc"           // domain/IP/hash match from a feed
	SignalIDS        = "ids-signature" // Suricata rule hit
	SignalTLS        = "tls"           // TLS fingerprint/SNI heuristic
	SignalBeacon     = "beacon"        // RITA beaconing
	SignalVolumetric = "volumetric"    // Isolation Forest flow anomaly
	SignalComposite  = "composite"     // combined output
)

// knownSignalClasses is the closed class vocabulary, mirrored by the schema.
// SignalComposite is only ever an event-level label, never the class of one
// contributing signal.
var knownSignalClasses = []string{
	SignalIoC, SignalIDS, SignalTLS, SignalBeacon, SignalVolumetric, SignalComposite,
}

// IsKnownBadSignal reports whether a signal class represents an externally
// attested known-bad indicator (a threat-feed match or an IDS signature) as
// opposed to a locally derived heuristic.
func IsKnownBadSignal(class string) bool {
	return class == SignalIoC || class == SignalIDS
}

// Indicator types name what a signal's indicator (and an event's
// matched_ioc) is. The vocabulary is open: sensors report types that are not
// listed here (Zeek's certificate hashes, for one) and receivers must not
// reject them. Only the target types below are closed.
const (
	IndicatorDomain = "domain"
	IndicatorIP     = "ip"
	IndicatorCIDR   = "cidr"
	IndicatorURL    = "url"
	IndicatorJA3    = "ja3"
	IndicatorTLSFP  = "tlsfp"
	IndicatorMD5    = "md5"
	IndicatorSHA256 = "sha256"
	IndicatorSID    = "sid" // IDS rule signature id
)

// Target types: the only things enforcement can be pointed at by name.
const (
	TargetDomain = "domain"
	TargetIP     = "ip"
)

// targetTypes is the closed target vocabulary, mirrored by the schema enum.
var targetTypes = []string{TargetDomain, TargetIP}

// DetectionIDPattern is the shape of DetectionEvent.ID: "DET-" plus a
// per-process prefix plus a counter. The prefix is what keeps ids unique
// across restarts — a bare counter restarted at DET-1 on every boot, so the
// audit trail could not say which detection an action came from.
const DetectionIDPattern = `^DET-[A-Za-z0-9]+-[0-9]+$`

var detectionIDRe = regexp.MustCompile(DetectionIDPattern)

// MACPattern is the canonical client_mac form: lower-case, colon-separated.
const MACPattern = `^([0-9a-f]{2}:){5}[0-9a-f]{2}$`

var macRe = regexp.MustCompile(MACPattern)

// Signal is one piece of evidence behind a detection.
//
// Confidence is THIS signal's own confidence, not the event's combined
// value: a composite at 93 can be built from a feed hit at 20 and two
// heuristics, and the policy has to be able to see that.
type Signal struct {
	Class      string `json:"class"`
	Confidence int    `json:"confidence"` // 0-100

	// Indicator is the concrete thing this signal attests, when it has one
	// (the feed's domain, the IP, the fingerprint, the rule SID), in the
	// same canonical form a Target would use.
	Indicator     string `json:"indicator,omitempty"`
	IndicatorType string `json:"indicator_type,omitempty"`
	Source        string `json:"source,omitempty"`
}

// Target is the thing enforcement may act on, typed so that a receiver never
// has to guess whether a string is a domain, an address or prose.
type Target struct {
	Type  string `json:"type"` // TargetDomain or TargetIP
	Value string `json:"value"`
}

// DetectionEvent is the canonical detection event produced by the
// detection-engine and consumed by killswitch-controller, web-ui,
// ClickHouse, and webhook receivers.
type DetectionEvent struct {
	SchemaVersion string    `json:"schema_version"`
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`

	// Summary is human-readable and is the ONLY field meant for display. It
	// is never used to decide or perform enforcement.
	Summary string `json:"summary"`

	// Domain is the DNS name that was actually observed (the queried name),
	// or empty. It never carries rule text, addresses, fingerprints or
	// decorated strings.
	Domain string `json:"domain,omitempty"`

	// MatchedIoC and IoCType describe the indicator of the strongest signal,
	// for display and as the false-positive suppression key.
	MatchedIoC string `json:"matched_ioc,omitempty"`
	IoCType    string `json:"ioc_type,omitempty"`

	// Who triggered it. ClientIP is canonical IPv4 or IPv6; ClientMAC is
	// lower-case colon-separated when known.
	ClientIP   string `json:"client_ip"`
	ClientMAC  string `json:"client_mac,omitempty"`
	ClientName string `json:"client_name,omitempty"`

	// Classification.
	Severity   string `json:"severity"`   // SeverityCritical..SeverityLow
	Confidence int    `json:"confidence"` // 0-100, combined over all signals
	Source     string `json:"source"`     // feed / sensor / "composite"
	Threat     string `json:"threat"`     // malware family / threat name

	// MITRE ATT&CK mapping.
	MitreID   string `json:"mitre_id,omitempty"`
	MitreName string `json:"mitre_name,omitempty"`

	// Context.
	QueryType string   `json:"query_type,omitempty"` // DNS query type: "A", "AAAA", etc.
	Tags      []string `json:"tags,omitempty"`

	// SignalClass is the class of a single-signal event and SignalComposite
	// when Signals spans more than one distinct class. Signals always has at
	// least one entry and is what the policy reads; SignalClass is the
	// summary of it for filtering and display.
	SignalClass string   `json:"signal_class"`
	Signals     []Signal `json:"signals"`

	// Target is present only when the detection names something concrete
	// that enforcement could act on. Absent means "nothing to enforce
	// automatically" — a pending action for a human at most.
	Target *Target `json:"target,omitempty"`
}

// KnownBadSignals returns the distinct known-bad signal classes the event's
// signals carry. An event with no known-bad signal returns nil — callers must
// treat that as "no attested known-bad evidence" and never as a free pass.
//
// Only Signals is consulted. SignalClass is a summary of Signals (Validate
// checks that they agree), so reading it as well would let an event that
// merely LABELS itself "ioc" claim evidence it does not carry.
func (e DetectionEvent) KnownBadSignals() []string {
	var out []string
	for _, s := range e.Signals {
		if IsKnownBadSignal(s.Class) && !contains(out, s.Class) {
			out = append(out, s.Class)
		}
	}
	return out
}

// HasKnownBadSignal reports whether the event is backed by at least one
// externally attested known-bad indicator.
func (e DetectionEvent) HasKnownBadSignal() bool {
	return len(e.KnownBadSignals()) > 0
}

// ContributingClasses returns the distinct signal classes in Signals, in
// order of first appearance.
func (e DetectionEvent) ContributingClasses() []string {
	var out []string
	for _, s := range e.Signals {
		if !contains(out, s.Class) {
			out = append(out, s.Class)
		}
	}
	return out
}

// AttestedSignal returns a known-bad signal whose own confidence is at least
// minConfidence AND whose indicator is the event's target (same type, same
// canonical value). When several qualify, the most confident one wins.
//
// This is the question auto-enforcement has to ask: not "is there any
// feed hit somewhere in this event" but "did a feed or signature vouch for
// THE THING WE ARE ABOUT TO BLOCK, strongly enough on its own". Without the
// indicator check a weak hit on one name unlocked a block of whatever the
// strongest heuristic pointed at.
func (e DetectionEvent) AttestedSignal(minConfidence int) (Signal, bool) {
	if e.Target == nil {
		return Signal{}, false
	}
	var best Signal
	found := false
	for _, s := range e.Signals {
		if !IsKnownBadSignal(s.Class) || s.Confidence < minConfidence {
			continue
		}
		if s.IndicatorType != e.Target.Type || !sameIndicator(e.Target.Type, s.Indicator, e.Target.Value) {
			continue
		}
		if !found || s.Confidence > best.Confidence {
			best, found = s, true
		}
	}
	return best, found
}

// sameIndicator compares two indicator values of the given type in their
// canonical forms, so "Evil.Example." and "evil.example", or two spellings of
// one IPv6 address, are the same indicator.
func sameIndicator(typ, a, b string) bool {
	switch typ {
	case TargetDomain:
		ca, okA := CanonicalDomain(a)
		cb, okB := CanonicalDomain(b)
		return okA && okB && ca == cb
	case TargetIP:
		ca, okA := CanonicalIP(a)
		cb, okB := CanonicalIP(b)
		return okA && okB && ca == cb
	default:
		return false
	}
}

// ValidationError lists every way an event breaks the contract, so a
// rejected sender can be fixed in one round trip instead of one per field.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return "invalid detection event: " + strings.Join(e.Problems, "; ")
}

// Validate checks the event against the v2 contract. Receivers run it before
// acting on an event: a detection that cannot say what it is, who it is
// about, or what evidence it rests on must be refused with a reason rather
// than half-evaluated.
func (e DetectionEvent) Validate() error {
	var problems []string
	add := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}

	if major, ok := schemaMajor(e.SchemaVersion); !ok {
		add("schema_version %q is not a MAJOR.MINOR version", e.SchemaVersion)
	} else if major != detectionSchemaMajor {
		add("schema_version %q has an unsupported major version (want %d.x)",
			e.SchemaVersion, detectionSchemaMajor)
	}
	if !detectionIDRe.MatchString(e.ID) {
		add("id %q does not match %s", e.ID, DetectionIDPattern)
	}
	if e.Timestamp.IsZero() {
		add("timestamp is missing")
	}
	if strings.TrimSpace(e.Summary) == "" {
		add("summary is empty")
	}
	if !contains(severities, e.Severity) {
		add("severity %q is not one of %s", e.Severity, strings.Join(severities, ", "))
	}
	if !validConfidence(e.Confidence) {
		add("confidence %d is outside 0-100", e.Confidence)
	}
	if ip, ok := CanonicalIP(e.ClientIP); !ok {
		add("client_ip %q is not an IP address", e.ClientIP)
	} else if ip != e.ClientIP {
		add("client_ip %q is not in canonical form (%s)", e.ClientIP, ip)
	}
	if e.ClientMAC != "" && !macRe.MatchString(e.ClientMAC) {
		add("client_mac %q is not lower-case colon-separated", e.ClientMAC)
	}

	if len(e.Signals) == 0 {
		add("signals is empty: every detection rests on at least one signal")
	}
	for i, s := range e.Signals {
		if !contains(knownSignalClasses, s.Class) || s.Class == SignalComposite {
			add("signals[%d].class %q is not a signal class", i, s.Class)
		}
		if !validConfidence(s.Confidence) {
			add("signals[%d].confidence %d is outside 0-100", i, s.Confidence)
		}
	}
	if want := e.expectedSignalClass(); want != "" && e.SignalClass != want {
		add("signal_class %q does not match signals (want %q)", e.SignalClass, want)
	}

	if t := e.Target; t != nil {
		switch t.Type {
		case TargetDomain:
			if d, ok := CanonicalDomain(t.Value); !ok {
				add("target domain %q is not a hostname", t.Value)
			} else if d != t.Value {
				add("target domain %q is not in canonical form (%s)", t.Value, d)
			}
		case TargetIP:
			if ip, ok := CanonicalIP(t.Value); !ok {
				add("target ip %q is not an IP address", t.Value)
			} else if ip != t.Value {
				add("target ip %q is not in canonical form (%s)", t.Value, ip)
			}
		default:
			add("target type %q is not one of %s", t.Type, strings.Join(targetTypes, ", "))
		}
	}

	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// expectedSignalClass derives signal_class from Signals: the single class,
// SignalComposite for more than one, "" when there are no signals.
func (e DetectionEvent) expectedSignalClass() string {
	switch classes := e.ContributingClasses(); len(classes) {
	case 0:
		return ""
	case 1:
		return classes[0]
	default:
		return SignalComposite
	}
}

// CanonicalIP parses an address and returns its canonical text form: IPv4
// dotted-quad (an IPv4-mapped IPv6 address is unmapped), IPv6 lower-case and
// compressed. Zoned addresses are refused — a zone names a local interface,
// not a device.
func CanonicalIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil || addr.Zone() != "" {
		return "", false
	}
	return addr.Unmap().String(), true
}

// CanonicalDomain lower-cases a hostname, drops a trailing dot, and checks it
// is something a DNS filter rule can name: at least two LDH labels of 1-63
// characters, at most 253 characters, and not an address. A top-level label
// is never all-numeric, which is what keeps "192.168.001.001" (which netip
// refuses to parse) from passing as a name.
func CanonicalDomain(s string) (string, bool) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if d == "" || len(d) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, l := range labels {
		if !validLabel(l) {
			return "", false
		}
	}
	if allDigits(labels[len(labels)-1]) {
		return "", false
	}
	return d, true
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// FormatDetectionID builds an id of the DetectionIDPattern shape.
func FormatDetectionID(prefix string, n uint64) string {
	return "DET-" + prefix + "-" + strconv.FormatUint(n, 10)
}

// ValidIDPrefix reports whether prefix can be used in FormatDetectionID.
func ValidIDPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// schemaMajor extracts MAJOR from a "MAJOR.MINOR" version string.
func schemaMajor(v string) (int, bool) {
	major, minor, ok := strings.Cut(v, ".")
	if !ok || !allDigits(major) || !allDigits(minor) {
		return 0, false
	}
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, false
	}
	return n, true
}

func validConfidence(c int) bool { return c >= 0 && c <= 100 }

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
