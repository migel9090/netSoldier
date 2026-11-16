package ingest

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/libs/events"
)

// SuricataAlerts tails netsoldier.suricata_alerts (EVE alert events).
type SuricataAlerts struct {
	// Local decides which side of a flow is the household's device.
	Local LocalNetworks
}

func NewSuricataAlerts(local LocalNetworks) SuricataAlerts { return SuricataAlerts{Local: local} }

func (SuricataAlerts) Name() string { return "suricata_alerts" }

func (SuricataAlerts) Columns() string {
	return `toUnixTimestamp(timestamp) AS ts, flow_id, src_ip, src_port, dest_ip, dest_port, proto,
  alert_signature, alert_category, alert_severity, alert_signature_id, threat_intel`
}

func (SuricataAlerts) Identity() string {
	return `timestamp, flow_id, src_ip, src_port, dest_ip, dest_port, proto,
  alert_signature, alert_category, alert_severity, alert_signature_id, threat_intel`
}

func (SuricataAlerts) Filter() string { return "" }

type suricataAlertRow struct {
	TS               json.Number `json:"ts"`
	FlowID           json.Number `json:"flow_id"`
	SrcIP            string      `json:"src_ip"`
	SrcPort          json.Number `json:"src_port"`
	DestIP           string      `json:"dest_ip"`
	DestPort         json.Number `json:"dest_port"`
	Proto            string      `json:"proto"`
	AlertSignature   string      `json:"alert_signature"`
	AlertCategory    string      `json:"alert_category"`
	AlertSeverity    json.Number `json:"alert_severity"`
	AlertSignatureID json.Number `json:"alert_signature_id"`
	ThreatIntel      string      `json:"threat_intel"`
}

// Parse normalizes one alert. Src is the household's side of the flow and
// Dst the other side, whatever direction the packet that fired went: for a
// server-to-client signature ("... Beacon Response") the packet source is
// the internet host, and naming it the client is how a C2 server ended up
// as the device a detection was about.
//
// A rule that fired because a feed indicator was in its dataset (the
// threat_intel context the datajson rules attach) is a feed match seen by
// Suricata, not an independent signature: it becomes an IoC observation
// with the indicator and the feed's confidence. Every other rule is scored
// from its severity and category (signatureConfidence).
func (s SuricataAlerts) Parse(row json.RawMessage) (SensorEvent, error) {
	var r suricataAlertRow
	if err := json.Unmarshal(row, &r); err != nil {
		return SensorEvent{}, fmt.Errorf("decode suricata alert: %w", err)
	}

	ts, err := r.TS.Int64()
	if err != nil {
		return SensorEvent{}, fmt.Errorf("bad ts: %w", err)
	}
	sev, _ := r.AlertSeverity.Int64()

	ev := SensorEvent{
		Sensor:      "suricata",
		Kind:        "ids-alert",
		Timestamp:   time.Unix(ts, 0).UTC(),
		FlowID:      r.FlowID.String(),
		SrcIP:       r.SrcIP,
		SrcPort:     toInt(r.SrcPort),
		DstIP:       r.DestIP,
		DstPort:     toInt(r.DestPort),
		Proto:       r.Proto,
		Signature:   r.AlertSignature,
		SignatureID: r.AlertSignatureID.String(),
		Category:    r.AlertCategory,
	}
	if !s.Local.Contains(ev.SrcIP) && s.Local.Contains(ev.DstIP) {
		ev.SrcIP, ev.DstIP = ev.DstIP, ev.SrcIP
		ev.SrcPort, ev.DstPort = ev.DstPort, ev.SrcPort
	}

	if ti, ok := parseThreatIntel(r.ThreatIntel); ok {
		ev.Kind = "ids-dataset"
		ev.Indicator, ev.IndicatorType = ti.indicator()
		ev.Confidence = detection.ClampConfidence(ti.Confidence)
		ev.Severity = ti.Severity
		if !validSeverity(ev.Severity) {
			ev.Severity = detection.SeverityForConfidence(ev.Confidence)
		}
		ev.Source = firstNonEmpty(ti.Source, "threat-intel")
		ev.Threat = ti.Threat
		return ev, nil
	}

	ev.Confidence = signatureConfidence(r.AlertSignature, r.AlertCategory, int(sev))
	ev.Severity = detection.SeverityForConfidence(ev.Confidence)
	ev.Source = "suricata"
	if strings.HasPrefix(strings.ToUpper(r.AlertSignature), "ET ") {
		ev.Source = "et-open"
	}
	return ev, nil
}

// threatIntelContext is the datajson context threat-intel-sync's dataset
// files carry (export.WriteSuricataJSONDataset): the indicator under its
// value key ("domain" or "ip") plus the feed's attribution.
type threatIntelContext struct {
	Domain     string `json:"domain"`
	IP         string `json:"ip"`
	Source     string `json:"source"`
	Severity   string `json:"severity"`
	Confidence int    `json:"confidence"`
	Threat     string `json:"threat"`
}

// parseThreatIntel reports whether raw is a dataset context at all. An
// empty or unparsable blob is an ordinary signature hit.
func parseThreatIntel(raw string) (threatIntelContext, bool) {
	if strings.TrimSpace(raw) == "" {
		return threatIntelContext{}, false
	}
	var ti threatIntelContext
	if err := json.Unmarshal([]byte(raw), &ti); err != nil {
		return threatIntelContext{}, false
	}
	return ti, ti.Source != "" || ti.Domain != "" || ti.IP != "" || ti.Confidence != 0
}

// indicator is the matched value in canonical form, or "" when the context
// does not say (the rule then still counts as a feed match, without one).
func (ti threatIntelContext) indicator() (value, typ string) {
	if d, ok := events.CanonicalDomain(ti.Domain); ok {
		return d, events.IndicatorDomain
	}
	if ip, ok := events.CanonicalIP(ti.IP); ok {
		return ip, events.IndicatorIP
	}
	return "", ""
}

func validSeverity(s string) bool {
	switch s {
	case events.SeverityCritical, events.SeverityHigh, events.SeverityMedium, events.SeverityLow:
		return true
	}
	return false
}

// Signature families, from what a rule says about itself.
const (
	familyMalware       = "malware"
	familyAttack        = "attack"
	familySuspicious    = "suspicious"
	familyInformational = "informational"
	familyUnclassified  = "unclassified"
)

// signatureScores is the confidence of a signature hit by family and EVE
// severity (1 is the most severe; 4 and above count as 3).
//
//	family          sev 1  sev 2  sev 3+   what it covers
//	malware/C2        80     70     60     the rule names malware or C2 traffic
//	attack            65     55     45     exploitation, web attacks, privilege gain
//	suspicious        45     35     25     reputation lists, hunting rules, miners, leaks
//	informational     20     15     10     policy, info, scans, protocol oddities
//	unclassified      50     35     20     category and message say nothing known
//
// The killswitch queues a detection for a human from confidence 50 and
// severity medium, and severity follows confidence (SeverityForConfidence):
// a malware/C2 rule clears that on its own at any severity, an attack rule
// at severity 1 or 2, an informational or policy rule never does. No
// signature reaches the auto-block bar (90): a rule names no target, so
// automatic enforcement is never on a signature alone anyway.
var signatureScores = map[string][3]int{
	familyMalware:       {80, 70, 60},
	familyAttack:        {65, 55, 45},
	familySuspicious:    {45, 35, 25},
	familyInformational: {20, 15, 10},
	familyUnclassified:  {50, 35, 20},
}

// signatureConfidence scores a signature hit. Without it a plain rule hit —
// even a severity-1 malware response — arrived with confidence 0 and the
// killswitch ignored it.
func signatureConfidence(signature, category string, severity int) int {
	col := 2
	switch {
	case severity == 1:
		col = 0
	case severity == 2:
		col = 1
	}
	return signatureScores[signatureFamily(signature, category)][col]
}

// signatureFamily reads the ruleset's own category from the message prefix
// ("ET MALWARE ...", "ET POLICY ...") first: ET assigns it per rule on
// purpose, while classtypes are coarse — policy-violation, which most
// "ET POLICY" rules use, carries priority 1 and so arrives as severity 1.
// The EVE category (the classtype's description) decides for rules without
// a known prefix, such as local ones.
func signatureFamily(signature, category string) string {
	if f := prefixFamily(signature); f != "" {
		return f
	}
	if f, ok := categoryFamilies[strings.ToLower(strings.TrimSpace(category))]; ok {
		return f
	}
	return familyUnclassified
}

func prefixFamily(signature string) string {
	words := strings.Fields(strings.ToUpper(signature))
	if len(words) == 0 {
		return ""
	}
	switch words[0] {
	case "SURICATA": // decoder, stream and app-layer events
		return familyInformational
	case "ET", "ETPRO":
		if len(words) > 1 {
			return etFamilies[words[1]]
		}
	}
	return ""
}

// etFamilies maps Emerging Threats ruleset categories.
var etFamilies = map[string]string{
	"MALWARE": familyMalware, "TROJAN": familyMalware, "CNC": familyMalware,
	"MOBILE_MALWARE": familyMalware, "EXPLOIT_KIT": familyMalware,
	"ATTACK_RESPONSE": familyMalware, "BOTCC": familyMalware, "WORM": familyMalware,

	"EXPLOIT": familyAttack, "WEB_SERVER": familyAttack, "WEB_CLIENT": familyAttack,
	"WEB_SPECIFIC_APPS": familyAttack, "PHISHING": familyAttack, "CURRENT_EVENTS": familyAttack,
	"SHELLCODE": familyAttack, "SQL": familyAttack, "DOS": familyAttack, "ACTIVEX": familyAttack,

	"HUNTING": familySuspicious, "COINMINER": familySuspicious, "ADWARE_PUP": familySuspicious,
	"DROP": familySuspicious, "DSHIELD": familySuspicious, "CINS": familySuspicious,
	"COMPROMISED": familySuspicious, "USER_AGENTS": familySuspicious, "TOR": familySuspicious,

	"INFO": familyInformational, "POLICY": familyInformational, "SCAN": familyInformational,
	"GAMES": familyInformational, "CHAT": familyInformational, "P2P": familyInformational,
	"DNS": familyInformational, "INAPPROPRIATE": familyInformational,
}

// categoryFamilies maps the classtype descriptions of Suricata's
// classification.config, lower-cased.
var categoryFamilies = map[string]string{
	"a network trojan was detected":                  familyMalware,
	"malware command and control activity detected":  familyMalware,
	"domain observed used for c2 detected":           familyMalware,
	"exploit kit activity detected":                  familyMalware,
	"successful credential theft detected":           familyMalware,
	"targeted malicious activity was detected":       familyMalware,
	"web application attack":                         familyAttack,
	"attempted administrator privilege gain":         familyAttack,
	"attempted user privilege gain":                  familyAttack,
	"successful administrator privilege gain":        familyAttack,
	"successful user privilege gain":                 familyAttack,
	"unsuccessful user privilege gain":               familyAttack,
	"executable code was detected":                   familyAttack,
	"misc attack":                                    familyAttack,
	"attempted denial of service":                    familyAttack,
	"denial of service":                              familyAttack,
	"detection of a denial of service attack":        familyAttack,
	"possible social engineering attempted":          familyAttack,
	"potentially bad traffic":                        familySuspicious,
	"crypto currency mining activity detected":       familySuspicious,
	"possibly unwanted program detected":             familySuspicious,
	"attempted information leak":                     familySuspicious,
	"information leak":                               familySuspicious,
	"large scale information leak":                   familySuspicious,
	"device retrieving external ip address detected": familySuspicious,
	"a suspicious filename was detected":             familySuspicious,
	"a suspicious string was detected":               familySuspicious,
	"a client was using an unusual port":             familySuspicious,
	"detection of a non-standard protocol or event":  familySuspicious,
	"potential corporate privacy violation":          familyInformational,
	"misc activity":                                  familyInformational,
	"not suspicious traffic":                         familyInformational,
	"unknown traffic":                                familyInformational,
	"generic protocol command decode":                familyInformational,
	"detection of a network scan":                    familyInformational,
	"generic icmp event":                             familyInformational,
	"a tcp connection was detected":                  familyInformational,
	"inappropriate content was detected":             familyInformational,
}

// DefaultLocalCIDRs is what LOCAL_NETWORKS defaults to: RFC 1918, IPv6
// unique-local, and loopback. A network with global IPv6 addresses on its
// LAN has to list its prefix.
var DefaultLocalCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "127.0.0.0/8"}

// LocalNetworks is the household's address space (LOCAL_NETWORKS).
type LocalNetworks struct {
	prefixes []netip.Prefix
}

// ParseLocalNetworks parses CIDRs, returning the ones it could not use.
func ParseLocalNetworks(cidrs []string) (LocalNetworks, []string) {
	var l LocalNetworks
	var bad []string
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			bad = append(bad, c)
			continue
		}
		l.prefixes = append(l.prefixes, p.Masked())
	}
	return l, bad
}

// Contains reports whether ip is a household address: inside a configured
// network, or loopback or link-local, which never leave the segment.
func (l LocalNetworks) Contains(ip string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsLinkLocalUnicast() {
		return true
	}
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
