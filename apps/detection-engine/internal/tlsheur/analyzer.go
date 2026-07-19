// Package tlsheur flags suspicious TLS clients from passive metadata only
// (step 110): TLS-client-fingerprint/JA3 IoC matches and fingerprint/SNI/DNS
// correlation. The fingerprint is JA4-format (tls_client_fp).
// No decryption is involved — everything derives from the ClientHello
// metadata Zeek already logged.
package tlsheur

import (
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	suppressWindow = time.Hour
	maxSuppressed  = 16384
)

var tlsFindings = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Name:      "tls_heuristic_findings_total",
	Help:      "Suspicious TLS client findings by reason.",
}, []string{"reason"})

func init() {
	prometheus.MustRegister(tlsFindings)
}

// Resolver answers "which domain did this IP resolve from" (correlator
// DNS cache).
type Resolver interface {
	Get(ip string) string
}

// Analyzer inspects unified TLS client events and emits alerts for
// fingerprint IoC matches and DNS/SNI inconsistencies.
type Analyzer struct {
	matcher   *iocmatch.Matcher
	resolver  Resolver
	localNets []*net.IPNet
	emit      func(detection.Alert)

	mu         sync.Mutex
	suppressed map[string]time.Time
}

func New(m *iocmatch.Matcher, r Resolver, localCIDRs []string, emit func(detection.Alert)) *Analyzer {
	var nets []*net.IPNet
	for _, c := range localCIDRs {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
			nets = append(nets, n)
		}
	}
	return &Analyzer{
		matcher:    m,
		resolver:   r,
		localNets:  nets,
		emit:       emit,
		suppressed: make(map[string]time.Time),
	}
}

// DefaultLocalCIDRs covers RFC1918 plus loopback.
var DefaultLocalCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}

// Handle inspects one TLS client observation.
func (a *Analyzer) Handle(ev ingest.SensorEvent) {
	if ev.Kind != "tls-client" || a.isLocal(ev.DstIP) {
		return
	}

	// 1) Fingerprint IoC match — works even when the sensor's intel file
	// lags behind the live matcher state.
	if ev.Indicator != "" {
		if ioc, ok := a.matcher.MatchHash(ev.Indicator); ok {
			a.alert(ev, "tlsfp-ioc", ev.Indicator, ioc.Severity, ioc.Confidence, ioc)
			return
		}
	}
	if ev.JA3 != "" {
		if ioc, ok := a.matcher.MatchHash(ev.JA3); ok {
			a.alert(ev, "ja3-ioc", ev.JA3, ioc.Severity, ioc.Confidence, ioc)
			return
		}
	}

	resolved := ""
	if a.resolver != nil {
		resolved = a.resolver.Get(ev.DstIP)
	}

	// 2) SNI does not belong to the domain the client actually resolved
	// for this IP — domain-fronting shaped. Registrable-domain comparison
	// keeps CDN multi-hosting from firing constantly.
	if ev.SNI != "" && resolved != "" && !sameRegistrableDomain(ev.SNI, resolved) {
		a.alert(ev, "sni-dns-mismatch", ev.SNI+" vs "+resolved, "low", 30, iocmatch.IoC{})
		return
	}

	// 3) TLS straight to an external IP: no SNI and no DNS resolution
	// observed — hardcoded-IP C2 shaped.
	if ev.SNI == "" && resolved == "" {
		a.alert(ev, "dns-less-tls", ev.DstIP, "low", 20, iocmatch.IoC{})
	}
}

func (a *Analyzer) alert(ev ingest.SensorEvent, reason, value, severity string, confidence int, ioc iocmatch.IoC) {
	if a.suppress(ev.SrcIP + "|" + ev.DstIP + "|" + reason + "|" + value) {
		return
	}
	tlsFindings.WithLabelValues(reason).Inc()

	alert := detection.Alert{
		Timestamp:  ev.Timestamp,
		Domain:     firstNonEmpty(ev.SNI, ev.DstIP),
		ClientIP:   ev.SrcIP,
		MatchedIoC: value,
		Severity:   severity,
		Source:     firstNonEmpty(ioc.Source, "tls-heuristics"),
		Confidence: confidence,
		Threat:     firstNonEmpty(ioc.Threat, reason),
		MitreID:    ioc.MitreID,
		MitreName:  ioc.MitreName,
	}
	if alert.MitreID == "" {
		alert.MitreID, alert.MitreName = "T1071.001", "Application Layer Protocol: Web Protocols"
	}
	if alert.Severity == "" {
		alert.Severity = "medium"
	}

	slog.Info("suspicious tls client", "reason", reason, "client", ev.SrcIP,
		"dst", ev.DstIP, "sni", ev.SNI, "tls_client_fp", ev.Indicator)
	a.emit(alert)
}

// suppress returns true when the same finding fired within the window.
func (a *Analyzer) suppress(key string) bool {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()

	if until, ok := a.suppressed[key]; ok && now.Before(until) {
		return true
	}
	if len(a.suppressed) >= maxSuppressed {
		for k, until := range a.suppressed {
			if now.After(until) {
				delete(a.suppressed, k)
			}
		}
	}
	a.suppressed[key] = now.Add(suppressWindow)
	return false
}

func (a *Analyzer) isLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // never alert on unparsable destinations
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsMulticast() {
		return true
	}
	for _, n := range a.localNets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// sameRegistrableDomain compares the last two DNS labels, a pragmatic
// eTLD+1 approximation for home traffic.
func sameRegistrableDomain(a, b string) bool {
	return lastLabels(a, 2) == lastLabels(b, 2)
}

func lastLabels(domain string, n int) string {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	parts := strings.Split(domain, ".")
	if len(parts) <= n {
		return domain
	}
	return strings.Join(parts[len(parts)-n:], ".")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
