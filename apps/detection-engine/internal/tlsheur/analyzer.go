// Package tlsheur flags suspicious TLS clients from passive metadata only
// (step 110): TLS-client-fingerprint/JA3 IoC matches and fingerprint/SNI/DNS
// correlation. The fingerprint is JA4-format (tls_client_fp).
// No decryption is involved — everything derives from the ClientHello
// metadata Zeek already logged.
package tlsheur

import (
	"container/list"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/detection"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/ingest"
	"github.com/migel9090/netSoldier/apps/detection-engine/internal/iocmatch"
	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	suppressWindow = time.Hour
	maxSuppressed  = 16384
	// sweepEvery is how often expired suppressions are dropped. Insertion
	// order is expiry order, so a sweep only walks what has expired.
	sweepEvery = time.Minute
)

var (
	tlsFindings = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "tls_heuristic_findings_total",
		Help:      "Suspicious TLS client findings by reason.",
	}, []string{"reason"})
	suppressEvicted = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "detection_engine",
		Name:      "tls_suppressions_evicted_total",
		Help:      "TLS finding suppressions dropped before expiry to keep the table bounded; the finding can fire again.",
	})
)

func init() {
	prometheus.MustRegister(tlsFindings, suppressEvicted)
}

// Resolver answers "which name did this client resolve to this address"
// (dnscache.Cache). Per client: a CDN address carries many names, and the
// one another device looked up says nothing about this connection.
type Resolver interface {
	Get(client, ip string) string
}

// Analyzer inspects unified TLS client events and emits alerts for
// fingerprint IoC matches and DNS/SNI inconsistencies.
type Analyzer struct {
	matcher   *iocmatch.Matcher
	resolver  Resolver
	localNets []*net.IPNet
	emit      func(detection.Alert)

	mu  sync.Mutex
	now func() time.Time
	// suppressed maps a finding key to its element in order, which holds
	// the suppressions oldest first.
	suppressed map[string]*list.Element
	order      *list.List
	nextSweep  time.Time
}

// suppression is one entry of the suppression table.
type suppression struct {
	key   string
	until time.Time
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
		now:        time.Now,
		suppressed: make(map[string]*list.Element),
		order:      list.New(),
	}
}

// DefaultLocalCIDRs is ingest's LOCAL_NETWORKS default: RFC 1918, IPv6
// unique-local, loopback.
var DefaultLocalCIDRs = ingest.DefaultLocalCIDRs

// Handle inspects one TLS client observation.
func (a *Analyzer) Handle(ev ingest.SensorEvent) {
	if ev.Kind != "tls-client" || a.isLocal(ev.DstIP) {
		return
	}

	// 1) Fingerprint IoC match — works even when the sensor's intel file
	// lags behind the live matcher state.
	if ev.Indicator != "" {
		if ioc, ok := a.matcher.MatchHash(ev.Indicator); ok {
			a.alert(ev, finding{
				reason: "tlsfp-ioc", key: ev.Indicator,
				indicator: strings.ToLower(ev.Indicator), indicatorType: firstNonEmpty(ioc.Type, events.IndicatorTLSFP),
				severity: ioc.Severity, confidence: ioc.Confidence, ioc: ioc,
				summary: fmt.Sprintf("TLS client fingerprint %s is listed by %s", ev.Indicator, firstNonEmpty(ioc.Source, "a feed")),
			})
			return
		}
	}
	if ev.JA3 != "" {
		if ioc, ok := a.matcher.MatchHash(ev.JA3); ok {
			a.alert(ev, finding{
				reason: "ja3-ioc", key: ev.JA3,
				indicator: strings.ToLower(ev.JA3), indicatorType: firstNonEmpty(ioc.Type, events.IndicatorJA3),
				severity: ioc.Severity, confidence: ioc.Confidence, ioc: ioc,
				summary: fmt.Sprintf("TLS client JA3 %s is listed by %s", ev.JA3, firstNonEmpty(ioc.Source, "a feed")),
			})
			return
		}
	}

	resolved := ""
	if a.resolver != nil {
		resolved = a.resolver.Get(ev.SrcIP, ev.DstIP)
	}

	// 2) SNI does not belong to the domain the client actually resolved
	// for this IP — domain-fronting shaped. Registrable-domain comparison
	// keeps CDN multi-hosting from firing constantly.
	if ev.SNI != "" && resolved != "" && !sameRegistrableDomain(ev.SNI, resolved) {
		f := finding{
			reason: "sni-dns-mismatch", key: ev.SNI + " vs " + resolved,
			severity: "low", confidence: 30,
			summary: fmt.Sprintf("TLS SNI %s does not match %s, the name %s was resolved from",
				ev.SNI, resolved, ev.DstIP),
		}
		if d, ok := events.CanonicalDomain(ev.SNI); ok {
			f.indicator, f.indicatorType = d, events.IndicatorDomain
		}
		a.alert(ev, f)
		return
	}

	// 3) TLS straight to an external IP: no SNI and no DNS resolution
	// observed — hardcoded-IP C2 shaped.
	if ev.SNI == "" && resolved == "" {
		ip, _ := events.CanonicalIP(ev.DstIP)
		a.alert(ev, finding{
			reason: "dns-less-tls", key: ev.DstIP,
			indicator: ip, indicatorType: events.IndicatorIP,
			severity: "low", confidence: 20,
			summary: fmt.Sprintf("TLS to %s with no SNI and no DNS lookup before it", ev.DstIP),
		})
	}
}

// finding is one TLS heuristic result before it becomes an alert.
type finding struct {
	reason string
	// key identifies the finding for suppression.
	key string
	// indicator is what the signal attests, canonical; "" when none.
	indicator, indicatorType string
	severity                 string
	confidence               int
	ioc                      iocmatch.IoC
	summary                  string
}

func (a *Analyzer) alert(ev ingest.SensorEvent, f finding) {
	if a.suppress(ev.SrcIP + "|" + ev.DstIP + "|" + f.reason + "|" + f.key) {
		return
	}
	tlsFindings.WithLabelValues(f.reason).Inc()

	clientIP := ev.SrcIP
	if c, ok := events.CanonicalIP(clientIP); ok {
		clientIP = c
	}
	confidence := detection.ClampConfidence(f.confidence)
	source := firstNonEmpty(f.ioc.Source, "tls-heuristics")
	alert := detection.Alert{
		// One finding per handshake row, so the row names it.
		Record:      ev.Record(),
		Timestamp:   ev.Timestamp,
		Summary:     f.summary + " (" + clientIP + " → " + ev.DstIP + ")",
		Domain:      observedName(ev),
		ClientIP:    clientIP,
		MatchedIoC:  f.indicator,
		IoCType:     f.indicatorType,
		Severity:    f.severity,
		Source:      source,
		Confidence:  confidence,
		Threat:      firstNonEmpty(f.ioc.Threat, f.reason),
		MitreID:     f.ioc.MitreID,
		MitreName:   f.ioc.MitreName,
		SignalClass: detection.SignalTLS,
		Signals: []events.Signal{{
			Class: detection.SignalTLS, Confidence: confidence,
			Indicator: f.indicator, IndicatorType: f.indicatorType, Source: source,
		}},
		Target: destination(ev),
	}
	if f.indicator == "" {
		alert.IoCType = ""
		alert.Signals[0].IndicatorType = ""
	}
	if alert.MitreID == "" {
		alert.MitreID, alert.MitreName = "T1071.001", "Application Layer Protocol: Web Protocols"
	}
	if alert.Severity == "" {
		alert.Severity = "medium"
	}

	slog.Info("suspicious tls client", "reason", f.reason, "client", ev.SrcIP,
		"dst", ev.DstIP, "sni", ev.SNI, "tls_client_fp", ev.Indicator)
	a.emit(alert)
}

// observedName is the DNS name the client named in the handshake, when it
// is a hostname (clients do put literal addresses in SNI).
func observedName(ev ingest.SensorEvent) string {
	if d, ok := events.CanonicalDomain(ev.SNI); ok {
		return d
	}
	return ""
}

// destination is what the client was observed talking to: the SNI name when
// there is a usable one, the address otherwise. A TLS finding is a heuristic,
// even when the fingerprint is on a feed — a fingerprint identifies client
// software, not a place to block — so this is where it points, and the
// policy decides whether that is enough.
func destination(ev ingest.SensorEvent) *events.Target {
	if d, ok := events.CanonicalDomain(ev.SNI); ok {
		return &events.Target{Type: events.TargetDomain, Value: d}
	}
	if ip, ok := events.CanonicalIP(ev.DstIP); ok {
		return &events.Target{Type: events.TargetIP, Value: ip}
	}
	return nil
}

// suppress returns true when the same finding fired within the window, and
// otherwise starts suppressing it.
//
// The table is bounded by maxSuppressed whatever the input: when it is full
// the oldest suppression goes. It used to sweep the whole map on every
// insert past the limit and insert anyway when the sweep freed nothing, so a
// client presenting a fresh random SNI on every handshake — each one a new
// key — grew it without bound and made every insert walk all of it.
// Evicting early only means a finding can fire again sooner; it never
// silences one.
func (a *Analyzer) suppress(key string) bool {
	now := a.now()
	a.mu.Lock()
	defer a.mu.Unlock()

	if !now.Before(a.nextSweep) {
		a.sweep(now)
		a.nextSweep = now.Add(sweepEvery)
	}
	if el, ok := a.suppressed[key]; ok {
		s := el.Value.(*suppression)
		if now.Before(s.until) {
			return true
		}
		s.until = now.Add(suppressWindow)
		a.order.MoveToBack(el)
		return false
	}
	for a.order.Len() >= maxSuppressed {
		oldest := a.order.Front()
		delete(a.suppressed, oldest.Value.(*suppression).key)
		a.order.Remove(oldest)
		suppressEvicted.Inc()
	}
	a.suppressed[key] = a.order.PushBack(&suppression{key: key, until: now.Add(suppressWindow)})
	return false
}

// sweep drops expired suppressions from the front of the order.
func (a *Analyzer) sweep(now time.Time) {
	for el := a.order.Front(); el != nil; el = a.order.Front() {
		s := el.Value.(*suppression)
		if now.Before(s.until) {
			return
		}
		delete(a.suppressed, s.key)
		a.order.Remove(el)
	}
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
