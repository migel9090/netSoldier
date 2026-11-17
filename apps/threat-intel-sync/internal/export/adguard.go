package export

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/libs/indicator"
)

// /export/adguard is meant to be added to AdGuard Home as a blocklist
// (ADR-0001 decision 10): every rule in it is a block for the whole
// household, applied without anyone looking. So it serves only what the
// store holds — validated, never-block hosts removed, anomalous fetches
// held back by the volume guard — and is shaped for a periodic fetcher:
//
//   - AdGuard filter syntax, one "||domain^" rule per domain (blocks the
//     domain and its subdomains), sorted, a "!" comment header.
//   - The header carries the generation time, the rule count, the count per
//     source, which sources are quarantined or stale, and the never-block
//     list in force.
//   - The body is rendered once per content change and cached. ETag (a hash
//     of the content) and Last-Modified (when that content was generated)
//     answer If-None-Match / If-Modified-Since with 304; gzip is served to
//     clients that ask for it; Content-Length is always set, so a transfer
//     cut short is an error at the client rather than a shorter list.
//
// Failure never reads as "unblock everything". Before there is a set worth
// serving, the route answers 503 (cmd/threat-intel-sync's readiness gate),
// and AdGuard Home keeps the copy it has: its updater treats any non-200 as
// a failed update and leaves the filter file in place (checked against
// AdGuardHome internal/filtering/filter.go, 2026-09). Serving a cached
// "last good" body instead was considered and rejected: the store already
// is the last good set — feed failures never remove from it, and the guard
// keeps anomalous fetches out of it — and it is persisted, so there is no
// separate older snapshot that would be better. Once ready, the list is
// served even with no rules (no enabled source provides domains): that is
// a deliberate configuration, for example COMMERCIAL_MODE removing the
// abuse.ch feeds, and their domains must then stop being blocked.

// AdGuardStatus is what the header reports beside the rules.
type AdGuardStatus struct {
	Quarantined []string // sources whose latest fetch is held back
	Stale       []string // sources past their freshness objective
}

// AdGuardOptions configures the export.
type AdGuardOptions struct {
	Status  func() AdGuardStatus // nil: nothing to report
	Expires time.Duration        // the advisory "! Expires" period; 0 omits it
	Now     func() time.Time     // nil: time.Now
}

// AdGuard serves the domain indicators as an AdGuard filter list.
type AdGuard struct {
	store *ioc.Store
	opts  AdGuardOptions

	mu  sync.Mutex
	cur *adguardBody
}

type adguardBody struct {
	hash      string // of the content, without the generation time
	generated time.Time
	plain     []byte
	gz        []byte
	rules     int
}

// NewAdGuard returns the export over store.
func NewAdGuard(store *ioc.Store, opts AdGuardOptions) *AdGuard {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &AdGuard{store: store, opts: opts}
}

// HandleAdGuard returns an HTTP handler serving the domain IoC store as an
// AdGuard filter list, with default options.
func HandleAdGuard(store *ioc.Store) http.HandlerFunc {
	return NewAdGuard(store, AdGuardOptions{}).ServeHTTP
}

// WriteAdGuard writes domain indicators as an AdGuard-compatible filter
// list. Format: ||domain^ (blocks domain and all subdomains).
//
// A rule is raw filter syntax, so only a value that passes domain validation
// in canonical form — letters, digits, hyphens and dots — and is not on the
// never-block list is written. The old exporter turned "*.*.*" into "||*.*^"
// and would have passed "evil.example^$dnsrewrite=…" straight into the
// filter engine.
func WriteAdGuard(w io.Writer, indicators []ioc.Indicator) {
	c := renderAdGuard(indicators, AdGuardStatus{}, 0)
	w.Write(c.body(time.Now())) //nolint:errcheck // the caller owns the writer
}

// ServeHTTP serves the current list, or 304 when the client already has it.
func (a *AdGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b := a.current()
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Vary", "Accept-Encoding")
	body, etag := b.plain, `"`+b.hash+`"`
	if acceptsGzip(r) {
		body, etag = b.gz, `"`+b.hash+`-gz"`
		h.Set("Content-Encoding", "gzip")
	}
	h.Set("ETag", etag)
	h.Set("X-Netsoldier-Rules", fmt.Sprint(b.rules))
	http.ServeContent(w, r, "", b.generated, bytes.NewReader(body))
}

// current returns the cached body, rendering a new one when the content
// changed. The generation time is the time this content first appeared, so
// an unchanged list keeps its ETag and Last-Modified across fetches.
func (a *AdGuard) current() *adguardBody {
	var st AdGuardStatus
	if a.opts.Status != nil {
		st = a.opts.Status()
	}
	c := renderAdGuard(a.store.ByType(ioc.TypeDomain), st, a.opts.Expires)

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cur != nil && a.cur.hash == c.hash {
		return a.cur
	}
	now := a.opts.Now().UTC().Truncate(time.Second)
	if a.cur != nil && !now.After(a.cur.generated) {
		// Last-Modified has one-second resolution: a new content must not
		// share the old one's timestamp, or If-Modified-Since would hide it.
		now = a.cur.generated.Add(time.Second)
	}
	plain := c.body(now)
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	zw.Write(plain) //nolint:errcheck // writes to memory
	zw.Close()
	a.cur = &adguardBody{hash: c.hash, generated: now, plain: plain, gz: gz.Bytes(), rules: c.n}
	return a.cur
}

type adguardContent struct {
	meta  string // header lines that are part of the content
	rules string // the rule lines
	n     int    // the number of rules
	hash  string // of meta and rules
}

func (c adguardContent) body(generated time.Time) []byte {
	var b strings.Builder
	b.Grow(len(c.meta) + len(c.rules) + 512)
	b.WriteString("! Title: netSoldier threat intelligence\n")
	b.WriteString("! Description: Domains named by the threat feeds this netSoldier instance follows, " +
		"after validation, the never-block list and the volume guard. Generated; do not edit.\n")
	b.WriteString("! Homepage: https://github.com/migel9090/netSoldier\n")
	fmt.Fprintf(&b, "! Last modified: %s\n", generated.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "! Version: %s\n", c.hash[:12])
	b.WriteString(c.meta)
	b.WriteString("!\n")
	b.WriteString(c.rules)
	return []byte(b.String())
}

func renderAdGuard(indicators []ioc.Indicator, st AdGuardStatus, expires time.Duration) adguardContent {
	perSource := map[string]int{}
	seen := make(map[string]struct{}, len(indicators))
	kept := make([]string, 0, len(indicators))
	for _, ind := range indicators {
		if ind.Type != ioc.TypeDomain || !exportable("adguard", ind) {
			continue
		}
		if _, dup := seen[ind.Value]; dup {
			continue
		}
		seen[ind.Value] = struct{}{}
		kept = append(kept, ind.Value)
		for _, src := range strings.Split(ind.Source, ",") {
			if src = indicator.Text(src, indicator.MaxSourceLen); src != "" && isLabel(src) {
				perSource[src]++
			}
		}
	}
	sort.Strings(kept)

	var meta strings.Builder
	if expires > 0 {
		hours := int((expires + time.Hour - 1) / time.Hour)
		fmt.Fprintf(&meta, "! Expires: %d hours (update frequency)\n", hours)
	}
	fmt.Fprintf(&meta, "! Entries: %d\n", len(kept))
	if len(kept) == 0 {
		meta.WriteString("! No enabled source currently provides domain indicators.\n")
	}
	fmt.Fprintf(&meta, "! Sources: %s\n", formatCounts(perSource))
	fmt.Fprintf(&meta, "! Quarantined sources: %s\n", formatNames(st.Quarantined))
	fmt.Fprintf(&meta, "! Stale sources: %s\n", formatNames(st.Stale))
	nb := indicator.NeverBlockList()
	fmt.Fprintf(&meta, "! Never-block list: %d entries, snapshot %s\n", nb.Entries, nb.Snapshot)

	var rules strings.Builder
	rules.Grow(len(kept) * 24)
	for _, d := range kept {
		rules.WriteString("||")
		rules.WriteString(d)
		rules.WriteString("^\n")
	}
	c := adguardContent{meta: meta.String(), rules: rules.String(), n: len(kept)}
	sum := sha256.Sum256([]byte(c.meta + c.rules))
	c.hash = hex.EncodeToString(sum[:16])
	return c
}

func formatCounts(m map[string]int) string {
	if len(m) == 0 {
		return "none"
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = fmt.Sprintf("%s=%d", n, m[n])
	}
	return strings.Join(parts, " ")
}

func formatNames(names []string) string {
	clean := make([]string, 0, len(names))
	for _, n := range names {
		if isLabel(n) {
			clean = append(clean, n)
		}
	}
	if len(clean) == 0 {
		return "none"
	}
	sort.Strings(clean)
	return strings.Join(clean, " ")
}

// isLabel admits the source names that may appear in a header comment:
// letters, digits, '-', '_' and '.'. A source name comes from feed content
// (MISP's, for one), and a header line must stay one line.
func isLabel(s string) bool {
	if s == "" || len(s) > indicator.MaxSourceLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
			return false
		}
	}
	return true
}

// acceptsGzip reports whether the request's Accept-Encoding allows gzip
// (Go's HTTP client asks for it unless compression is switched off).
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			continue
		}
		q := strings.ReplaceAll(strings.ToLower(params), " ", "")
		return q != "q=0" && q != "q=0.0" && q != "q=0.00" && q != "q=0.000"
	}
	return false
}
