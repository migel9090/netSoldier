package export

import (
	"fmt"
	"io"
	"net/http"
	"sort"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// WriteAdGuard writes domain indicators as an AdGuard-compatible filter list.
// Format: ||domain^ (blocks domain and all subdomains).
//
// A rule is raw filter syntax, so only a value that passes domain validation
// in canonical form — letters, digits, hyphens and dots — is written. The
// old exporter turned "*.*.*" into "||*.*^" and would have passed
// "evil.example^$dnsrewrite=…" straight into the filter engine.
func WriteAdGuard(w io.Writer, indicators []ioc.Indicator) {
	kept := indicators[:0:0]
	for _, ind := range indicators {
		if ind.Type == ioc.TypeDomain && exportable("adguard", ind) {
			kept = append(kept, ind)
		}
	}
	sort.Slice(kept, func(i, j int) bool {
		return kept[i].Value < kept[j].Value
	})

	fmt.Fprintln(w, "! Title: netSoldier Threat Intel")
	fmt.Fprintf(w, "! Entries: %d\n", len(kept))
	fmt.Fprintln(w, "! Homepage: https://github.com/migel9090/netSoldier")
	fmt.Fprintln(w, "!")
	for _, ind := range kept {
		fmt.Fprintf(w, "||%s^\n", ind.Value)
	}
}

// HandleAdGuard returns an HTTP handler serving the domain IoC store
// as an AdGuard filter list.
func HandleAdGuard(store *ioc.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		domains := store.ByType(ioc.TypeDomain)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		WriteAdGuard(w, domains)
	}
}
