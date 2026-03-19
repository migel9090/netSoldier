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
func WriteAdGuard(w io.Writer, indicators []ioc.Indicator) {
	sort.Slice(indicators, func(i, j int) bool {
		return indicators[i].Value < indicators[j].Value
	})

	fmt.Fprintln(w, "! Title: netSoldier Threat Intel")
	fmt.Fprintf(w, "! Entries: %d\n", len(indicators))
	fmt.Fprintln(w, "! Homepage: https://github.com/migel9090/netSoldier")
	fmt.Fprintln(w, "!")
	for _, ind := range indicators {
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
