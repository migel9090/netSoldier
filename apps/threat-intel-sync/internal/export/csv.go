package export

import (
	"encoding/csv"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// csvHeader is the schema contract with the Vector aggregator's `ioc` file
// enrichment table (deploy/observability/vector/values.yaml): lookups match
// on `value`, the remaining columns become threat_source / threat_name
// context on flows, DNS queries and alerts.
var csvHeader = []string{"value", "type", "source", "threat", "confidence"}

// WriteCSV writes indicators of the given types as a CSV enrichment table.
// CIDR ranges are dropped: the enrichment lookup is an exact-value match,
// so a range can never be a lookup key. The header row is always written —
// an IoC-less store still yields a loadable table.
func WriteCSV(w io.Writer, indicators []ioc.Indicator, types ...string) error {
	wanted := make(map[string]bool, len(types))
	for _, t := range types {
		wanted[t] = true
	}

	kept := make([]ioc.Indicator, 0, len(indicators))
	for _, ind := range indicators {
		if !wanted[ind.Type] {
			continue
		}
		if ind.Type == ioc.TypeIP && net.ParseIP(ind.Value) == nil {
			continue
		}
		kept = append(kept, ind)
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].Value < kept[j].Value })

	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, ind := range kept {
		if err := cw.Write([]string{
			ind.Value, ind.Type, ind.Source, ind.Threat,
			strconv.Itoa(ind.Confidence),
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// HandleCSV returns an HTTP handler serving indicators of the given types
// as a CSV enrichment table for Vector.
func HandleCSV(store *ioc.Store, types ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		if err := WriteCSV(w, store.All(), types...); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}
