package export

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// WriteSuricataDataset writes indicators as a Suricata dataset file, one
// value per line. Suricata stores string-type datasets base64-encoded;
// ip, md5 and sha256 datasets use the raw value.
func WriteSuricataDataset(w io.Writer, indicators []ioc.Indicator, base64Encode bool) {
	sort.Slice(indicators, func(i, j int) bool {
		return indicators[i].Value < indicators[j].Value
	})
	for _, ind := range indicators {
		if base64Encode {
			fmt.Fprintln(w, base64.StdEncoding.EncodeToString([]byte(ind.Value)))
		} else {
			fmt.Fprintln(w, ind.Value)
		}
	}
}

// WriteSuricataJSONDataset writes indicators as a Suricata ndjson dataset
// (format ndjson, one JSON object per line). The match value is stored
// under valueKey; the remaining fields enrich the alert via context_key.
func WriteSuricataJSONDataset(w io.Writer, indicators []ioc.Indicator, valueKey string) {
	sort.Slice(indicators, func(i, j int) bool {
		return indicators[i].Value < indicators[j].Value
	})
	enc := json.NewEncoder(w)
	for _, ind := range indicators {
		entry := map[string]any{
			valueKey:     ind.Value,
			"source":     ind.Source,
			"severity":   severityFromConfidence(ind.Confidence),
			"confidence": ind.Confidence,
		}
		if ind.Threat != "" {
			entry["threat"] = ind.Threat
		}
		if len(ind.Tags) > 0 {
			entry["tags"] = ind.Tags
		}
		enc.Encode(entry) //nolint:errcheck // map[string]any of scalars cannot fail
	}
}

// HandleSuricataDataset returns an HTTP handler serving indicators of the
// given types as a Suricata dataset file.
func HandleSuricataDataset(store *ioc.Store, base64Encode bool, types ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		WriteSuricataDataset(w, collectForSuricata(store, types), base64Encode)
	}
}

// suricataSeedEntries guarantee json datasets are never empty: Suricata
// fails to load a rule whose ndjson dataset file has no valid entries.
// The sentinel values cannot occur in real traffic (.invalid TLD,
// TEST-NET-1 address).
var suricataSeedEntries = map[string]ioc.Indicator{
	"domain": {Value: "sentinel.netsoldier.invalid", Source: "netsoldier-seed"},
	"ip":     {Value: "192.0.2.254", Source: "netsoldier-seed"},
}

// HandleSuricataJSONDataset returns an HTTP handler serving indicators of
// the given types as a Suricata ndjson dataset with enrichment context.
func HandleSuricataJSONDataset(store *ioc.Store, valueKey string, types ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		indicators := collectForSuricata(store, types)
		if seed, ok := suricataSeedEntries[valueKey]; ok {
			indicators = append(indicators, seed)
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		WriteSuricataJSONDataset(w, indicators, valueKey)
	}
}

// collectForSuricata gathers indicators of the given types, dropping
// values Suricata datasets cannot parse: ip-type datasets accept only
// exact IPv4/IPv6 addresses, so CIDR ranges (e.g. Spamhaus DROP) are
// excluded — range matching is covered by detection-engine.
func collectForSuricata(store *ioc.Store, types []string) []ioc.Indicator {
	var indicators []ioc.Indicator
	for _, t := range types {
		batch := store.ByType(t)
		if t == ioc.TypeIP {
			kept := batch[:0]
			for _, ind := range batch {
				if net.ParseIP(ind.Value) != nil {
					kept = append(kept, ind)
				}
			}
			batch = kept
		}
		indicators = append(indicators, batch...)
	}
	return indicators
}

func severityFromConfidence(confidence int) string {
	switch {
	case confidence >= 80:
		return "high"
	case confidence >= 50:
		return "medium"
	case confidence > 0:
		return "low"
	default:
		return "unknown"
	}
}
