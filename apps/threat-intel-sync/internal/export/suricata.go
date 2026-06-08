package export

import (
	"encoding/base64"
	"fmt"
	"io"
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

// HandleSuricataDataset returns an HTTP handler serving indicators of the
// given types as a Suricata dataset file.
func HandleSuricataDataset(store *ioc.Store, base64Encode bool, types ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var indicators []ioc.Indicator
		for _, t := range types {
			indicators = append(indicators, store.ByType(t)...)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		WriteSuricataDataset(w, indicators, base64Encode)
	}
}
