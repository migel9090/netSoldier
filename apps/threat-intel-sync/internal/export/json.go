package export

import (
	"encoding/json"
	"net/http"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// HandleJSON returns an HTTP handler serving the full IoC store as a
// JSON array. The detection-engine fetches this to populate its matcher.
func HandleJSON(store *ioc.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(store.All())
	}
}
