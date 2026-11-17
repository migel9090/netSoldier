package export

import (
	"fmt"
	"log/slog"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
	"github.com/migel9090/netSoldier/libs/indicator"
	"github.com/prometheus/client_golang/prometheus"
)

// exportDropped counts indicators an exporter refused to write. Ingest
// validation makes this zero in normal operation; anything else means a
// value reached the store without passing through it, which is a bug.
var exportDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "threat_intel",
	Name:      "export_indicators_dropped_total",
	Help:      "Indicators an exporter refused because they fail validation in canonical form or name a never-block host.",
}, []string{"format"})

func init() {
	prometheus.MustRegister(exportDropped)
}

// exportable is each exporter's second line of defence behind ingest
// validation: a value is written only if the shared rules accept it, it is
// already in canonical spelling and it is not on the never-block list. A
// format that cannot represent a value safely — an AdGuard rule, a Zeek TSV
// line, a raw Suricata dataset line — must never receive one that slipped
// past ingest (an older database, a future code path that forgets to
// validate), and no export may name a host that must never be blocked.
func exportable(format string, ind ioc.Indicator) bool {
	v, err := indicator.Value(ind.Type, ind.Value)
	if err == nil && v != ind.Value {
		err = fmt.Errorf("not in canonical form (%q)", v)
	}
	if err == nil {
		err = indicator.CheckBlockable(ind.Type, v)
	}
	if err == nil {
		return true
	}
	exportDropped.WithLabelValues(format).Inc()
	slog.Error("export refused an indicator that fails validation",
		"format", format, "type", ind.Type, "value", indicator.Text(ind.Value, 128), "error", err)
	return false
}
