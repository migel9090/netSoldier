package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
)

type connectionRow struct {
	Timestamp string    `json:"timestamp"`
	DstIP     string    `json:"dst_ip"`
	DstDomain string    `json:"dst_domain"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  uint8     `json:"protocol"`
	BytesIn   ch.UInt64 `json:"bytes_in"`
	BytesOut  ch.UInt64 `json:"bytes_out"`
	Duration  ch.UInt64 `json:"duration_ms"`
	// Service is the application protocol Zeek recognised ("ssl", "dns",
	// "http", ...), "" when it recognised none.
	Service string `json:"service"`
}

type dnsRow struct {
	Timestamp  string `json:"timestamp"`
	Domain     string `json:"domain"`
	QueryType  string `json:"query_type"`
	Answer     string `json:"answer"`
	Status     string `json:"status"`
	ResponseMs uint16 `json:"response_ms"`
	Blocked    uint8  `json:"blocked"`
}

type alertRow struct {
	Timestamp  string `json:"timestamp"`
	ID         string `json:"id"`
	Summary    string `json:"summary"`
	Domain     string `json:"domain"`
	QueryType  string `json:"query_type"`
	MatchedIoC string `json:"matched_ioc"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
	// SignalClass, Threat and Suppressed are what detection-engine adds
	// (migration 030); "" and false on rows from before it wrote the table.
	SignalClass string  `json:"signal_class"`
	Threat      string  `json:"threat"`
	Suppressed  ch.Bool `json:"suppressed"`
}

// The per-device history queries (step 125.10). Each names the device by
// its current address, and the alerts also by its MAC: detection-engine
// stamps alerts with the MAC device-inventory reported, which stays right
// when the DHCP lease moves.
const (
	// connectionsQuery reads the device's latest connections from Zeek
	// (network_flows is a view over zeek_conn, migration 028) and names
	// each destination by the TLS server name or HTTP host Zeek logged for
	// the same connection. The lookups are bounded to the time span of the
	// connections shown: both tables are sorted by time. No alias may repeat
	// a column name: ClickHouse substitutes aliases into WHERE.
	connectionsQuery = `WITH (
		SELECT min(timestamp) FROM (
			SELECT timestamp FROM network_flows
			WHERE src_ip = {ip:String}
			ORDER BY timestamp DESC
			LIMIT 100)
	) AS since
	SELECT
		c.timestamp AS timestamp, c.dst_ip AS dst_ip,
		if(s.sni != '', s.sni, h.http_host) AS dst_domain,
		c.dst_port AS dst_port, c.protocol AS protocol,
		c.bytes_in AS bytes_in, c.bytes_out AS bytes_out,
		c.duration_ms AS duration_ms, c.service AS service
	FROM (
		SELECT uid, timestamp, dst_ip, dst_port, protocol, bytes_in, bytes_out, duration_ms, service
		FROM network_flows
		WHERE src_ip = {ip:String}
		ORDER BY timestamp DESC
		LIMIT 100
	) AS c
	LEFT JOIN (
		SELECT uid, any(server_name) AS sni FROM zeek_ssl
		WHERE src_ip = {ip:String} AND timestamp >= since AND server_name != ''
		GROUP BY uid
	) AS s ON s.uid = c.uid
	LEFT JOIN (
		SELECT uid, any(host) AS http_host FROM zeek_http
		WHERE src_ip = {ip:String} AND timestamp >= since AND host != ''
		GROUP BY uid
	) AS h ON h.uid = c.uid
	ORDER BY timestamp DESC`

	// dnsQuery reads the AdGuard query log detection-engine copies
	// (migration 031).
	dnsQuery = `SELECT
		timestamp, domain, query_type, answer, status, response_ms, blocked
	FROM dns_queries
	WHERE client_ip = {ip:String}
	ORDER BY timestamp DESC
	LIMIT 100`

	// alertsQuery reads the alerts detection-engine copies (migration 030).
	alertsQuery = `SELECT
		timestamp, id, summary, domain, query_type, matched_ioc, severity, source,
		signal_class, threat, suppressed
	FROM alerts
	WHERE client_mac = {mac:String} OR (client_mac = '' AND client_ip = {ip:String})
	ORDER BY timestamp DESC
	LIMIT 50`
)

func (h *Handler) DeviceConnections(w http.ResponseWriter, r *http.Request) {
	rows := []connectionRow{}
	h.deviceHistory(w, r, "network_flows", connectionsQuery, &rows)
}

func (h *Handler) DeviceDNS(w http.ResponseWriter, r *http.Request) {
	rows := []dnsRow{}
	h.deviceHistory(w, r, "dns_queries", dnsQuery, &rows)
}

func (h *Handler) DeviceAlerts(w http.ResponseWriter, r *http.Request) {
	rows := []alertRow{}
	h.deviceHistory(w, r, "alerts", alertsQuery, &rows)
}

// deviceHistory answers a per-device ClickHouse view keyed by the device's
// current address. No device, no address or no ClickHouse configured is an
// empty list; a failing ClickHouse is a 502, logged and counted, not an empty
// list that looks like "nothing happened".
func (h *Handler) deviceHistory(w http.ResponseWriter, r *http.Request, table, query string, rows any) {
	mac, ok := pathMAC(w, r)
	if !ok {
		return
	}
	device, err := h.store.GetDevice(mac)
	if err != nil {
		slog.Error("get device failed", "mac", mac, "error", err)
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}
	if device == nil || device.IP == "" || h.ch == nil {
		writeJSON(w, http.StatusOK, rows)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := h.ch.Query(ctx, query, rows, map[string]string{"ip": device.IP, "mac": device.MAC}); err != nil {
		metrics.ClickHouseErrors.WithLabelValues("query", table).Inc()
		slog.Warn("clickhouse query failed", "table", table, "mac", mac, "error", err)
		writeError(w, http.StatusBadGateway, "clickhouse query failed")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
