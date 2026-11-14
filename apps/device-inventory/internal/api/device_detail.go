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
	Duration  uint32    `json:"duration_ms"`
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
	Domain     string `json:"domain"`
	QueryType  string `json:"query_type"`
	MatchedIoC string `json:"matched_ioc"`
	Severity   string `json:"severity"`
	Source     string `json:"source"`
}

const (
	connectionsQuery = `SELECT
		timestamp, dst_ip, dst_domain, dst_port, protocol,
		bytes_in, bytes_out, duration_ms
	FROM connections
	WHERE src_ip = {ip:String}
	ORDER BY timestamp DESC
	LIMIT 100`

	dnsQuery = `SELECT
		timestamp, domain, query_type, answer, status, response_ms, blocked
	FROM dns_queries
	WHERE client_ip = {ip:String}
	ORDER BY timestamp DESC
	LIMIT 100`

	alertsQuery = `SELECT
		timestamp, id, domain, query_type, matched_ioc, severity, source
	FROM alerts
	WHERE client_ip = {ip:String}
	ORDER BY timestamp DESC
	LIMIT 50`
)

func (h *Handler) DeviceConnections(w http.ResponseWriter, r *http.Request) {
	rows := []connectionRow{}
	h.deviceHistory(w, r, "connections", connectionsQuery, &rows)
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
	if err := h.ch.Query(ctx, query, rows, map[string]string{"ip": device.IP}); err != nil {
		metrics.ClickHouseErrors.WithLabelValues("query", table).Inc()
		slog.Warn("clickhouse query failed", "table", table, "mac", mac, "error", err)
		writeError(w, http.StatusBadGateway, "clickhouse query failed")
		return
	}
	writeJSON(w, http.StatusOK, rows)
}
