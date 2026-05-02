package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"time"
)

var macRe = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)

type connectionRow struct {
	Timestamp string `json:"timestamp"`
	DstIP     string `json:"dst_ip"`
	DstDomain string `json:"dst_domain"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  uint8  `json:"protocol"`
	BytesIn   uint64 `json:"bytes_in"`
	BytesOut  uint64 `json:"bytes_out"`
	Duration  uint32 `json:"duration_ms"`
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

func (h *Handler) DeviceConnections(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	if !macRe.MatchString(mac) {
		http.Error(w, `{"error":"invalid mac"}`, http.StatusBadRequest)
		return
	}

	device, err := h.store.GetDevice(mac)
	if err != nil {
		slog.Error("get device failed", "mac", mac, "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if device == nil || device.IP == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	if net.ParseIP(device.IP) == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	if h.ch == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	query := fmt.Sprintf(`SELECT
		timestamp, dst_ip, dst_domain, dst_port, protocol,
		bytes_in, bytes_out, duration_ms
	FROM connections
	WHERE src_ip = '%s'
	ORDER BY timestamp DESC
	LIMIT 100`, escapeCH(device.IP))

	var rows []connectionRow
	if err := h.ch.Query(ctx, query, &rows); err != nil {
		slog.Debug("device connections query failed", "mac", mac, "error", err)
		rows = []connectionRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

func (h *Handler) DeviceDNS(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	if !macRe.MatchString(mac) {
		http.Error(w, `{"error":"invalid mac"}`, http.StatusBadRequest)
		return
	}

	device, err := h.store.GetDevice(mac)
	if err != nil {
		slog.Error("get device failed", "mac", mac, "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if device == nil || device.IP == "" || net.ParseIP(device.IP) == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	if h.ch == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	query := fmt.Sprintf(`SELECT
		timestamp, domain, query_type, answer, status, response_ms, blocked
	FROM dns_queries
	WHERE client_ip = '%s'
	ORDER BY timestamp DESC
	LIMIT 100`, escapeCH(device.IP))

	var rows []dnsRow
	if err := h.ch.Query(ctx, query, &rows); err != nil {
		slog.Debug("device dns query failed", "mac", mac, "error", err)
		rows = []dnsRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

func (h *Handler) DeviceAlerts(w http.ResponseWriter, r *http.Request) {
	mac := r.PathValue("mac")
	if !macRe.MatchString(mac) {
		http.Error(w, `{"error":"invalid mac"}`, http.StatusBadRequest)
		return
	}

	device, err := h.store.GetDevice(mac)
	if err != nil {
		slog.Error("get device failed", "mac", mac, "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	if device == nil || device.IP == "" || net.ParseIP(device.IP) == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	if h.ch == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	query := fmt.Sprintf(`SELECT
		timestamp, id, domain, query_type, matched_ioc, severity, source
	FROM alerts
	WHERE client_ip = '%s'
	ORDER BY timestamp DESC
	LIMIT 50`, escapeCH(device.IP))

	var rows []alertRow
	if err := h.ch.Query(ctx, query, &rows); err != nil {
		slog.Debug("device alerts query failed", "mac", mac, "error", err)
		rows = []alertRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows)
}

func escapeCH(s string) string {
	var out []byte
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'':
			out = append(out, '\\', '\'')
		case '\\':
			out = append(out, '\\', '\\')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
