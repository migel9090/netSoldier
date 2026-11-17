package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
)

type TopologyHandler struct {
	devices *store.Store
	ch      *ch.Client
}

func NewTopologyHandler(devices *store.Store, chClient *ch.Client) *TopologyHandler {
	return &TopologyHandler{devices: devices, ch: chClient}
}

type topoNode struct {
	ID              string `json:"id"`
	Label           string `json:"label"`
	MAC             string `json:"mac,omitempty"`
	IP              string `json:"ip"`
	DeviceType      string `json:"device_type,omitempty"`
	Vendor          string `json:"vendor,omitempty"`
	IsLocal         bool   `json:"is_local"`
	TotalBytes      uint64 `json:"total_bytes"`
	ConnectionCount int    `json:"connection_count"`
}

type topoEdge struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	TotalBytes   uint64 `json:"total_bytes"`
	TotalPackets uint64 `json:"total_packets"`
	FlowCount    uint64 `json:"flow_count"`
}

type topoResponse struct {
	Nodes []topoNode `json:"nodes"`
	Edges []topoEdge `json:"edges"`
}

// flowRow is one aggregate from ClickHouse. sum() and count() are UInt64,
// which the JSON output quotes; decoding them as plain uint64 used to fail and
// leave the topology without a single edge.
type flowRow struct {
	SrcIP        string    `json:"src_ip"`
	DstIP        string    `json:"dst_ip"`
	TotalBytes   ch.UInt64 `json:"total_bytes"`
	TotalPackets ch.UInt64 `json:"total_packets"`
	FlowCount    ch.UInt64 `json:"flow_count"`
}

func (h *TopologyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hours := 1
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}

	// Addresses are unique in the store, so each IP maps to its one holder.
	devices, err := h.devices.ListBound()
	if err != nil {
		slog.Error("topology: list devices failed", "error", err)
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}

	deviceByIP := make(map[string]*store.Device, len(devices))
	for i := range devices {
		if devices[i].IP != "" {
			deviceByIP[devices[i].IP] = &devices[i]
		}
	}

	edges := []topoEdge{}
	if h.ch != nil {
		var err error
		if edges, err = h.queryFlows(r.Context(), hours); err != nil {
			writeError(w, http.StatusBadGateway, "clickhouse query failed")
			return
		}
	}

	nodeMap := make(map[string]*topoNode)

	for _, d := range devices {
		if d.IP == "" {
			continue
		}
		nodeMap[d.IP] = &topoNode{
			ID:         d.IP,
			Label:      pickLabel(d.Hostname, d.IP),
			MAC:        d.MAC,
			IP:         d.IP,
			DeviceType: d.DeviceType,
			Vendor:     d.Vendor,
			IsLocal:    true,
		}
	}

	for i := range edges {
		e := &edges[i]
		ensureNode(nodeMap, e.Source, deviceByIP)
		ensureNode(nodeMap, e.Target, deviceByIP)
		if n := nodeMap[e.Source]; n != nil {
			n.TotalBytes += e.TotalBytes
			n.ConnectionCount++
		}
		if n := nodeMap[e.Target]; n != nil {
			n.TotalBytes += e.TotalBytes
			n.ConnectionCount++
		}
	}

	nodes := make([]topoNode, 0, len(nodeMap))
	for _, n := range nodeMap {
		nodes = append(nodes, *n)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topoResponse{Nodes: nodes, Edges: edges})
}

// queryFlows aggregates the flows of the last hours per address pair.
// network_flows is a view over Zeek's conn.log (migration 028): bytes and
// packets of both directions, src the side that opened the connection.
func (h *TopologyHandler) queryFlows(ctx context.Context, hours int) ([]topoEdge, error) {
	qctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	query := `SELECT
		src_ip,
		dst_ip,
		sum(bytes_in + bytes_out) AS total_bytes,
		sum(packets_in + packets_out) AS total_packets,
		count() AS flow_count
	FROM network_flows
	WHERE timestamp >= now() - INTERVAL {hours:UInt32} HOUR
	GROUP BY src_ip, dst_ip
	ORDER BY total_bytes DESC
	LIMIT 500`

	var rows []flowRow
	if err := h.ch.Query(qctx, query, &rows, map[string]string{"hours": strconv.Itoa(hours)}); err != nil {
		metrics.ClickHouseErrors.WithLabelValues("query", "network_flows").Inc()
		slog.Warn("topology: clickhouse query failed", "error", err)
		return nil, err
	}

	edges := make([]topoEdge, 0, len(rows))
	for _, r := range rows {
		if r.SrcIP == "" || r.DstIP == "" || r.SrcIP == r.DstIP {
			continue
		}
		edges = append(edges, topoEdge{
			Source:       r.SrcIP,
			Target:       r.DstIP,
			TotalBytes:   uint64(r.TotalBytes),
			TotalPackets: uint64(r.TotalPackets),
			FlowCount:    uint64(r.FlowCount),
		})
	}
	return edges, nil
}

func ensureNode(m map[string]*topoNode, ip string, devices map[string]*store.Device) {
	if _, ok := m[ip]; ok {
		return
	}
	n := &topoNode{
		ID:      ip,
		Label:   ip,
		IP:      ip,
		IsLocal: isPrivateIP(ip),
	}
	if d, ok := devices[ip]; ok {
		n.Label = pickLabel(d.Hostname, ip)
		n.MAC = d.MAC
		n.DeviceType = d.DeviceType
		n.Vendor = d.Vendor
		n.IsLocal = true
	}
	m[ip] = n
}

func pickLabel(hostname, ip string) string {
	if hostname != "" {
		return hostname
	}
	return ip
}

func isPrivateIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.SplitN(ip, ".", 3)
		if len(parts) >= 2 {
			if oct, err := strconv.Atoi(parts[1]); err == nil && oct >= 16 && oct <= 31 {
				return true
			}
		}
	}
	return false
}
