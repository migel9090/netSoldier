// Package metrics declares every Prometheus series device-inventory exports,
// so names and labels live in one place.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const ns = "device_inventory"

var (
	// Kept under their original names: alert rules and dashboards use them.
	DHCPPackets = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "dhcp_packets_total",
		Help: "DHCP client messages accepted by the listener.",
	})
	KnownDevices = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: ns, Name: "known_devices",
		Help: "Rows in the inventory.",
	})
	LastDeviceEvent = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: ns, Name: "last_device_event_timestamp_seconds",
		Help: "Unix time of the most recent sighting the inventory accepted.",
	})
	EventsDropped = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "events_dropped_total",
		Help: "ClickHouse rows dropped because the write queue was full.",
	})
	DevicesPruned = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "devices_pruned_total",
		Help: "Stale unlabelled devices removed by retention.",
	})

	// CaptureUp and LastHeartbeat are derived from netagent's heartbeat
	// (contract 8.1): device-inventory no longer runs listeners of its own.
	CaptureUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns, Name: "capture_up",
		Help: "1 while the agent reports this protocol's capture is running, else 0.",
	}, []string{"proto"})
	LastHeartbeat = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: ns, Name: "agent_last_heartbeat_timestamp_seconds",
		Help: "Unix time of the most recent batch the agent posted.",
	})
	AgentFramesDropped = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: ns, Name: "agent_frames_dropped",
		Help: "Frames the agent's bounded queue has dropped since it started (from the heartbeat).",
	})
	ProbesScheduled = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "arp_probes_scheduled_total",
		Help: "arp_probe commands device-inventory has queued for the agent.",
	})
	FramesReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "frames_received_total",
		Help: "Frames the ingestion endpoint accepted from the agent, before parsing, by protocol.",
	}, []string{"proto"})
	FramesRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "frames_rejected_total",
		Help: "Frames the parser refused, by protocol and reason (link_mismatch, malformed, ignored).",
	}, []string{"proto", "reason"})

	Sightings = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "sightings_total",
		Help: "Sightings handed to the store, by source and outcome.",
	}, []string{"source", "outcome"})
	Conflicts = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "conflicts_total",
		Help: "Claims refused because they contradicted a live binding or an established device, by kind.",
	}, []string{"kind"})
	Rebinds = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "rebinds_total",
		Help: "Addresses that moved between devices, or devices that moved address, after the old binding lapsed.",
	})
	DevicesEvicted = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "devices_evicted_total",
		Help: "Rows evicted to stay under DEVICE_MAX_ROWS.",
	})

	ClickHouseErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "clickhouse_errors_total",
		Help: "Failed ClickHouse calls, by operation and table.",
	}, []string{"op", "table"})
)
