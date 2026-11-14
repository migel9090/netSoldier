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

	ListenerUp = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns, Name: "listener_up",
		Help: "1 while the listener has its socket open and is reading, else 0.",
	}, []string{"listener"})
	ListenerRestarts = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "listener_restarts_total",
		Help: "Times a listener stopped (error or panic) and was restarted.",
	}, []string{"listener"})
	FramesReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "frames_received_total",
		Help: "Frames or datagrams a listener read, before parsing.",
	}, []string{"listener"})
	FramesRejected = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "frames_rejected_total",
		Help: "Frames a listener refused, by reason (link_mismatch, malformed, ignored).",
	}, []string{"listener", "reason"})

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
