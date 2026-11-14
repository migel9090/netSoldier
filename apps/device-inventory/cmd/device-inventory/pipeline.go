package main

import (
	"context"
	"log/slog"
	"time"

	ch "github.com/migel9090/netSoldier/apps/device-inventory/internal/clickhouse"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/dhcpfp"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/discovery"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/oui"
	"github.com/migel9090/netSoldier/apps/device-inventory/internal/store"
)

// processSightings is the single consumer of every listener's output.
func processSightings(ctx context.Context, db *store.Store, w *chWriter, in <-chan discovery.Sighting) {
	for {
		select {
		case s := <-in:
			handleSighting(db, w, s)
		case <-ctx.Done():
			return
		}
	}
}

// handleSighting enriches a sighting with what is derived locally (OUI
// vendor, DHCP profile), hands it to the store, and turns the result into
// logs, metrics and ClickHouse rows. It touches no socket, so it does not
// care where the frame was captured.
func handleSighting(db *store.Store, w *chWriter, s discovery.Sighting) {
	if s.MAC != "" {
		s.Vendor = oui.Lookup(s.MAC)
	}
	if p := dhcpfp.Lookup(s.Fingerprint, s.VendorClass); p != nil {
		s.OS, s.DeviceType = p.OS, p.DeviceType
	}

	res, err := db.Observe(s)
	if err != nil {
		metrics.Sightings.WithLabelValues(string(s.Source), "error").Inc()
		slog.Error("sighting not recorded", "source", s.Source, "mac", s.MAC, "ip", s.IP, "error", err)
		return
	}
	metrics.Sightings.WithLabelValues(string(s.Source), string(res.Outcome)).Inc()
	if res.Outcome != store.Applied {
		if res.Outcome == store.Full {
			slog.Warn("inventory full of labelled devices; new device not recorded", "mac", s.MAC)
		}
		return
	}
	metrics.LastDeviceEvent.SetToCurrentTime()

	d := res.Device
	if res.Evicted != "" {
		metrics.DevicesEvicted.Inc()
		slog.Info("device evicted to stay under DEVICE_MAX_ROWS", "evicted", res.Evicted, "for", d.MAC)
	}
	if res.Created || res.Evicted != "" {
		metrics.KnownDevices.Set(float64(db.Count()))
	}

	event := "seen"
	if res.Created {
		event = "new"
		slog.Info("new device", "source", s.Source, "mac", d.MAC, "ip", d.IP, "hostname", d.Hostname)
	}
	if res.Linked != "" {
		slog.Info("device looks like a MAC rotation of an earlier row (linked, labels not moved)",
			"mac", d.MAC, "rotation_of", res.Linked)
	}
	if rb := res.Rebind; rb != nil {
		event = "rebind"
		metrics.Rebinds.Inc()
		level := slog.LevelInfo
		if rb.FromEstablished {
			level = slog.LevelWarn
		}
		slog.Log(context.Background(), level, "binding changed after the previous one lapsed",
			"ip", rb.IP, "to_mac", rb.ToMAC, "from_mac", rb.FromMAC, "previous_ip", rb.PreviousIP, "source", s.Source)
	}
	for _, c := range res.Conflicts {
		metrics.Conflicts.WithLabelValues(c.Kind).Inc()
		attrs := []any{"kind", c.Kind, "mac", c.MAC, "claimant", c.Claimant, "ip", c.IP, "value", c.Value,
			"source", c.Source, "count", c.Count}
		if c.New {
			slog.Warn("claim contradicts the inventory; recorded as a conflict, not applied", attrs...)
		} else {
			slog.Debug("conflict repeated", attrs...)
		}
		w.event(c.MAC, c.IP, "", "", c.Source, "conflict")
	}
	slog.Debug("sighting applied", "source", s.Source, "mac", d.MAC, "ip", d.IP, "event", event)

	w.event(d.MAC, d.IP, d.Hostname, d.Vendor, string(s.Source), event)
	if res.Changed {
		w.device(d)
	}
	if res.Released != nil {
		w.device(res.Released)
	}
}

// chWriter batches rows for ClickHouse through a bounded queue.
//
// Discovery is driven by unauthenticated LAN protocols, so a flood must cost
// dropped rows (counted in events_dropped_total), never unbounded goroutines
// or memory. Failed batches are logged at Warn, counted in
// clickhouse_errors_total and dropped; there is no retry buffer.
type chWriter struct {
	client *ch.Client
	queue  chan chRow
	now    func() time.Time
}

type chRow struct {
	table string
	row   any
}

func newCHWriter(client *ch.Client, depth int) *chWriter {
	return &chWriter{client: client, queue: make(chan chRow, depth), now: time.Now}
}

func (w *chWriter) enqueue(table string, row any) {
	if w == nil || w.client == nil {
		return
	}
	select {
	case w.queue <- chRow{table: table, row: row}:
	default:
		metrics.EventsDropped.Inc()
	}
}

// event queues a device_events row. Timestamps carry milliseconds: the
// column is DateTime64(3) from migration 023 on.
func (w *chWriter) event(mac, ip, hostname, vendor, protocol, eventType string) {
	if w == nil || w.client == nil {
		return
	}
	w.enqueue("device_events", ch.DeviceEvent{
		Timestamp: w.now().UTC().Format(ch.MillisLayout),
		MAC:       mac,
		IP:        ip,
		Hostname:  hostname,
		Vendor:    vendor,
		Protocol:  protocol,
		EventType: eventType,
	})
}

// device queues a snapshot of d for the devices table, a ReplacingMergeTree
// on updated_at: the newest snapshot per MAC wins. Snapshots are written when
// identity fields change, not on every sighting, so last_seen there lags.
func (w *chWriter) device(d *store.Device) {
	if w == nil || w.client == nil || d == nil {
		return
	}
	labels := d.Labels
	if labels == nil {
		labels = []string{}
	}
	w.enqueue("devices", ch.DeviceRecord{
		MAC:         d.MAC,
		IP:          d.IP,
		Hostname:    d.Hostname,
		Fingerprint: d.Fingerprint,
		VendorClass: d.VendorClass,
		Vendor:      d.Vendor,
		OS:          d.OS,
		DeviceType:  d.DeviceType,
		Labels:      labels,
		FirstSeen:   d.FirstSeen.UTC().Format(ch.SecondsLayout),
		LastSeen:    d.LastSeen.UTC().Format(ch.SecondsLayout),
		UpdatedAt:   w.now().UTC().Format(ch.SecondsLayout),
	})
}

// Run drains the queue, flushing per table on a full batch or a timer.
func (w *chWriter) Run(ctx context.Context) {
	const batchSize = 100
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	batches := map[string][]any{}
	flush := func(table string) {
		batch := batches[table]
		if len(batch) == 0 {
			return
		}
		writeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := w.client.Insert(writeCtx, table, batch...); err != nil {
			metrics.ClickHouseErrors.WithLabelValues("insert", table).Inc()
			slog.Warn("clickhouse batch write failed; rows dropped", "table", table, "rows", len(batch), "error", err)
		}
		cancel()
		batches[table] = batch[:0]
	}
	flushAll := func() {
		for table := range batches {
			flush(table)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Drain what is already queued so a shutdown loses nothing
			// that was accepted.
			for {
				select {
				case r := <-w.queue:
					batches[r.table] = append(batches[r.table], r.row)
					continue
				default:
				}
				break
			}
			flushAll()
			return
		case r := <-w.queue:
			batches[r.table] = append(batches[r.table], r.row)
			if len(batches[r.table]) >= batchSize {
				flush(r.table)
			}
		case <-ticker.C:
			flushAll()
		}
	}
}
