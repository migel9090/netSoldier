package correlator

import (
	"context"
	"log/slog"
	"time"

	"github.com/migel9090/netSoldier/apps/detection-engine/internal/capture"
	"github.com/prometheus/client_golang/prometheus"
)

var connectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Subsystem: "correlator",
	Name:      "connections_total",
	Help:      "Total enriched connection records produced.",
})

func init() {
	prometheus.MustRegister(connectionsTotal)
}

// Correlator enriches flow records with DNS and device inventory data,
// producing "who → where → what" connection records.
type Correlator struct {
	dns    *DNSCache
	dev    *DeviceCache
	writer *CHWriter
	flowCh <-chan capture.FlowRecord
}

// New creates a correlator. If writer is nil, records are logged only.
func New(dns *DNSCache, dev *DeviceCache, writer *CHWriter, flowCh <-chan capture.FlowRecord) *Correlator {
	return &Correlator{
		dns:    dns,
		dev:    dev,
		writer: writer,
		flowCh: flowCh,
	}
}

// Run consumes flow records and produces enriched connection records.
func (c *Correlator) Run(ctx context.Context) {
	slog.Info("correlator started")
	for {
		select {
		case flow, ok := <-c.flowCh:
			if !ok {
				return
			}
			c.handle(ctx, flow)
		case <-ctx.Done():
			return
		}
	}
}

func (c *Correlator) handle(ctx context.Context, flow capture.FlowRecord) {
	dev := c.dev.Lookup(flow.SrcIP)
	domain := c.dns.Get(flow.DstIP)

	rec := ConnectionRecord{
		Timestamp:     flow.Timestamp.UTC().Format("2006-01-02 15:04:05"),
		SrcMAC:        dev.MAC,
		SrcHostname:   dev.Hostname,
		SrcVendor:     dev.Vendor,
		SrcOS:         dev.OS,
		SrcDeviceType: dev.DeviceType,
		SrcIP:         flow.SrcIP,
		SrcPort:       flow.SrcPort,
		DstIP:         flow.DstIP,
		DstDomain:     domain,
		DstPort:       flow.DstPort,
		Protocol:      flow.Protocol,
		BytesIn:       flow.BytesIn,
		BytesOut:      flow.BytesOut,
		PacketsIn:     flow.PacketsIn,
		PacketsOut:    flow.PacketsOut,
		DurationMs:    flow.DurationMs,
		TCPFlags:      flow.TCPFlags,
		VlanID:        flow.VlanID,
	}

	connectionsTotal.Inc()

	if c.writer != nil {
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := c.writer.Insert(writeCtx, "connections", rec); err != nil {
			slog.Debug("connection write failed", "error", err)
		}
	} else {
		slog.Debug("connection",
			"src", flow.SrcIP, "dst_ip", flow.DstIP,
			"dst_domain", domain, "device", dev.Hostname,
			"bytes", flow.BytesIn+flow.BytesOut,
		)
	}
}
