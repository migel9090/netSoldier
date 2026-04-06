package capture

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var flowsExported = prometheus.NewCounter(prometheus.CounterOpts{
	Namespace: "detection_engine",
	Subsystem: "capture",
	Name:      "flows_exported_total",
	Help:      "Total network flows exported after idle timeout.",
})

func init() {
	prometheus.MustRegister(flowsExported)
}

type flowEntry struct {
	srcIP, dstIP     net.IP
	srcPort, dstPort uint16
	protocol         uint8
	bytesOut         uint64
	bytesIn          uint64
	packetsOut       uint32
	packetsIn        uint32
	tcpFlags         uint8
	vlanID           uint16
	startTime        time.Time
	lastSeen         time.Time
}

type flowTracker struct {
	mu    sync.Mutex
	flows map[string]*flowEntry
	ch    chan<- FlowRecord
}

func newTracker(ch chan<- FlowRecord) *flowTracker {
	return &flowTracker{
		flows: make(map[string]*flowEntry),
		ch:    ch,
	}
}

func (t *flowTracker) update(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8, size uint64, tcpFlags uint8, vlanID uint16) {
	key, reversed := normalizeKey(srcIP, dstIP, srcPort, dstPort, protocol)
	now := time.Now()

	t.mu.Lock()
	defer t.mu.Unlock()

	f, ok := t.flows[key]
	if !ok {
		f = &flowEntry{
			srcIP:     copyIP(srcIP),
			dstIP:     copyIP(dstIP),
			srcPort:   srcPort,
			dstPort:   dstPort,
			protocol:  protocol,
			vlanID:    vlanID,
			startTime: now,
		}
		if reversed {
			f.srcIP, f.dstIP = f.dstIP, f.srcIP
			f.srcPort, f.dstPort = f.dstPort, f.srcPort
		}
		t.flows[key] = f
	}

	f.lastSeen = now
	f.tcpFlags |= tcpFlags
	if !reversed {
		f.bytesOut += size
		f.packetsOut++
	} else {
		f.bytesIn += size
		f.packetsIn++
	}
}

func (t *flowTracker) sweeper(ctx context.Context, idleTimeout time.Duration) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.expire(idleTimeout)
		}
	}
}

func (t *flowTracker) expire(idleTimeout time.Duration) {
	cutoff := time.Now().Add(-idleTimeout)
	t.mu.Lock()
	defer t.mu.Unlock()

	for key, f := range t.flows {
		if f.lastSeen.Before(cutoff) {
			t.export(f)
			delete(t.flows, key)
		}
	}
}

func (t *flowTracker) flushAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, f := range t.flows {
		t.export(f)
		delete(t.flows, key)
	}
}

func (t *flowTracker) export(f *flowEntry) {
	rec := FlowRecord{
		Timestamp:  f.startTime,
		SrcIP:      f.srcIP.String(),
		SrcPort:    f.srcPort,
		DstIP:      f.dstIP.String(),
		DstPort:    f.dstPort,
		Protocol:   f.protocol,
		BytesIn:    f.bytesIn,
		BytesOut:   f.bytesOut,
		PacketsIn:  f.packetsIn,
		PacketsOut: f.packetsOut,
		DurationMs: uint32(f.lastSeen.Sub(f.startTime).Milliseconds()),
		TCPFlags:   f.tcpFlags,
		VlanID:     f.vlanID,
	}
	select {
	case t.ch <- rec:
		flowsExported.Inc()
	default:
	}
}

func normalizeKey(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol uint8) (string, bool) {
	src := fmt.Sprintf("%s:%d", srcIP, srcPort)
	dst := fmt.Sprintf("%s:%d", dstIP, dstPort)
	if src > dst {
		return fmt.Sprintf("%d|%s|%s", protocol, dst, src), true
	}
	return fmt.Sprintf("%d|%s|%s", protocol, src, dst), false
}

func copyIP(ip net.IP) net.IP {
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
