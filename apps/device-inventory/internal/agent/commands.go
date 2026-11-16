package agent

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/device-inventory/internal/metrics"
)

// CommandQueue holds the arp_probe commands device-inventory wants the agent
// to run. arp_probe is the only command device-inventory may issue (contract
// 8.1); the agent reports each outcome in a later batch. The queue is bounded
// and coalesces: only the most recent probe for a given target is pending, so
// a slow or absent agent cannot make it grow.
type CommandQueue struct {
	mu      sync.Mutex
	pending map[string]command // keyed by target
	seq     int
}

// NewCommandQueue returns an empty queue.
func NewCommandQueue() *CommandQueue { return &CommandQueue{pending: map[string]command{}} }

// Probe queues (or refreshes) an arp_probe for target, an IPv4 CIDR.
func (q *CommandQueue) Probe(target string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.seq++
	q.pending[target] = command{ID: "p-" + strconv.Itoa(q.seq), Type: "arp_probe", Target: target}
}

// Take returns the pending commands and clears them. The agent reports
// outcomes separately, so a command handed out is not re-sent; if a sweep is
// still wanted, the scheduler queues it again.
func (q *CommandQueue) Take() []command {
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]command, 0, len(q.pending))
	for _, c := range q.pending {
		out = append(out, c)
	}
	q.pending = map[string]command{}
	return out
}

// RunProbeScheduler queues an arp_probe for subnet every interval until ctx
// is done. This is the ARP scanner's new shape: it no longer sends frames
// (netagent does), it asks the agent to. subnet must be a valid IPv4 CIDR of
// /16 or narrower; the function validates it and returns an error otherwise,
// so a misconfiguration fails at start.
func (q *CommandQueue) RunProbeScheduler(ctx context.Context, subnet string, interval time.Duration) error {
	if err := ValidateProbeSubnet(subnet); err != nil {
		return err
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		q.Probe(subnet)
		metrics.ProbesScheduled.Inc()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				q.Probe(subnet)
				metrics.ProbesScheduled.Inc()
			}
		}
	}()
	slog.Info("arp probe scheduler started", "subnet", subnet, "interval", interval)
	return nil
}

// maxScanHostBits bounds a probe subnet to a /16, matching netagent's own
// limit: a /16 is ~65k requests, and anything wider is a misconfiguration.
const maxScanHostBits = 16

// ValidateProbeSubnet reports whether subnet is a probeable IPv4 CIDR.
func ValidateProbeSubnet(subnet string) error {
	_, n, err := net.ParseCIDR(subnet)
	if err != nil {
		return err
	}
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return &net.ParseError{Type: "IPv4 CIDR", Text: subnet}
	}
	if bits-ones > maxScanHostBits {
		return &net.ParseError{Type: "subnet narrower than /" + strconv.Itoa(32-maxScanHostBits), Text: subnet}
	}
	return nil
}
