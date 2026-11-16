// Package probe carries out device-inventory's arp_probe commands: a paced
// sweep of broadcast ARP requests over a subnet the agent's interface is on.
// The replies come back through the ARP capture like any other frame.
package probe

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
	"github.com/migel9090/netSoldier/apps/netagent/internal/ratelimit"
)

// MinPrefix bounds a sweep to a /16 (65,534 requests, about eleven minutes at
// the default pace). device-inventory's ARP_SCAN_SUBNET has the same bound.
const MinPrefix = 16

// Sender transmits one probe; wire.Sender implements it.
type Sender interface {
	Probe(sender, target netip.Addr) error
}

// Prober runs at most one sweep at a time.
type Prober struct {
	Enabled bool
	Tx      Sender
	Report  func(proto.Result)
	// Limit is the rate of accepted probe commands.
	Limit *ratelimit.Bucket
	// Pace is the gap between two requests of a sweep.
	Pace time.Duration
	// Local returns the interface's IPv4 prefixes, with the agent's own
	// address in each (read at command time: addresses can change).
	Local func() ([]netip.Prefix, error)

	ctx     context.Context
	running atomic.Bool
	now     func() time.Time
}

// Start binds the prober's sweeps to ctx.
func (p *Prober) Start(ctx context.Context) {
	p.ctx = ctx
	if p.now == nil {
		p.now = time.Now
	}
}

func (p *Prober) refuse(c proto.Command, reason string) {
	slog.Warn("arp probe refused", "id", c.ID, "target", proto.Clip(c.Target, 64), "reason", reason)
	p.Report(proto.Result{ID: c.ID, Error: "refused: " + reason})
}

// Handle validates c and starts its sweep, or reports why not.
func (p *Prober) Handle(c proto.Command) {
	if !p.Enabled {
		p.refuse(c, "arp probing is disabled on this agent")
		return
	}
	local, err := p.Local()
	if err != nil {
		p.refuse(c, "cannot read the interface addresses")
		return
	}
	target, src, err := Plan(c.Target, local)
	if err != nil {
		p.refuse(c, err.Error())
		return
	}
	if p.running.Load() {
		p.refuse(c, "a probe is already running")
		return
	}
	if !p.Limit.Allow(p.now()) {
		p.refuse(c, "rate limited")
		return
	}
	if !p.running.CompareAndSwap(false, true) {
		p.refuse(c, "a probe is already running")
		return
	}
	go func() {
		defer p.running.Store(false)
		p.Report(p.sweep(c.ID, target, src))
	}()
}

// Plan validates a probe target against the interface's prefixes and
// returns the subnet to sweep and the source address to sweep it from.
// target is an IPv4 CIDR or a single IPv4 address. It must lie inside one
// prefix of the interface: probing anything else is either pointless (ARP
// does not cross routers) or a flood aimed somewhere it should not be.
func Plan(target string, local []netip.Prefix) (netip.Prefix, netip.Addr, error) {
	var pfx netip.Prefix
	if a, err := netip.ParseAddr(target); err == nil {
		pfx = netip.PrefixFrom(a, a.BitLen())
	} else if pfx, err = netip.ParsePrefix(target); err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("target %q is not an IPv4 address or CIDR", proto.Clip(target, 64))
	}
	if !pfx.Addr().Is4() {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("target %s is not IPv4", pfx)
	}
	pfx = pfx.Masked()
	if pfx.Bits() < MinPrefix {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("target %s is wider than /%d", pfx, MinPrefix)
	}
	for _, l := range local {
		if l.Addr().Is4() && l.Bits() <= pfx.Bits() && l.Contains(pfx.Addr()) {
			return pfx, l.Addr(), nil
		}
	}
	return netip.Prefix{}, netip.Addr{}, fmt.Errorf("target %s is not on the interface's subnet", pfx)
}

// Hosts lists the addresses a sweep of pfx asks for: every address except,
// for prefixes up to /30, the network and broadcast addresses, and except
// the agent's own address src.
func Hosts(pfx netip.Prefix, src netip.Addr) []netip.Addr {
	var out []netip.Addr
	first, last := pfx.Addr(), lastAddr(pfx)
	if pfx.Bits() <= 30 {
		first, last = first.Next(), last.Prev()
	}
	for a := first; a.IsValid() && pfx.Contains(a); a = a.Next() {
		if a != src {
			out = append(out, a)
		}
		if a == last {
			break
		}
	}
	return out
}

func lastAddr(pfx netip.Prefix) netip.Addr {
	b := pfx.Addr().As4()
	host := uint32(1)<<(32-pfx.Bits()) - 1
	v := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (p *Prober) sweep(id string, pfx netip.Prefix, src netip.Addr) proto.Result {
	hosts := Hosts(pfx, src)
	slog.Info("arp probe started", "id", id, "target", pfx.String(), "requests", len(hosts))
	sent, failed := 0, 0
	var lastErr error
	tick := time.NewTicker(p.Pace)
	defer tick.Stop()
	for _, a := range hosts {
		select {
		case <-p.ctx.Done():
			return proto.Result{ID: id, Error: fmt.Sprintf("interrupted after %d of %d requests", sent, len(hosts))}
		case <-tick.C:
		}
		if err := p.Tx.Probe(src, a); err != nil {
			failed++
			lastErr = err
			continue
		}
		sent++
	}
	slog.Info("arp probe finished", "id", id, "target", pfx.String(), "sent", sent, "failed", failed)
	if failed > 0 {
		return proto.Result{ID: id, Error: fmt.Sprintf("sent %d of %d requests; last error: %v", sent, len(hosts), lastErr)}
	}
	return proto.Result{ID: id, OK: true}
}
