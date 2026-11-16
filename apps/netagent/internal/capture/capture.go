// Package capture reads frames off one interface, one AF_PACKET socket per
// protocol, and hands each whole Ethernet frame with its capture time to a
// sink. It checks lengths and nothing else: the frames are parsed by
// device-inventory, which runs without capabilities in a sandbox, so a parser
// bug there cannot reach the one process that holds raw network access.
package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

// Sink receives captured frames. It must not block (the forwarder's queue
// drops its oldest frame instead).
type Sink interface{ Push(proto.Frame) }

// Backoff for a capture that failed. One that stayed up for resetAfter is
// considered healthy again.
var (
	backoffInitial = time.Second
	backoffMax     = 30 * time.Second
	resetAfter     = time.Minute
	watchEvery     = 2 * time.Second
)

// Capture runs the configured protocols on one interface.
type Capture struct {
	ifi    *net.Interface
	protos []Protocol
	sink   Sink
	now    func() time.Time

	mu sync.Mutex
	up map[string]bool

	received  atomic.Uint64
	badLength atomic.Uint64
}

// New prepares captures of protos on ifi into sink.
func New(ifi *net.Interface, protos []Protocol, sink Sink) *Capture {
	up := make(map[string]bool, len(protos))
	for _, p := range protos {
		up[p.Name] = false
	}
	return &Capture{ifi: ifi, protos: protos, sink: sink, now: time.Now, up: up}
}

// Status reports, per configured protocol, whether its socket is open and
// being read. It is the heartbeat's capture map.
func (c *Capture) Status() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]bool, len(c.up))
	for k, v := range c.up {
		out[k] = v
	}
	return out
}

// Counts returns how many frames were forwarded to the sink and how many
// were dropped for their length.
func (c *Capture) Counts() (received, badLength uint64) {
	return c.received.Load(), c.badLength.Load()
}

func (c *Capture) set(name string, up bool) {
	c.mu.Lock()
	c.up[name] = up
	c.mu.Unlock()
}

// Run captures until ctx is done. A capture that fails (interface gone,
// socket error) is reopened after a backoff; its state is false meanwhile.
func (c *Capture) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range c.protos {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.supervise(ctx, p)
		}()
	}
	wg.Wait()
}

func (c *Capture) supervise(ctx context.Context, p Protocol) {
	backoff := backoffInitial
	for {
		started := c.now()
		err := c.runOnce(ctx, p)
		c.set(p.Name, false)
		if ctx.Err() != nil {
			return
		}
		if c.now().Sub(started) >= resetAfter {
			backoff = backoffInitial
		}
		slog.Warn("capture stopped; retrying", "proto", p.Name, "interface", c.ifi.Name, "error", err, "backoff", backoff.String())
		t := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		backoff = min(2*backoff, backoffMax)
	}
}

func (c *Capture) runOnce(ctx context.Context, p Protocol) error {
	if err := c.checkInterface(); err != nil {
		return err
	}
	s, err := open(c.ifi, p)
	if err != nil {
		return err
	}
	defer s.close()
	c.set(p.Name, true)
	slog.Info("capture up", "proto", p.Name, "interface", c.ifi.Name)

	buf := make([]byte, p.MaxLen+1)
	lastWatch := c.now()
	for ctx.Err() == nil {
		// A socket bound to a vanished or downed interface just stops
		// receiving; without this check the capture would stay "up".
		if now := c.now(); now.Sub(lastWatch) >= watchEvery {
			lastWatch = now
			if err := c.checkInterface(); err != nil {
				return err
			}
		}
		n, err := s.read(buf)
		if errors.Is(err, errTimeout) {
			continue
		}
		if err != nil {
			return err
		}
		if n < p.MinLen || n > p.MaxLen {
			c.badLength.Add(1)
			continue
		}
		c.received.Add(1)
		c.sink.Push(proto.Frame{T: c.now().UnixNano(), Proto: p.Name, Data: append([]byte(nil), buf[:n]...)})
	}
	return nil
}

func (c *Capture) checkInterface() error {
	cur, err := net.InterfaceByIndex(c.ifi.Index)
	if err != nil || cur.Name != c.ifi.Name {
		return fmt.Errorf("interface %s is gone", c.ifi.Name)
	}
	if cur.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface %s is down", c.ifi.Name)
	}
	return nil
}
