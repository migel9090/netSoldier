package isolate

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
	"github.com/migel9090/netSoldier/apps/netagent/internal/ratelimit"
	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

// Transmitter applies and lifts the Layer-2 redirection for one target;
// wire.Sender implements it. Apply steers the target's gateway traffic (and
// the gateway's traffic for the target) to this interface, where it is
// dropped because the guard has refused to run while the host forwards.
// Lift sends the corrective entries that hand the two stations each other's
// real address again.
type Transmitter interface {
	Apply(target, gateway wire.Host) error
	Lift(target, gateway wire.Host) error
}

// Timing of the enforcement frames. A neighbour cache accepts an update
// about once a second, so re-asserting every two seconds keeps the redirect
// in place; three corrections half a second apart survive one lost frame on
// lift.
var (
	refreshEvery = 2 * time.Second
	liftRounds   = 3
	liftGap      = 500 * time.Millisecond
)

// Engine holds the isolations in force. It is safe for concurrent use.
type Engine struct {
	guard     *Guard
	gateway   wire.Host // pinned from configuration, never changed
	tx        Transmitter
	maxActive int
	limit     *ratelimit.Bucket
	report    func(proto.Result)
	now       func() time.Time

	mu       sync.Mutex
	active   map[wire.MAC]*isolation
	lifting  map[wire.MAC]bool // targets whose corrective rounds are still in flight
	refused  map[string]uint64
	accepted uint64

	loopWG sync.WaitGroup
}

type isolation struct {
	id       string
	target   wire.Host
	expires  time.Time
	cancel   context.CancelFunc
	failures int
}

// NewEngine returns an engine whose gateway is the guard's pinned gateway.
// isolatesPerMinute rate-limits accepted arp_isolate commands.
func NewEngine(g *Guard, tx Transmitter, maxActive, isolatesPerMinute int, report func(proto.Result)) *Engine {
	return &Engine{
		guard:     g,
		gateway:   wire.Host{MAC: g.GatewayMAC, IP: g.GatewayIP},
		tx:        tx,
		maxActive: maxActive,
		limit:     ratelimit.New(isolatesPerMinute, time.Minute),
		report:    report,
		now:       time.Now,
		active:    make(map[wire.MAC]*isolation),
		lifting:   make(map[wire.MAC]bool),
		refused:   make(map[string]uint64),
	}
}

// Handle carries out one command from the killswitch and reports its
// outcome. Only arp_isolate and arp_release are accepted here.
func (e *Engine) Handle(ctx context.Context, c proto.Command) {
	switch c.Type {
	case proto.CmdARPIsolate:
		e.start(ctx, c)
	case proto.CmdARPRelease:
		e.stop(c)
	default:
		e.refuse(c, refuse("command", "command type is not accepted from the killswitch"))
	}
}

func (e *Engine) refuse(c proto.Command, err error) {
	var r *Refusal
	if !errors.As(err, &r) {
		r = &Refusal{Code: "error", Reason: err.Error()}
	}
	e.mu.Lock()
	e.refused[r.Code]++
	e.mu.Unlock()
	slog.Warn("isolation command refused", "id", c.ID, "type", proto.Clip(c.Type, 32), "code", r.Code,
		"reason", r.Reason, "mac", proto.Clip(c.MAC, 32), "ip", proto.Clip(c.IP, 48))
	e.report(proto.Result{ID: c.ID, Error: r.Error()})
}

// start validates a request through the guard, records it, applies the first
// pair synchronously (so a send failure is reported, never hidden), and
// leaves a loop to refresh it and to lift it when the TTL expires.
func (e *Engine) start(ctx context.Context, c proto.Command) {
	t, ttl, err := e.guard.Check(c.MAC, c.IP, c.TTLSeconds)
	if err != nil {
		e.refuse(c, err)
		return
	}

	e.mu.Lock()
	now := e.now()
	if cur, ok := e.active[t.MAC]; ok {
		// A repeat for the same pair just extends the deadline (idempotent
		// retries from the killswitch); a different IP for the same MAC is a
		// conflict we will not silently re-point.
		if cur.target.IP != t.IP {
			e.mu.Unlock()
			e.refuse(c, refuse("conflict", "target MAC is already isolated with another IP"))
			return
		}
		cur.expires, cur.id = now.Add(ttl), c.ID
		e.accepted++
		e.mu.Unlock()
		e.report(proto.Result{ID: c.ID, OK: true})
		return
	}
	for _, other := range e.active {
		if other.target.IP == t.IP {
			e.mu.Unlock()
			e.refuse(c, refuse("conflict", "target IP is already isolated with another MAC"))
			return
		}
	}
	if e.lifting[t.MAC] {
		e.mu.Unlock()
		e.refuse(c, refuse("conflict", "target is still being released"))
		return
	}
	if len(e.active) >= e.maxActive {
		e.mu.Unlock()
		e.refuse(c, refuse("capacity", "at the limit of concurrent isolations"))
		return
	}
	if !e.limit.Allow(now) {
		e.mu.Unlock()
		e.refuse(c, refuse("rate", "rate limited"))
		return
	}

	// Apply the first pair while holding nothing but the engine lock's
	// intent: do it before recording, so a failure records nothing.
	if err := e.tx.Apply(t, e.gateway); err != nil {
		e.mu.Unlock()
		e.refuse(c, refuse("send", "could not apply isolation: %v", err))
		return
	}
	loopCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	iso := &isolation{id: c.ID, target: t, expires: now.Add(ttl), cancel: cancel}
	e.active[t.MAC] = iso
	e.accepted++
	e.loopWG.Add(1)
	go e.run(loopCtx, iso)
	e.mu.Unlock()

	slog.Info("isolation applied", "id", c.ID, "mac", t.MAC, "ip", t.IP, "expires", iso.expires.UTC())
	e.report(proto.Result{ID: c.ID, OK: true})
}

// run refreshes one isolation until its TTL expires or it is released, then
// lifts it. The TTL is enforced here, so an isolation ends even if the
// killswitch never sends a release (it may have crashed).
func (e *Engine) run(ctx context.Context, iso *isolation) {
	defer e.loopWG.Done()
	ticker := time.NewTicker(refreshEvery)
	defer ticker.Stop()
	for {
		e.mu.Lock()
		expires := iso.expires
		e.mu.Unlock()
		select {
		case <-ctx.Done():
			// Released (stop cancelled us); stop handles the lift.
			return
		case now := <-ticker.C:
			if !now.Before(expires) {
				e.expire(iso)
				return
			}
			if err := e.tx.Apply(iso.target, e.gateway); err != nil {
				e.mu.Lock()
				iso.failures++
				n := iso.failures
				e.mu.Unlock()
				if n == 3 {
					slog.Error("isolation refresh is failing; the target may no longer be isolated",
						"mac", iso.target.MAC, "ip", iso.target.IP, "error", err)
				}
			}
		}
	}
}

// expire removes an isolation whose TTL has passed and restores the target.
func (e *Engine) expire(iso *isolation) {
	e.mu.Lock()
	if e.active[iso.target.MAC] != iso {
		e.mu.Unlock() // already released
		return
	}
	delete(e.active, iso.target.MAC)
	e.lifting[iso.target.MAC] = true
	e.mu.Unlock()
	slog.Info("isolation expired; restoring", "id", iso.id, "mac", iso.target.MAC, "ip", iso.target.IP)
	e.lift(iso.target)
}

// stop ends an isolation named by the killswitch and restores the target.
// Releasing something not in force is reported as success: the killswitch
// and the agent then agree it is not isolated, which is the point.
func (e *Engine) stop(c proto.Command) {
	m, err := wire.ParseMAC(c.MAC)
	if err != nil {
		e.refuse(c, refuse("malformed", "target MAC is malformed"))
		return
	}
	e.mu.Lock()
	iso, ok := e.active[m]
	if !ok {
		e.mu.Unlock()
		e.report(proto.Result{ID: c.ID, OK: true})
		return
	}
	delete(e.active, m)
	e.lifting[m] = true
	iso.cancel()
	target := iso.target
	e.mu.Unlock()

	slog.Info("isolation released; restoring", "id", c.ID, "mac", target.MAC, "ip", target.IP)
	e.lift(target)
	e.report(proto.Result{ID: c.ID, OK: true})
}

// lift sends the corrective entries and clears the lifting flag. It is safe
// to call once per isolation: the flag stops a new isolation of the same MAC
// from racing the corrections.
func (e *Engine) lift(target wire.Host) {
	defer func() {
		e.mu.Lock()
		delete(e.lifting, target.MAC)
		e.mu.Unlock()
	}()
	for i := 0; i < liftRounds; i++ {
		if err := e.tx.Lift(target, e.gateway); err != nil {
			slog.Warn("restore send failed; neighbour caches will time out on their own",
				"mac", target.MAC, "ip", target.IP, "error", err)
		}
		if i < liftRounds-1 {
			time.Sleep(liftGap)
		}
	}
}

// Active lists the isolations in force, for the killswitch to reconcile with.
func (e *Engine) Active() []proto.Active {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]proto.Active, 0, len(e.active))
	for _, iso := range e.active {
		out = append(out, proto.Active{MAC: iso.target.MAC.String(), IP: iso.target.IP.String(), Expires: iso.expires.UTC()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// Refusals returns a copy of the per-reason refusal counts.
func (e *Engine) Refusals() map[string]uint64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make(map[string]uint64, len(e.refused))
	for k, v := range e.refused {
		out[k] = v
	}
	return out
}

// Shutdown stops every isolation and restores every target, so a clean exit
// leaves the segment as it found it. It cancels the loops, then lifts each
// target.
func (e *Engine) Shutdown() {
	e.mu.Lock()
	targets := make([]wire.Host, 0, len(e.active))
	for mac, iso := range e.active {
		iso.cancel()
		delete(e.active, mac)
		e.lifting[mac] = true
		targets = append(targets, iso.target)
	}
	e.mu.Unlock()
	e.loopWG.Wait()
	for _, t := range targets {
		slog.Info("isolation lifted on shutdown", "mac", t.MAC, "ip", t.IP)
		e.lift(t)
	}
}
