package drivers

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
	"github.com/prometheus/client_golang/prometheus"
)

// ARPIsolateDriver isolates a device at layer 2 through the netagent
// (contract §8.2, ADR-0004). This process opens no socket and holds no
// capability: it queues arp_isolate / arp_release commands, the agent
// fetches them on its poll and reports each outcome in a later poll. Apply
// and Revert therefore answer ErrDeferred, and the controller moves the
// action when the result arrives (or the deadline passes).
//
// The agent is authoritative: it is the only component that can send the
// frames, so its own guard (pinned gateway, protected devices, subnet,
// ip_forward, rate limits) is what really protects the network. The checks
// here are a first filter that keeps an obviously wrong target from ever
// being asked for — and they cannot be relied on, because a compromised
// controller would skip them.
type ARPIsolateDriver struct {
	commands CommandStore
	guard    *TargetGuard
	// notOffered, when set, is why isolations are refused here (the
	// gateway is not pinned, the protected set is incomplete). Releases are
	// always accepted: they only give a device its access back.
	notOffered error
	// staleAfter is how long after its last poll the agent still counts as
	// connected.
	staleAfter time.Duration
	now        func() time.Time

	mu       sync.Mutex
	lastPoll time.Time
	agent    string
}

var agentLastPoll = prometheus.NewGauge(prometheus.GaugeOpts{
	Namespace: "killswitch",
	Name:      "agent_last_poll_timestamp_seconds",
	Help:      "Unix time of the netagent's last poll (0: never since start-up).",
})

func init() {
	prometheus.MustRegister(agentLastPoll)
}

// NewARPIsolateDriver returns the agent-backed driver. notOffered, when not
// nil, refuses every isolation with that reason.
func NewARPIsolateDriver(commands CommandStore, guard *TargetGuard, notOffered error) *ARPIsolateDriver {
	return &ARPIsolateDriver{
		commands:   commands,
		guard:      guard,
		notOffered: notOffered,
		staleAfter: 15 * time.Second,
		now:        time.Now,
	}
}

func (d *ARPIsolateDriver) Name() string { return events.ActionARPIsolate }

// Deferred implements Deferring.
func (d *ARPIsolateDriver) Deferred() bool { return true }

// Seen records a poll from the named agent.
func (d *ARPIsolateDriver) Seen(agent string) {
	now := d.now()
	d.mu.Lock()
	d.lastPoll, d.agent = now, agent
	d.mu.Unlock()
	agentLastPoll.Set(float64(now.Unix()))
}

// Available reports whether an isolation could be carried out now: it is
// offered, and an agent has polled recently. Approving one while nobody
// would fetch the command only produces an apply_failed later.
func (d *ARPIsolateDriver) Available() error {
	if d.notOffered != nil {
		return d.notOffered
	}
	d.mu.Lock()
	last := d.lastPoll
	d.mu.Unlock()
	if last.IsZero() {
		return errors.New("no netagent has polled since start-up")
	}
	if age := d.now().Sub(last); age > d.staleAfter {
		return fmt.Errorf("the netagent last polled %s ago", age.Round(time.Second))
	}
	return nil
}

// VetIsolationTarget is the controller-side check of an isolation target:
// the guard (both identifiers, one unicast device, not protected) and an
// IPv4 address, since ARP has no IPv6.
func VetIsolationTarget(g *TargetGuard, mac, ip string) (Device, error) {
	dev, err := g.Vet(mac, ip)
	if err != nil {
		return dev, err
	}
	if addr, _ := netip.ParseAddr(dev.IP); !addr.Is4() {
		return Device{}, fmt.Errorf("refusing ARP isolation of %s: ARP isolation is IPv4-only", dev.IP)
	}
	return dev, nil
}

// Apply queues an arp_isolate command.
func (d *ARPIsolateDriver) Apply(_ context.Context, action *events.EnforcementAction) error {
	if err := d.Available(); err != nil {
		return NotApplied(fmt.Errorf("arp isolation unavailable: %w", err))
	}
	dev, err := VetIsolationTarget(d.guard, action.TargetMAC, action.TargetIP)
	if err != nil {
		return NotApplied(err)
	}
	if action.TTLSeconds <= 0 {
		// The agent ends every isolation on its own clock so that a lost
		// controller cannot leave a device cut off; that needs a TTL.
		return NotApplied(errors.New("arp isolation needs a TTL"))
	}
	if _, err := d.commands.EnqueueCommand(AgentCommand{Type: CommandIsolate, ActionID: action.ID,
		MAC: dev.MAC, IP: dev.IP, TTLSeconds: action.TTLSeconds}); err != nil {
		return NotApplied(fmt.Errorf("queue arp_isolate: %w", err))
	}
	return ErrDeferred
}

// Revert queues an arp_release command. A target that does not parse was
// never isolated (Apply refuses it), so there is nothing to release.
func (d *ARPIsolateDriver) Revert(_ context.Context, action *events.EnforcementAction) error {
	mac, ip, ok := canonicalTarget(action.TargetMAC, action.TargetIP)
	if !ok {
		return nil
	}
	if _, err := d.commands.EnqueueCommand(AgentCommand{Type: CommandRelease, ActionID: action.ID,
		MAC: mac, IP: ip}); err != nil {
		return fmt.Errorf("queue arp_release: %w", err)
	}
	return ErrDeferred
}

// Reissue queues the isolation of an action that is still wanted but that
// the agent no longer has in force (it restarted, or lifted it on its own
// clock), for the rest of its TTL. The agent treats a repeat for the same
// MAC and IP as an extension, never as a second isolation.
func (d *ARPIsolateDriver) Reissue(action *events.EnforcementAction, ttlSeconds int) error {
	if err := d.Available(); err != nil {
		return NotApplied(fmt.Errorf("arp isolation unavailable: %w", err))
	}
	dev, err := VetIsolationTarget(d.guard, action.TargetMAC, action.TargetIP)
	if err != nil {
		return NotApplied(err)
	}
	_, err = d.commands.EnqueueCommand(AgentCommand{Type: CommandIsolate, ActionID: action.ID,
		MAC: dev.MAC, IP: dev.IP, TTLSeconds: max(ttlSeconds, 1)})
	return err
}

// Release queues an arp_release that belongs to no action: an isolation
// the agent reports that nothing here owns.
func (d *ARPIsolateDriver) Release(mac, ip string) error {
	mac, ip, ok := canonicalTarget(mac, ip)
	if !ok {
		return fmt.Errorf("cannot release %q / %q: not a MAC and an IP", mac, ip)
	}
	_, err := d.commands.EnqueueCommand(AgentCommand{Type: CommandRelease, MAC: mac, IP: ip})
	return err
}

// CanonicalMAC returns the lower-case colon form of mac, or "".
func CanonicalMAC(mac string) string {
	if key := normalizeMACKey(mac); key != "" {
		return formatMACKey(key)
	}
	return ""
}

func canonicalTarget(mac, ip string) (string, string, bool) {
	m := CanonicalMAC(mac)
	addr, err := parseDeviceIP(ip)
	if m == "" || err != nil {
		return "", "", false
	}
	return m, addr.String(), true
}

// Limits on one poll body; the body itself is capped at 1 MiB.
const (
	maxPollResults = 1000
	maxPollActive  = 4096
	maxCommandID   = 128
	maxAgentName   = 64
)

// PollRequest is the agent's poll (contract §8.2).
type PollRequest struct {
	Agent   string           `json:"agent"`
	Results []AgentResult    `json:"results"`
	Active  []AgentIsolation `json:"active"`
}

// AgentResult is the outcome of one command.
type AgentResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// AgentIsolation is one isolation the agent has in force.
type AgentIsolation struct {
	MAC     string `json:"mac"`
	IP      string `json:"ip"`
	Expires string `json:"expires"`
}

// PollResponse carries the commands for the agent.
type PollResponse struct {
	Commands []AgentCommand `json:"commands"`
}

// Sanitize canonicalises the request in place and drops what cannot be
// used, returning how many entries were dropped. One malformed entry must
// not make the controller ignore the rest of the agent's report.
func (r *PollRequest) Sanitize() int {
	dropped := 0
	r.Agent = sanitizeText(r.Agent, maxAgentName)
	if len(r.Results) > maxPollResults {
		dropped += len(r.Results) - maxPollResults
		r.Results = r.Results[:maxPollResults]
	}
	results := r.Results[:0]
	for _, res := range r.Results {
		if res.ID == "" || len(res.ID) > maxCommandID {
			dropped++
			continue
		}
		res.Error = sanitizeText(res.Error, 512)
		results = append(results, res)
	}
	r.Results = results
	if len(r.Active) > maxPollActive {
		dropped += len(r.Active) - maxPollActive
		r.Active = r.Active[:maxPollActive]
	}
	active := r.Active[:0]
	for _, a := range r.Active {
		mac, ip, ok := canonicalTarget(a.MAC, a.IP)
		if !ok {
			dropped++
			continue
		}
		a.MAC, a.IP = mac, ip
		active = append(active, a)
	}
	r.Active = active
	return dropped
}

// sanitizeText keeps printable ASCII so an agent-supplied string cannot
// forge log lines or audit text.
func sanitizeText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return b.String()
}
