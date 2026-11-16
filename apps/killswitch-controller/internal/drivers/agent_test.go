package drivers

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/libs/events"
)

// memCommands is an in-memory CommandStore.
type memCommands struct {
	mu   sync.Mutex
	cmds []AgentCommand
}

func (m *memCommands) EnqueueCommand(c AgentCommand) (AgentCommand, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.ID, c.State = fmt.Sprintf("i-%d", len(m.cmds)+1), CommandQueued
	m.cmds = append(m.cmds, c)
	return c, nil
}

func (m *memCommands) TakeCommands(limit int) ([]AgentCommand, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []AgentCommand
	for i := range m.cmds {
		if m.cmds[i].State == CommandQueued && len(out) < limit {
			m.cmds[i].State = CommandSent
			out = append(out, m.cmds[i])
		}
	}
	return out, nil
}

func (m *memCommands) CompleteCommand(id string, ok bool, errText string) (AgentCommand, bool, error) {
	return AgentCommand{}, false, nil
}

func (m *memCommands) CancelCommand(id string) (bool, error) { return false, nil }

func (m *memCommands) OpenCommands() ([]AgentCommand, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]AgentCommand(nil), m.cmds...), nil
}

func newAgentDriver(t *testing.T, notOffered error) (*ARPIsolateDriver, *memCommands, *time.Time) {
	t.Helper()
	var g TargetGuard
	mustProtect(t, &g, []string{"192.168.1.1"}, []string{"aa:00:00:00:00:01"})
	cmds := &memCommands{}
	d := NewARPIsolateDriver(cmds, &g, notOffered)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return now }
	return d, cmds, &now
}

func isolation(mac, ip string) *events.EnforcementAction {
	return &events.EnforcementAction{ID: "ACT-1", ActionType: events.ActionARPIsolate,
		TargetMAC: mac, TargetIP: ip, TTLSeconds: 600}
}

func TestARPIsolationNeedsAPollingAgent(t *testing.T) {
	d, cmds, now := newAgentDriver(t, nil)
	if err := d.Available(); err == nil {
		t.Fatal("no agent has polled: isolation is not available")
	}
	if err := d.Apply(context.Background(), isolation("02:00:00:00:00:09", "192.168.1.50")); !errors.Is(err, ErrNotApplied) {
		t.Fatalf("apply without an agent: %v", err)
	}
	d.Seen("soc-node-1")
	if err := d.Available(); err != nil {
		t.Fatalf("after a poll: %v", err)
	}
	*now = now.Add(time.Minute)
	if err := d.Available(); err == nil || !strings.Contains(err.Error(), "last polled") {
		t.Fatalf("a silent agent is not available: %v", err)
	}
	if len(cmds.cmds) != 0 {
		t.Fatal("nothing may be queued while unavailable")
	}
	off, _, _ := newAgentDriver(t, errors.New("GATEWAY_MAC not pinned"))
	off.Seen("x")
	if err := off.Available(); err == nil || !strings.Contains(err.Error(), "GATEWAY_MAC") {
		t.Fatalf("not offered: %v", err)
	}
}

// TestARPIsolateQueuesACommand: the driver speaks contract §8.2 and opens
// no socket; the outcome comes from the agent.
func TestARPIsolateQueuesACommand(t *testing.T) {
	d, cmds, _ := newAgentDriver(t, nil)
	d.Seen("soc-node-1")
	if err := d.Apply(context.Background(), isolation("02-AA-BB-CC-DD-EE", "::ffff:192.168.1.50")); !errors.Is(err, ErrDeferred) {
		t.Fatalf("apply: %v, want ErrDeferred", err)
	}
	if err := d.Revert(context.Background(), isolation("02:aa:bb:cc:dd:ee", "192.168.1.50")); !errors.Is(err, ErrDeferred) {
		t.Fatalf("revert: %v", err)
	}
	taken, _ := cmds.TakeCommands(10)
	if len(taken) != 2 {
		t.Fatalf("queued %+v", taken)
	}
	iso, rel := taken[0], taken[1]
	if iso.Type != CommandIsolate || iso.MAC != "02:aa:bb:cc:dd:ee" || iso.IP != "192.168.1.50" ||
		iso.TTLSeconds != 600 || iso.ActionID != "ACT-1" {
		t.Errorf("isolate command: %+v", iso)
	}
	if rel.Type != CommandRelease || rel.MAC != "02:aa:bb:cc:dd:ee" || rel.TTLSeconds != 0 {
		t.Errorf("release command: %+v", rel)
	}
	if !IsDeferring(d) || IsDeferring(NewSinkholeDriver("http://x", "", "", nil)) {
		t.Error("IsDeferring")
	}
	if err := d.Revert(context.Background(), isolation("not-a-mac", "192.168.1.50")); err != nil {
		t.Errorf("a target that never parsed was never isolated: %v", err)
	}
	if err := d.Release("02:aa:bb:cc:dd:ef", "192.168.1.51"); err != nil {
		t.Fatal(err)
	}
	if err := d.Release("x", "y"); err == nil {
		t.Error("an unparseable release must be refused")
	}
}

// TestARPIsolateRefusesWhatIsNotOneDevice: the first check, before the
// agent's own guard.
func TestARPIsolateRefusesWhatIsNotOneDevice(t *testing.T) {
	d, cmds, _ := newAgentDriver(t, nil)
	d.Seen("soc-node-1")
	for _, a := range []*events.EnforcementAction{
		isolation("ff:ff:ff:ff:ff:ff", "192.168.1.50"),
		isolation("01:00:5e:00:00:01", "192.168.1.50"),
		isolation("11:22:33:44:55:66", "192.168.1.50"),
		isolation("00:00:00:00:00:00", "192.168.1.50"),
		isolation("02:00:00:00:00:09", "255.255.255.255"),
		isolation("02:00:00:00:00:09", "0.0.0.0"),
		isolation("02:00:00:00:00:09", "2001:db8::1"),  // ARP is IPv4-only
		isolation("aa:00:00:00:00:01", "192.168.1.50"), // the pinned gateway MAC
		isolation("02:00:00:00:00:09", "192.168.1.1"),  // the gateway IP
		isolation("", "192.168.1.50"),
		{ID: "ACT-2", TargetMAC: "02:00:00:00:00:09", TargetIP: "192.168.1.50"}, // no TTL
	} {
		if err := d.Apply(context.Background(), a); !errors.Is(err, ErrNotApplied) {
			t.Errorf("mac=%q ip=%q ttl=%d: %v, want a refusal", a.TargetMAC, a.TargetIP, a.TTLSeconds, err)
		}
	}
	if len(cmds.cmds) != 0 {
		t.Fatalf("refused targets were queued: %+v", cmds.cmds)
	}
}

func TestPollRequestSanitize(t *testing.T) {
	long := strings.Repeat("x", 200)
	req := PollRequest{
		Agent: "soc-node-1\n{\"forged\":1}",
		Results: []AgentResult{{ID: "i-1", OK: true}, {ID: ""}, {ID: long},
			{ID: "i-2", Error: "refused\x1b[31m"}},
		Active: []AgentIsolation{{MAC: "02-AA-BB-CC-DD-EE", IP: "192.168.1.50"}, {MAC: "nope", IP: "x"}},
	}
	if dropped := req.Sanitize(); dropped != 3 {
		t.Errorf("dropped %d, want 3", dropped)
	}
	if req.Agent != `soc-node-1{"forged":1}` || len(req.Results) != 2 || req.Results[1].Error != "refused[31m" {
		t.Errorf("sanitized: %+v", req)
	}
	if len(req.Active) != 1 || req.Active[0].MAC != "02:aa:bb:cc:dd:ee" {
		t.Errorf("active: %+v", req.Active)
	}
	big := PollRequest{Results: make([]AgentResult, maxPollResults+5), Active: make([]AgentIsolation, maxPollActive+1)}
	for i := range big.Results {
		big.Results[i].ID = "i"
	}
	big.Sanitize()
	if len(big.Results) != maxPollResults || len(big.Active) != 0 {
		t.Errorf("caps not applied: %d results %d active", len(big.Results), len(big.Active))
	}
}

// TestNoRawNetworkCode pins ADR-0004: this service holds no capability and
// opens no raw socket, so nothing in it may be able to craft frames.
func TestNoRawNetworkCode(t *testing.T) {
	root := filepath.Join("..", "..")
	forbidden := []string{"AF_PACKET", "SOCK_RAW", "syscall.Socket", "golang.org/x/sys/unix",
		"SockaddrLinklayer", "CAP_NET_RAW", `ListenPacket("ip`, "ipv4.NewRawConn", "pcap"}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, f := range forbidden {
			if strings.Contains(string(src), f) {
				t.Errorf("%s contains %q: raw network access belongs to the netagent", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
