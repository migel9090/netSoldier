// Command netagent is netSoldier's only process with raw network access
// (ADR-0004). It captures ARP, DHCP, LLDP, mDNS and SSDP frames on one
// interface and forwards them to device-inventory for parsing; it builds and
// sends ARP probes and, only when started with NETAGENT_ENABLE_ARP_ISOLATION,
// ARP isolation frames, each from validated structured commands. It parses
// nothing off the wire and listens on no port.
package main

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/capture"
	"github.com/migel9090/netSoldier/apps/netagent/internal/config"
	"github.com/migel9090/netSoldier/apps/netagent/internal/forward"
	"github.com/migel9090/netSoldier/apps/netagent/internal/isolate"
	"github.com/migel9090/netSoldier/apps/netagent/internal/netif"
	"github.com/migel9090/netSoldier/apps/netagent/internal/peer"
	"github.com/migel9090/netSoldier/apps/netagent/internal/probe"
	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
	"github.com/migel9090/netSoldier/apps/netagent/internal/ratelimit"
	"github.com/migel9090/netSoldier/apps/netagent/internal/wire"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	// Fail with a clear message before any socket work if the capability is
	// missing: added capabilities do nothing for a non-root process without a
	// file capability (audit DP-7/DI-4), so this is the check that matters.
	if err := capture.CheckRaw(); err != nil {
		slog.Error("raw network access unavailable", "error", err)
		os.Exit(1)
	}
	ifi, err := netif.Resolve(cfg.Interface)
	if err != nil {
		slog.Error("interface unusable", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	var protos []capture.Protocol
	for _, name := range cfg.Protocols {
		p, _ := capture.Lookup(name)
		protos = append(protos, p)
	}

	queue := forward.NewQueue(cfg.QueueDepth)
	// Two result streams, one per channel: arp_probe outcomes go back to
	// device-inventory (8.1), arp_isolate/arp_release outcomes to the
	// killswitch (8.2). They must not be mixed, or each peer would be told
	// about the other's commands.
	invResults := proto.NewResults(cfg.ResultsCap)
	ksResults := proto.NewResults(cfg.ResultsCap)
	capt := capture.New(ifi, protos, queue)

	tx, err := wire.Open(ifi)
	if err != nil {
		slog.Error("transmit socket unavailable", "error", err)
		os.Exit(1)
	}
	defer tx.Close()

	prober := &probe.Prober{
		Enabled: cfg.ProbeEnabled,
		Tx:      tx,
		Report:  invResults.Add,
		Limit:   ratelimit.New(cfg.ProbeRate, time.Minute),
		Pace:    cfg.ProbePace,
		Local:   func() ([]netip.Prefix, error) { return netif.Prefixes(ifi) },
	}
	prober.Start(ctx)

	fwd := &forward.Forwarder{
		Agent:     cfg.Agent,
		Interface: cfg.Interface,
		Interval:  cfg.Heartbeat,
		Client:    peer.New("device-inventory", cfg.InventoryURL, cfg.InventoryToken, 2*cfg.Heartbeat),
		Queue:     queue,
		Results:   invResults,
		Capture:   capt.Status,
		Probe:     prober.Handle,
	}

	var engine *isolate.Engine
	if cfg.Isolation {
		guard := &isolate.Guard{
			Interface:     cfg.Interface,
			GatewayIP:     cfg.GatewayIP,
			GatewayMAC:    cfg.GatewayMAC,
			ProtectedMACs: cfg.ProtectedMACs,
			ProtectedIPs:  cfg.ProtectedIPs,
			MaxTTL:        cfg.MaxTTL,
			Local:         netif.Local(ifi),
			Forwarding:    isolate.ProcForwarding(cfg.Interface),
		}
		engine = isolate.NewEngine(guard, tx, cfg.MaxIsolations, cfg.IsolationsPerMin, ksResults.Add)
	}

	var wg sync.WaitGroup
	start := func(fn func()) { wg.Add(1); go func() { defer wg.Done(); fn() }() }
	start(func() { capt.Run(ctx) })
	start(func() { fwd.Run(ctx) })

	fwdClient := fwd.Client
	var pollClient *peer.Client
	if engine != nil {
		poller := &isolate.Poller{
			Agent:    cfg.Agent,
			Interval: cfg.PollInterval,
			Client:   peer.New("killswitch", cfg.KillswitchURL, cfg.KillswitchToken, 5*time.Second),
			Engine:   engine,
			Results:  ksResults,
		}
		pollClient = poller.Client
		start(func() { poller.Run(ctx) })
	}

	stopHealth := startHealth(ctx, cfg, capt, queue, fwdClient, pollClient)

	slog.Info("netagent started", "agent", cfg.Agent, "interface", cfg.Interface,
		"protocols", cfg.Protocols, "arp_probe", cfg.ProbeEnabled, "arp_isolation", cfg.Isolation)

	<-ctx.Done()
	slog.Info("shutting down")
	if engine != nil {
		// Restore every isolated target before the process exits, so a clean
		// stop leaves the segment as it was found.
		engine.Shutdown()
	}
	wg.Wait()
	stopHealth()
}

// startHealth writes the agent's health to a file (and keeps it fresh), so
// a probe can read it without the agent ever opening a port. It returns a
// function that removes the file on shutdown.
func startHealth(ctx context.Context, cfg config.Config, capt *capture.Capture, q *forward.Queue, inv, ks *peer.Client) func() {
	if cfg.HealthFile == "" {
		return func() {}
	}
	type health struct {
		Agent      string          `json:"agent"`
		Time       time.Time       `json:"time"`
		Capture    map[string]bool `json:"capture"`
		QueueLen   int             `json:"queue_len"`
		Dropped    uint64          `json:"dropped"`
		Inventory  peer.Health     `json:"inventory"`
		Killswitch *peer.Health    `json:"killswitch,omitempty"`
	}
	write := func() {
		h := health{Agent: cfg.Agent, Time: time.Now().UTC(), Capture: capt.Status(),
			QueueLen: q.Len(), Dropped: q.Dropped(), Inventory: inv.Health()}
		if ks != nil {
			kh := ks.Health()
			h.Killswitch = &kh
		}
		data, _ := json.Marshal(h)
		tmp := cfg.HealthFile + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			slog.Warn("health file write failed", "error", err)
			return
		}
		_ = os.Rename(tmp, cfg.HealthFile)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(cfg.Heartbeat)
		defer t.Stop()
		write()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				write()
			}
		}
	}()
	return func() { <-done; _ = os.Remove(cfg.HealthFile) }
}
