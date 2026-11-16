package isolate

import (
	"context"
	"log/slog"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/peer"
	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

// Poller is the agent's side of the killswitch channel (contract 8.2): about
// once a second it POSTs its pending results and the isolations in force, and
// acts on the commands the killswitch returns. It never listens; commands
// arrive only as answers to its own poll.
type Poller struct {
	Agent    string
	Interval time.Duration
	Client   *peer.Client
	Engine   *Engine
	Results  *proto.Results

	now func() time.Time
}

// Run polls until ctx is done, backing off on failure.
func (p *Poller) Run(ctx context.Context) {
	if p.now == nil {
		p.now = time.Now
	}
	backoff := peer.Backoff{Initial: time.Second, Max: 30 * time.Second}
	wait := time.Duration(0)
	for {
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		if err := p.round(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			p.Client.Failed(p.now(), err)
			wait = backoff.Next()
			continue
		}
		backoff.Reset()
		wait = p.Interval
	}
}

func (p *Poller) round(ctx context.Context) error {
	results := p.Results.Take(proto.MaxResultBatch)
	body := proto.Poll{Agent: p.Agent, Results: results, Active: p.Engine.Active()}
	code, cmds, err := p.Client.Post(ctx, body)
	if err != nil || code != 200 {
		// The killswitch did not accept the poll, so it did not see these
		// outcomes; keep them for the next round.
		p.Results.Return(results)
		if err == nil {
			err = &Refusal{Code: "http", Reason: "non-200 from killswitch"}
		}
		return err
	}
	p.Client.Succeeded(p.now())
	p.dispatch(ctx, cmds)
	return nil
}

func (p *Poller) dispatch(ctx context.Context, cmds []proto.Command) {
	if len(cmds) > proto.MaxCommands {
		slog.Warn("killswitch sent too many commands; the rest are ignored", "sent", len(cmds), "max", proto.MaxCommands)
		cmds = cmds[:proto.MaxCommands]
	}
	for _, c := range cmds {
		if !proto.ValidID(c.ID) {
			slog.Warn("isolation command without a usable id ignored", "type", proto.Clip(c.Type, 32))
			continue
		}
		p.Engine.Handle(ctx, c)
	}
}
