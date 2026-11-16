// Package forward delivers captured frames to device-inventory (contract v2
// section 8.1) and carries its arp_probe commands back. Every request is
// also the heartbeat: it is sent at least every interval, frames or not.
package forward

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/peer"
	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

// Batch bounds. A frame costs its base64 length plus the JSON around it;
// what is left of MaxBody after the frame budget covers results, status and
// the envelope with a wide margin.
const (
	maxBatchFrames = 4096
	frameBudget    = proto.MaxBody - 96<<10
	frameOverhead  = 64 // {"t":…,"proto":"mdns","data":""},
)

func frameCost(f proto.Frame) int { return base64.StdEncoding.EncodedLen(len(f.Data)) + frameOverhead }

// Forwarder sends batches from a queue.
type Forwarder struct {
	Agent, Interface string
	Interval         time.Duration
	Client           *peer.Client
	Queue            *Queue
	Results          *proto.Results
	// Capture reports the heartbeat's capture map.
	Capture func() map[string]bool
	// Probe handles a validated-id arp_probe command; it reports the
	// outcome into Results itself.
	Probe func(proto.Command)

	now func() time.Time
}

// Run sends until ctx is done. After a failure it backs off; after a full
// batch it sends again at once, so a backlog drains as fast as
// device-inventory accepts it.
func (f *Forwarder) Run(ctx context.Context) {
	if f.now == nil {
		f.now = time.Now
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
		full, err := f.send(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			f.Client.Failed(f.now(), err)
			wait = backoff.Next()
		case full:
			backoff.Reset()
			wait = 0
		default:
			backoff.Reset()
			wait = f.Interval
		}
	}
}

// send delivers one batch. It reports whether the batch was full, i.e.
// whether more frames are probably waiting.
func (f *Forwarder) send(ctx context.Context) (bool, error) {
	frames, end := f.Queue.Peek(maxBatchFrames, frameBudget, frameCost)
	results := f.Results.Take(proto.MaxResultBatch)
	batch := proto.Batch{
		Agent:     f.Agent,
		Interface: f.Interface,
		Frames:    frames,
		Results:   results,
		Status:    proto.Status{Capture: f.Capture(), Dropped: f.Queue.Dropped()},
	}
	if batch.Frames == nil {
		batch.Frames = []proto.Frame{}
	}
	code, cmds, err := f.Client.Post(ctx, batch)
	switch {
	case code == http.StatusOK:
		f.Queue.Commit(end)
		f.Client.Succeeded(f.now())
		if err != nil {
			slog.Warn("device-inventory accepted the batch but its response was unusable", "error", err)
		}
		f.dispatch(cmds)
		return len(frames) > 0 && f.Queue.Len() > 0, nil
	case errors.Is(err, peer.ErrTooLarge), code == http.StatusBadRequest,
		code == http.StatusRequestEntityTooLarge, code == http.StatusUnprocessableEntity:
		// The batch itself is unacceptable. Retrying it would wedge the
		// queue behind it forever, so it is dropped (and counted).
		f.Queue.Discard(end)
		slog.Error("device-inventory refused a batch; its frames are dropped", "status", code, "frames", len(frames), "error", err)
		return false, err
	default:
		f.Results.Return(results)
		return false, err
	}
}

func (f *Forwarder) dispatch(cmds []proto.Command) {
	if len(cmds) > proto.MaxCommands {
		slog.Warn("device-inventory sent too many commands; the rest are ignored", "sent", len(cmds), "max", proto.MaxCommands)
		cmds = cmds[:proto.MaxCommands]
	}
	for _, c := range cmds {
		if !proto.ValidID(c.ID) {
			slog.Warn("command without a usable id ignored", "type", proto.Clip(c.Type, 32))
			continue
		}
		if c.Type != proto.CmdARPProbe {
			slog.Warn("command refused", "id", c.ID, "type", proto.Clip(c.Type, 32), "reason", "not accepted from device-inventory")
			f.Results.Add(proto.Result{ID: c.ID, Error: "refused: command type is not accepted from device-inventory"})
			continue
		}
		f.Probe(c)
	}
}
