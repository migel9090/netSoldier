package forward

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/peer"
	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

// stubInventory records the batches it receives and returns a fixed set of
// commands once.
type stubInventory struct {
	mu       sync.Mutex
	batches  []proto.Batch
	commands []proto.Command
	status   int
}

func (s *stubInventory) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, proto.MaxBody+1))
		var b proto.Batch
		if err := json.Unmarshal(body, &b); err != nil {
			t.Errorf("batch does not decode: %v", err)
		}
		s.mu.Lock()
		s.batches = append(s.batches, b)
		code := s.status
		cmds := s.commands
		s.commands = nil
		s.mu.Unlock()
		if code == 0 {
			code = http.StatusOK
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(proto.Commands{Commands: cmds})
	}
}

func (s *stubInventory) seen() []proto.Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]proto.Batch(nil), s.batches...)
}

// probeLog records dispatched probe commands with its own lock.
type probeLog struct {
	mu   sync.Mutex
	cmds []proto.Command
}

func (p *probeLog) add(c proto.Command) { p.mu.Lock(); p.cmds = append(p.cmds, c); p.mu.Unlock() }
func (p *probeLog) len() int            { p.mu.Lock(); defer p.mu.Unlock(); return len(p.cmds) }
func (p *probeLog) first() proto.Command {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmds[0]
}

func newForwarder(t *testing.T, url string) (*Forwarder, *Queue, *proto.Results, *probeLog) {
	q := NewQueue(100)
	res := proto.NewResults(100)
	probed := &probeLog{}
	f := &Forwarder{
		Agent: "soc-node-1", Interface: "eth0", Interval: 10 * time.Millisecond,
		Client: peer.New("device-inventory", url, "tok", 2*time.Second),
		Queue:  q, Results: res,
		Capture: func() map[string]bool { return map[string]bool{"arp": true} },
		Probe:   probed.add,
	}
	return f, q, res, probed
}

func TestForwarderDeliversFramesAndHeartbeat(t *testing.T) {
	stub := &stubInventory{}
	srv := httptest.NewServer(stub.handler(t))
	defer srv.Close()
	f, q, _, _ := newForwarder(t, srv.URL)

	q.Push(proto.Frame{T: 1, Proto: "arp", Data: []byte{1, 2, 3}})
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)
	defer cancel()

	// One batch with the frame, then heartbeats with the capture status.
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		if b := stub.seen(); len(b) >= 1 && len(b[0].Frames) == 1 {
			if b[0].Agent != "soc-node-1" || !b[0].Status.Capture["arp"] {
				t.Fatalf("batch missing agent/status: %+v", b[0])
			}
			// The frame is committed when the forwarder has processed the
			// response, which is a moment after the server saw the request:
			// wait for it rather than asserting in that gap.
			for q.Len() != 0 {
				if time.Now().After(deadline) {
					t.Fatal("delivered frame not committed")
				}
				time.Sleep(time.Millisecond)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no batch with the frame arrived")
}

func TestArpProbeCommandIsDispatched(t *testing.T) {
	stub := &stubInventory{commands: []proto.Command{{ID: "c-18", Type: proto.CmdARPProbe, Target: "192.168.1.0/24"}}}
	srv := httptest.NewServer(stub.handler(t))
	defer srv.Close()
	f, _, _, probed := newForwarder(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)
	defer cancel()

	waitFor(t, func() bool { return probed.len() == 1 })
	if probed.first().Target != "192.168.1.0/24" {
		t.Fatalf("probe command not passed through: %+v", probed.first())
	}
}

// TestNonProbeCommandIsRefused: device-inventory may only issue arp_probe;
// anything else is refused and the refusal is queued back.
func TestNonProbeCommandIsRefused(t *testing.T) {
	stub := &stubInventory{commands: []proto.Command{{ID: "c-19", Type: "arp_isolate", MAC: "aa:bb:cc:dd:ee:ff"}}}
	srv := httptest.NewServer(stub.handler(t))
	defer srv.Close()
	f, _, res, probed := newForwarder(t, srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	go f.Run(ctx)
	defer cancel()

	waitFor(t, func() bool { return res.Len() > 0 })
	if probed.len() != 0 {
		t.Fatal("a non-probe command was dispatched to the prober")
	}
	r := res.Take(1)[0]
	if r.ID != "c-19" || r.OK {
		t.Fatalf("refusal not queued: %+v", r)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Minute)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(3 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}
