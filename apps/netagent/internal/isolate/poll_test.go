package isolate

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

// stubKillswitch stands in for the killswitch's POST /agent/v1/poll. It
// records each poll body and replies with queued commands once. This is the
// contract the real killswitch must serve (see the report).
type stubKillswitch struct {
	mu       sync.Mutex
	polls    []proto.Poll
	commands []proto.Command
	token    string
}

func (s *stubKillswitch) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/agent/v1/poll" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+s.token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(r.Body, proto.MaxBody+1))
		var p proto.Poll
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("poll body does not decode: %v", err)
		}
		s.mu.Lock()
		s.polls = append(s.polls, p)
		cmds := s.commands
		s.commands = nil
		s.mu.Unlock()
		_ = json.NewEncoder(w).Encode(proto.Commands{Commands: cmds})
	}
}

func (s *stubKillswitch) lastPoll() (proto.Poll, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.polls) == 0 {
		return proto.Poll{}, false
	}
	return s.polls[len(s.polls)-1], true
}

func (s *stubKillswitch) queue(c ...proto.Command) {
	s.mu.Lock()
	s.commands = c
	s.mu.Unlock()
}

// sawResult reports whether any poll body carried a result matching pred.
func (s *stubKillswitch) sawResult(pred func(proto.Result) bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.polls {
		for _, r := range p.Results {
			if pred(r) {
				return true
			}
		}
	}
	return false
}

func TestPollerDrivesTheEngine(t *testing.T) {
	refreshEvery, liftRounds, liftGap = 10*time.Millisecond, 1, 0
	stub := &stubKillswitch{token: "ktok"}
	srv := httptest.NewServer(stub.handler(t))
	defer srv.Close()

	tx := &fakeTx{}
	res := proto.NewResults(100)
	eng := NewEngine(newGuard(), tx, 4, 100, res.Add)
	defer eng.Shutdown()
	poller := &Poller{
		Agent:    "soc-node-1",
		Interval: 10 * time.Millisecond,
		Client:   peer.New("killswitch", srv.URL+"/agent/v1/poll", "ktok", 2*time.Second),
		Engine:   eng,
		Results:  res,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The killswitch asks to isolate a host, then (a round later) to release it.
	stub.queue(proto.Command{ID: "i-5", Type: proto.CmdARPIsolate, MAC: "aa:bb:cc:dd:ee:77", IP: "192.168.1.77", TTLSeconds: 3600})
	go poller.Run(ctx)

	waitFor(t, func() bool { return len(eng.Active()) == 1 })
	// The next poll reports the isolation in `active` and the result of i-5.
	waitFor(t, func() bool {
		p, ok := stub.lastPoll()
		return ok && len(p.Active) == 1 && p.Active[0].IP == "192.168.1.77"
	})
	if !stub.sawResult(func(r proto.Result) bool { return r.ID == "i-5" && r.OK }) {
		t.Fatal("the isolate result was never reported back to the killswitch")
	}

	stub.queue(proto.Command{ID: "i-6", Type: proto.CmdARPRelease, MAC: "aa:bb:cc:dd:ee:77"})
	waitFor(t, func() bool { return len(eng.Active()) == 0 })
	if _, lifts := tx.counts(); lifts == 0 {
		t.Fatal("release did not restore the target")
	}
}

func TestPollerRefusalReachesKillswitch(t *testing.T) {
	stub := &stubKillswitch{token: "ktok"}
	srv := httptest.NewServer(stub.handler(t))
	defer srv.Close()
	res := proto.NewResults(100)
	eng := NewEngine(newGuard(), &fakeTx{}, 4, 100, res.Add)
	defer eng.Shutdown()
	poller := &Poller{Agent: "n", Interval: 10 * time.Millisecond,
		Client: peer.New("killswitch", srv.URL+"/agent/v1/poll", "ktok", 2*time.Second), Engine: eng, Results: res}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stub.queue(proto.Command{ID: "i-7", Type: proto.CmdARPIsolate, MAC: "ff:ff:ff:ff:ff:ff", IP: "192.168.1.77", TTLSeconds: 3600})
	go poller.Run(ctx)
	waitFor(t, func() bool {
		return stub.sawResult(func(r proto.Result) bool { return r.ID == "i-7" && !r.OK })
	})
}
