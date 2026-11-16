package peer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/netagent/internal/proto"
)

func TestPostSendsBearerAndParsesCommands(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"commands":[{"id":"c-1","type":"arp_probe","target":"192.168.1.0/24"}]}`))
	}))
	defer srv.Close()
	c := New("inv", srv.URL, "secret", time.Minute)
	code, cmds, err := c.Post(context.Background(), proto.Batch{Agent: "n"})
	if err != nil || code != 200 {
		t.Fatalf("Post: %d %v", code, err)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("auth header = %q", gotAuth)
	}
	if len(cmds) != 1 || cmds[0].ID != "c-1" {
		t.Fatalf("commands = %+v", cmds)
	}
}

func TestPostRejectsOversizeBody(t *testing.T) {
	c := New("inv", "http://127.0.0.1:0", "t", time.Second)
	big := proto.Batch{Agent: strings.Repeat("a", proto.MaxBody+1)}
	if _, _, err := c.Post(context.Background(), big); err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestPostBoundsResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("{\"commands\":[")) // start a huge body
		filler := strings.Repeat(" ", proto.MaxResponse+100)
		w.Write([]byte(filler))
		w.Write([]byte("]}"))
	}))
	defer srv.Close()
	c := New("inv", srv.URL, "t", time.Minute)
	code, cmds, err := c.Post(context.Background(), proto.Batch{})
	if code != 200 || err == nil || cmds != nil {
		t.Fatalf("oversize response should return 200 with an error and no commands: %d %v %+v", code, err, cmds)
	}
}

func TestHealthTracksFailures(t *testing.T) {
	c := New("inv", "http://127.0.0.1:0", "t", time.Second)
	now := time.Now()
	c.Failed(now, errSample)
	c.Failed(now, errSample)
	if h := c.Health(); h.Failures != 2 || h.LastError == "" {
		t.Fatalf("health = %+v", h)
	}
	c.Succeeded(now)
	if h := c.Health(); h.Failures != 0 || h.LastOK.IsZero() {
		t.Fatalf("health after success = %+v", h)
	}
}

func TestBackoffGrowsAndResets(t *testing.T) {
	b := Backoff{Initial: time.Second, Max: 10 * time.Second}
	first := b.Next()
	if first < 800*time.Millisecond || first > 1200*time.Millisecond {
		t.Fatalf("first backoff out of jitter range: %v", first)
	}
	for i := 0; i < 10; i++ {
		b.Next()
	}
	if capped := b.Next(); capped > 12*time.Second {
		t.Fatalf("backoff exceeded max+jitter: %v", capped)
	}
	b.Reset()
	if again := b.Next(); again > 1200*time.Millisecond {
		t.Fatalf("reset did not take: %v", again)
	}
}

type errStr string

func (e errStr) Error() string { return string(e) }

const errSample = errStr("boom")
