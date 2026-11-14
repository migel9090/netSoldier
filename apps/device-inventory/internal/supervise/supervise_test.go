package supervise

import (
	"context"
	"errors"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func init() {
	Initial, Max, ResetAfter = time.Millisecond, 4*time.Millisecond, time.Hour
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// DI-11, from the auditor's eintr.sh: one EINTR (or any transient error)
// ended a listener goroutine for good while /healthz stayed green.
func TestFailingListenerIsRestarted(t *testing.T) {
	st := NewStatus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	done := make(chan struct{})
	go func() {
		Run(ctx, st, "arp", func(ctx context.Context, up func()) error {
			if runs.Add(1) < 3 {
				return syscall.EINTR
			}
			up()
			<-ctx.Done()
			return nil
		})
		close(done)
	}()
	waitFor(t, "third run up", func() bool { _, s := st.Ready(); return s["arp"].Up })
	_, states := st.Ready()
	if s := states["arp"]; !s.Up || s.Restarts != 2 || s.LastError != syscall.EINTR.Error() {
		t.Errorf("state %+v", s)
	}
	cancel()
	<-done
	if ready, _ := st.Ready(); ready {
		t.Error("a stopped listener must not be ready")
	}
}

func TestPanickingListenerIsRecovered(t *testing.T) {
	st := NewStatus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	go Run(ctx, st, "mdns", func(ctx context.Context, up func()) error {
		if runs.Add(1) == 1 {
			up()
			panic("parser bug")
		}
		up()
		<-ctx.Done()
		return nil
	})
	waitFor(t, "restart after panic", func() bool { return runs.Load() >= 2 })
	waitFor(t, "up again", func() bool { _, s := st.Ready(); return s["mdns"].Up && s["mdns"].Restarts > 0 })
	if _, s := st.Ready(); s["mdns"].LastError != "panic: parser bug" {
		t.Errorf("state %+v", s["mdns"])
	}
}

func TestReadyNeedsEveryListener(t *testing.T) {
	st := NewStatus()
	if ready, _ := st.Ready(); !ready {
		t.Error("with no listeners configured there is nothing to wait for")
	}
	st.Register("dhcp")
	st.Register("arp")
	if ready, _ := st.Ready(); ready {
		t.Error("registered but not yet up must not be ready")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Run(ctx, st, "dhcp", func(ctx context.Context, up func()) error { up(); <-ctx.Done(); return nil })
	go Run(ctx, st, "arp", func(ctx context.Context, up func()) error {
		return errors.New("AF_PACKET socket (needs CAP_NET_RAW): operation not permitted")
	})
	waitFor(t, "dhcp up", func() bool { _, s := st.Ready(); return s["dhcp"].Up })
	time.Sleep(20 * time.Millisecond)
	if ready, s := st.Ready(); ready || s["arp"].Up || s["arp"].Restarts == 0 {
		t.Errorf("ready=%v arp=%+v", ready, s["arp"])
	}
	if names := st.Names(); len(names) != 2 || names[0] != "arp" {
		t.Errorf("names %v", names)
	}
}

func TestReturningWithoutErrorIsAFailure(t *testing.T) {
	st := NewStatus()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	go Run(ctx, st, "ssdp", func(context.Context, func()) error { runs.Add(1); return nil })
	waitFor(t, "restarts", func() bool { return runs.Load() >= 3 })
}
