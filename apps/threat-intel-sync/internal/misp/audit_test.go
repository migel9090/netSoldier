package misp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
)

// TestAuditPaginationNeverEnds (TI-4): a MISP that always returns a full
// page (it ignores "page", or simply holds a lot). Pagination used to stop
// only when a deadline the production code never set expired; now it stops
// at the page cap and returns what it has with ErrPageCap.
func TestAuditPaginationNeverEnds(t *testing.T) {
	var pages atomic.Int64
	attrs := make([]Attribute, 10000)
	for i := range attrs {
		attrs[i] = Attribute{Type: "domain", Value: "same.example", Comment: "c"}
	}
	var resp attributeResponse
	resp.Response.Attribute = attrs
	page, _ := json.Marshal(resp)
	var auth atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.Store(r.Header.Get("Authorization"))
		pages.Add(1)
		w.Write(page)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "SECRETKEY")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	start := time.Now()
	all, err := c.FetchAllAttributes(context.Background(), SearchRequest{Types: []string{TypeDomain}, Limit: 10000})
	runtime.ReadMemStats(&after)
	t.Logf("pages requested=%d, attributes=%d, heap +%d MiB, in %s, err=%v", pages.Load(), len(all),
		(int64(after.HeapAlloc)-int64(before.HeapAlloc))>>20, time.Since(start).Round(time.Millisecond), err)

	if !errors.Is(err, ErrPageCap) {
		t.Fatalf("err = %v, want ErrPageCap", err)
	}
	if pages.Load() != DefaultMaxPages || len(all) != DefaultMaxPages*10000 {
		t.Errorf("pages=%d attributes=%d, want %d pages", pages.Load(), len(all), DefaultMaxPages)
	}
	if auth.Load() != "SECRETKEY" {
		t.Error("Authorization header not sent")
	}

	// With the default page size the same server is caught on its first
	// page: it sends more than was asked for.
	pages.Store(0)
	all, err = c.FetchAllAttributes(context.Background(), SearchRequest{Types: []string{TypeDomain}})
	if err == nil || pages.Load() != 1 || len(all) != DefaultPageSize {
		t.Errorf("oversized page: pages=%d attributes=%d err=%v", pages.Load(), len(all), err)
	}
}

// TestPaginationHonoursDeadline: the caller's overall deadline (the sync
// loop's SOURCE_TIMEOUT) ends pagination with what was fetched.
//
// The deadline passes while the second page is outstanding, because the
// server says so — not 200ms into the test, which a loaded runner could
// reach before the first page was in.
func TestPaginationHonoursDeadline(t *testing.T) {
	ctx := newExpiringContext()
	var pages atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // to the end: then the caller giving up ends r.Context()
		if pages.Add(1) > 1 {
			ctx.expire()
			select {
			case <-r.Context().Done():
			case <-time.After(time.Minute):
			}
			return
		}
		w.Write([]byte(`{"response":{"Attribute":[{"type":"domain","value":"a.example"},{"type":"domain","value":"b.example"}]}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "k")
	c.SetLimits(0, 1000, 2)
	all, err := c.FetchAllAttributes(ctx, SearchRequest{})
	if !errors.Is(err, context.DeadlineExceeded) || len(all) != 2 || pages.Load() != 2 {
		t.Errorf("pages=%d attributes=%d err=%v, want the first page and the deadline", pages.Load(), len(all), err)
	}
}

// expiringContext is a context whose deadline passes when the test says
// so: from expire on, it is done with context.DeadlineExceeded.
type expiringContext struct {
	context.Context
	done chan struct{}
	once sync.Once
}

func newExpiringContext() *expiringContext {
	return &expiringContext{Context: context.Background(), done: make(chan struct{})}
}

func (c *expiringContext) Done() <-chan struct{} { return c.done }

func (c *expiringContext) Err() error {
	select {
	case <-c.done:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

func (c *expiringContext) expire() { c.once.Do(func() { close(c.done) }) }

func TestPageBodyCapAndStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "k" {
			http.Error(w, "nope\n\tforged log line", http.StatusForbidden)
			return
		}
		w.Write([]byte(`{"response":{"Attribute":[{"type":"domain","value":"` + strings.Repeat("a", 2<<20) + `"}]}}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "k")
	c.SetLimits(1<<20, 0, 0)
	if _, err := c.FetchAllAttributes(context.Background(), SearchRequest{}); !errors.Is(err, feedhttp.ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
	_, err := NewClient(srv.URL, "wrong").FetchAttributes(context.Background(), SearchRequest{
		Types: []string{TypeDomain}, Published: true, Timestamp: "7d", Page: 2, ToIDs: true, EnforceWarninglist: true})
	if err == nil || !strings.Contains(err.Error(), "credentials rejected") || strings.ContainsAny(err.Error(), "\n\t") {
		t.Errorf("err = %q", err)
	}
}

func TestAttributeHelpers(t *testing.T) {
	a := Attribute{Timestamp: "1700000000", Tags: []Tag{{Name: "tlp:white"}}}
	if a.Time().Unix() != 1700000000 || !a.HasTag("tlp:white") || a.HasTag("x") {
		t.Errorf("helpers wrong for %+v", a)
	}
	if !(Attribute{Timestamp: "x"}).Time().IsZero() {
		t.Error("bad timestamp should be zero")
	}
}
