package misp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
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
func TestPaginationHonoursDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.Write([]byte(`{"response":{"Attribute":[{"type":"domain","value":"a.example"},{"type":"domain","value":"b.example"}]}}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "k")
	c.SetLimits(0, 1000, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	all, err := c.FetchAllAttributes(ctx, SearchRequest{})
	if !errors.Is(err, context.DeadlineExceeded) || len(all) == 0 {
		t.Errorf("attributes=%d err=%v", len(all), err)
	}
}

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
