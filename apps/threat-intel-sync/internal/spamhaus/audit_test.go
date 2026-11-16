package spamhaus

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

// TestAuditParseAndPartial (TI-2, TI-8): the auditor's DROP body with a
// catch-all and a private range, and the retired EDROP URL. EDROP was merged
// into DROP on 2024-04-10; fetching it made FetchAll return data AND an
// error, and the sync loop discarded the data.
func TestAuditParseAndPartial(t *testing.T) {
	inds, err := parseDROPList(strings.NewReader("; Spamhaus DROP List 2026/11/16\n; Last-Modified: x\n"+
		"1.10.16.0/20 ; SBL256263\n0.0.0.0/1 ; SBL1\tx\ty\n10.0.0.0/8 ; SBL2\n; EOF\n"), "spamhaus-drop", "drop")
	if err != nil || len(inds) != 3 {
		t.Fatalf("parsed %d, err=%v", len(inds), err)
	}
	s := ioc.NewStore()
	if acc, rej := s.UpsertAll(inds); acc != 1 || rej != 2 {
		t.Errorf("accepted=%d rejected=%d, want only 1.10.16.0/20", acc, rej)
	}
	for _, i := range s.All() {
		if strings.ContainsAny(i.Reference, "\t\n") {
			t.Errorf("reference kept a control character: %q", i.Reference)
		}
	}

	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if strings.Contains(r.URL.Path, "edrop") {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("1.10.16.0/20 ; SBL256263\n"))
	}))
	defer srv.Close()
	c := NewClient(0)
	c.dropURL = srv.URL + "/drop/drop.txt"
	all, err := c.FetchAll(context.Background())
	if err != nil || len(all) != 1 {
		t.Errorf("FetchAll = %d indicators, err=%v", len(all), err)
	}
	if len(paths) != 1 || paths[0] != "/drop/drop.txt" {
		t.Errorf("requested %v; the retired EDROP list must not be fetched", paths)
	}
	c.dropURL = srv.URL + "/edrop/edrop.txt"
	if _, err := c.FetchDROP(context.Background()); err == nil {
		t.Error("a 404 must be an error")
	}
}

// TestDROPBodyCap (TI-4): an oversized body stops at the cap, returns the
// complete lines read so far, and never the truncated last one.
func TestDROPBodyCap(t *testing.T) {
	body := "1.10.16.0/20 ; SBL1\n203.0.113.128/25 ; SBL2\n"
	cut := strings.Index(body, "203.0.113.128") + len("203.0.113.1")
	inds, err := parseDROPList(feedhttp.LimitBody(strings.NewReader(body), int64(cut)), "spamhaus-drop", "drop")
	if !errors.Is(err, feedhttp.ErrTooLarge) {
		t.Fatalf("err = %v", err)
	}
	if len(inds) != 1 || inds[0].Value != "1.10.16.0/20" {
		t.Errorf("rows = %+v", inds)
	}
}
