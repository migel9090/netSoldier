package export

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/ioc"
)

func adguardGet(a *AdGuard, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/export/adguard", nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, req)
	return rec
}

func rulesOf(body string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if l != "" && !strings.HasPrefix(l, "!") {
			out = append(out, l)
		}
	}
	return out
}

// TestAdGuardFormat: filter syntax only, sorted, with a header that says
// when it was generated, how many rules it holds per source, and which
// sources are held back or stale. A popular domain never becomes a rule.
func TestAdGuardFormat(t *testing.T) {
	s := ioc.NewStore()
	s.UpsertFeed("threatfox", []ioc.Indicator{
		{Type: ioc.TypeDomain, Value: "zz.evil.example", Source: "threatfox"},
		{Type: ioc.TypeDomain, Value: "aa.evil.example", Source: "threatfox"},
		{Type: ioc.TypeDomain, Value: "drive.google.com", Source: "threatfox"}, // never-block
		{Type: ioc.TypeIP, Value: "203.0.113.9", Source: "threatfox"},
	})
	s.UpsertFeed("urlhaus", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "aa.evil.example", Source: "urlhaus"}})
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	a := NewAdGuard(s, AdGuardOptions{
		Expires: 6 * time.Hour,
		Now:     func() time.Time { return now },
		Status: func() AdGuardStatus {
			return AdGuardStatus{Quarantined: []string{"misp"}, Stale: []string{"feodo", "bad\nname"}}
		},
	})
	rec := adguardGet(a, nil)
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rulesOf(body); strings.Join(got, ",") != "||aa.evil.example^,||zz.evil.example^" {
		t.Errorf("rules = %q", got)
	}
	for _, want := range []string{
		"! Title: netSoldier threat intelligence\n",
		"! Last modified: 2026-11-17T12:00:00Z\n",
		"! Expires: 6 hours (update frequency)\n",
		"! Entries: 2\n",
		"! Sources: threatfox=2 urlhaus=1\n",
		"! Quarantined sources: misp\n",
		"! Stale sources: feodo\n",
		"! Never-block list: ",
		"! Version: ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("header lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "google") || strings.Contains(body, "bad") {
		t.Errorf("a never-block domain or an unsafe source name leaked:\n%s", body)
	}
	for _, l := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if !strings.HasPrefix(l, "!") && !strings.HasPrefix(l, "||") {
			t.Errorf("line %q is neither a comment nor a rule", l)
		}
	}
	if rec.Header().Get("Content-Length") != strconv.Itoa(len(body)) {
		t.Errorf("Content-Length %q for %d bytes", rec.Header().Get("Content-Length"), len(body))
	}
	if rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type %q", rec.Header().Get("Content-Type"))
	}
}

// TestAdGuardConditionalRequests: an unchanged list keeps its ETag and
// Last-Modified however often it is fetched, and a client that has it gets
// 304 with no body. A change produces a new ETag and a later Last-Modified.
func TestAdGuardConditionalRequests(t *testing.T) {
	s := ioc.NewStore()
	s.UpsertFeed("threatfox", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "c2.evil.example"}})
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	a := NewAdGuard(s, AdGuardOptions{Now: func() time.Time { return clock }})

	first := adguardGet(a, nil)
	etag, lm := first.Header().Get("ETag"), first.Header().Get("Last-Modified")
	if first.Code != 200 || etag == "" || lm == "" {
		t.Fatalf("first fetch: %d etag=%q lm=%q", first.Code, etag, lm)
	}
	clock = clock.Add(time.Hour)
	again := adguardGet(a, nil)
	if again.Header().Get("ETag") != etag || again.Header().Get("Last-Modified") != lm || again.Body.String() != first.Body.String() {
		t.Error("an unchanged list changed its ETag, Last-Modified or body")
	}
	if rec := adguardGet(a, map[string]string{"If-None-Match": etag}); rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("If-None-Match: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if rec := adguardGet(a, map[string]string{"If-Modified-Since": lm}); rec.Code != http.StatusNotModified {
		t.Errorf("If-Modified-Since: %d", rec.Code)
	}

	s.UpsertFeed("threatfox", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "c3.evil.example"}})
	changed := adguardGet(a, map[string]string{"If-None-Match": etag})
	if changed.Code != 200 || changed.Header().Get("ETag") == etag || len(rulesOf(changed.Body.String())) != 2 {
		t.Errorf("after a change: %d etag=%q", changed.Code, changed.Header().Get("ETag"))
	}
	if rec := adguardGet(a, map[string]string{"If-Modified-Since": lm}); rec.Code != 200 {
		t.Errorf("If-Modified-Since the old version after a change: %d", rec.Code)
	}
}

// TestAdGuardSameSecondChange: two contents within one second must not
// share a Last-Modified, or If-Modified-Since would hide the second.
func TestAdGuardSameSecondChange(t *testing.T) {
	s := ioc.NewStore()
	s.UpsertFeed("f", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "a.evil.example"}})
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	a := NewAdGuard(s, AdGuardOptions{Now: func() time.Time { return clock }})
	lm := adguardGet(a, nil).Header().Get("Last-Modified")
	s.UpsertFeed("f", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "b.evil.example"}})
	if rec := adguardGet(a, map[string]string{"If-Modified-Since": lm}); rec.Code != 200 {
		t.Errorf("a change within the same second answered %d", rec.Code)
	}
}

func TestAdGuardGzip(t *testing.T) {
	s := ioc.NewStore()
	s.UpsertFeed("f", []ioc.Indicator{{Type: ioc.TypeDomain, Value: "a.evil.example"}})
	a := NewAdGuard(s, AdGuardOptions{})
	plain := adguardGet(a, nil)
	gz := adguardGet(a, map[string]string{"Accept-Encoding": "gzip"})
	if gz.Header().Get("Content-Encoding") != "gzip" || gz.Header().Get("ETag") == plain.Header().Get("ETag") {
		t.Fatalf("gzip response headers: %v", gz.Header())
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := io.ReadAll(zr)
	if string(dec) != plain.Body.String() {
		t.Error("the gzip body is not the plain body")
	}
	if rec := adguardGet(a, map[string]string{"Accept-Encoding": "gzip;q=0, identity"}); rec.Header().Get("Content-Encoding") != "" {
		t.Error("gzip served although the client refused it")
	}
}

// TestAdGuardEmptyWhenReady: with no domain source enabled the list is
// served with no rules and says why. A deliberate configuration change
// (COMMERCIAL_MODE removing the abuse.ch feeds) must stop their blocks; the
// failure cases are kept out by the readiness gate in front of this
// handler (cmd/threat-intel-sync).
func TestAdGuardEmptyWhenReady(t *testing.T) {
	s := ioc.NewStore()
	s.UpsertFeed("spamhaus", []ioc.Indicator{{Type: ioc.TypeIP, Value: "198.51.100.0/24"}})
	rec := adguardGet(NewAdGuard(s, AdGuardOptions{}), nil)
	if rec.Code != 200 || len(rulesOf(rec.Body.String())) != 0 ||
		!strings.Contains(rec.Body.String(), "! Entries: 0\n! No enabled source currently provides domain indicators.\n") {
		t.Errorf("%d\n%s", rec.Code, rec.Body.String())
	}
}
