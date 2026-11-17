package feedhttp

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// ErrRedirectRefused reports a redirect that would leave the origin a feed
// is pinned to.
var ErrRedirectRefused = errors.New("redirect refused")

// MaxRedirects bounds the same-origin redirects a feed may answer with.
// None of the built-in feeds redirects today (checked 2026-11-17); a few
// hops on the same host leave room for a moved path, no more.
const MaxRedirects = 3

var redirectsRefused = prometheus.NewCounterVec(prometheus.CounterOpts{
	Namespace: "threat_intel",
	Name:      "feed_redirects_refused_total",
	Help:      "Feed responses that redirected to another scheme, host or port and were refused.",
}, []string{"source"})

func init() {
	prometheus.MustRegister(redirectsRefused)
}

// InitSourceMetrics creates the per-source series up front.
func InitSourceMetrics(source string) { redirectsRefused.WithLabelValues(source) }

// NewClient returns the HTTP client every feed uses. A feed is pinned to the
// origin — scheme, host and port — of the URL it is configured with:
//
//   - A redirect to any other origin is refused, and so is a downgrade from
//     https to http on the same host. Go's default client follows up to ten
//     redirects anywhere, carrying custom headers along: abuse.ch's Auth-Key
//     would have gone to whatever host a hijacked or misconfigured response
//     pointed at, and the "feed" would have been that host's content.
//     (Go strips Authorization on a cross-host redirect, but not Auth-Key.)
//   - TLS 1.2 is the minimum and certificates are verified against the
//     system roots; there is no option to turn that off.
//
// source names the feed in the refusal counter and the error.
func NewClient(source string, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &http.Client{
		Timeout:       timeout,
		Transport:     tr,
		CheckRedirect: sameOrigin(source),
	}
}

func sameOrigin(source string) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		from := origin(via[0].URL)
		to := origin(req.URL)
		if to != from {
			redirectsRefused.WithLabelValues(source).Inc()
			return fmt.Errorf("%w: %s is pinned to %s, the response redirected to %s",
				ErrRedirectRefused, source, from, to)
		}
		if len(via) > MaxRedirects {
			return fmt.Errorf("%w: %s redirected more than %d times", ErrRedirectRefused, source, MaxRedirects)
		}
		return nil
	}
}

// origin is scheme://host:port with the default port made explicit and the
// host lower-cased, so "https://Feed.example/" and "https://feed.example:443"
// compare equal and nothing else does.
func origin(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// CheckPinned reports whether rawURL is an https URL on exactly host, with
// no user information and the default port: the shape of every built-in
// feed's endpoint.
func CheckPinned(rawURL, host string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme != "https":
		return fmt.Errorf("%s: scheme %q, want https", rawURL, u.Scheme)
	case u.User != nil:
		return fmt.Errorf("%s: carries user information", rawURL)
	case u.Host != host:
		return fmt.Errorf("%s: host %q, want %q", rawURL, u.Host, host)
	}
	return nil
}
