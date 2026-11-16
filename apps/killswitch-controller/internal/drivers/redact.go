package drivers

import (
	"errors"
	"net/url"
	"strings"
)

// A driver's error becomes the action's failure_reason, an audit entry and
// a log line, so it must not carry what authenticates the controller to
// its backend. Two things in it come from outside this code: the request
// URL that net/http puts into a transport error, and the backend's own
// answer, which an upstream or a proxy in front of it may build from the
// request.

// redacted stands in for a removed secret.
const redacted = "[redacted]"

// endpointOf is scheme://host[:port] of a configured URL. net/http hides a
// password in the URL's userinfo, but keeps the path and the query, and a
// webhook URL's path or query is often its secret (an adapter's hook id,
// a token parameter).
func endpointOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(configured URL)"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// requestError is err with the URL of a transport error replaced by
// endpoint. The cause is kept, so errors.Is still sees a deadline.
func requestError(err error, endpoint string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return &url.Error{Op: ue.Op, URL: endpoint, Err: ue.Err}
	}
	return err
}

// scrub is a backend's answer with every given secret replaced, for an
// error message.
func scrub(body []byte, secrets ...string) string {
	s := strings.TrimSpace(string(body))
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, redacted)
		}
	}
	return s
}

// urlSecrets are the parts of a configured URL that may authenticate: the
// whole URL, its userinfo password, and its path with the query when there
// is more to it than "/".
func urlSecrets(raw string) []string {
	out := []string{raw}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	if p, ok := u.User.Password(); ok {
		out = append(out, p)
	}
	if uri := u.RequestURI(); uri != "/" && uri != "" {
		out = append(out, uri)
		if u.RawQuery != "" {
			out = append(out, u.RawQuery)
		}
	}
	return out
}
