package abusech

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/migel9090/netSoldier/apps/threat-intel-sync/internal/feedhttp"
)

// Option configures an abuse.ch client.
type Option func(*options)

type options struct {
	authKey  string
	maxBytes int64
}

// WithAuthKey sets the abuse.ch Auth-Key sent in the "Auth-Key" header.
// The ThreatFox and URLhaus API documentation states that every request must
// carry one (keys are issued free of charge at https://auth.abuse.ch/), and
// the abuse.ch terms of use restrict access to authenticated users. The
// Feodo Tracker blocklist page documents no key; it is sent there too when
// configured.
func WithAuthKey(key string) Option { return func(o *options) { o.authKey = key } }

// WithMaxBodyBytes caps the size of one response body.
func WithMaxBodyBytes(n int64) Option { return func(o *options) { o.maxBytes = n } }

func buildOptions(opts []Option) options {
	o := options{maxBytes: feedhttp.DefaultMaxBodyBytes}
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

func (o options) authorize(req *http.Request) {
	if o.authKey != "" {
		req.Header.Set("Auth-Key", o.authKey)
	}
}

// decodeEnvelope streams an abuse.ch API response of the shape
// {"query_status": "...", "<listKey>": [ ... ]}, handing each element of the
// list to each as it is read, so memory follows the useful rows rather than
// the body size. It returns the query status and how many elements were
// read. A decode error on a single element (a field of the wrong type) is
// counted in malformed and skipped; a syntax error or the body cap stops the
// walk and is returned together with whatever was read before it.
func decodeEnvelope(r io.Reader, listKey string, each func(*json.Decoder) error) (status string, rows, malformed int, err error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return "", 0, 0, err
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return status, rows, malformed, err
		}
		key, _ := tok.(string)
		switch key {
		case "query_status":
			if err := dec.Decode(&status); err != nil {
				return status, rows, malformed, fmt.Errorf("query_status: %w", err)
			}
		case listKey:
			tok, err := dec.Token()
			if err != nil {
				return status, rows, malformed, err
			}
			if d, ok := tok.(json.Delim); !ok || d != '[' {
				// null, or an explanatory string on an empty result
				if d == '{' {
					if err := skipValue(dec, 1); err != nil {
						return status, rows, malformed, err
					}
				}
				continue
			}
			for dec.More() {
				rows++
				if err := each(dec); err != nil {
					var typeErr *json.UnmarshalTypeError
					if errors.As(err, &typeErr) {
						malformed++
						continue
					}
					return status, rows, malformed, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return status, rows, malformed, err
			}
		default:
			if err := skipValue(dec, 0); err != nil {
				return status, rows, malformed, err
			}
		}
	}
	if _, err := dec.Token(); err != nil && !errors.Is(err, io.EOF) {
		return status, rows, malformed, err
	}
	return status, rows, malformed, nil
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("unexpected JSON token %v, want %q", tok, want)
	}
	return nil
}

// skipValue discards the next value without materialising it. depth is the
// number of already-opened containers to close.
func skipValue(dec *json.Decoder, depth int) error {
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
