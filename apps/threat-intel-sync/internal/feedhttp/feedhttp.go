// Package feedhttp holds what every feed client needs to read a third-party
// response safely: a hard cap on the body size and a log-safe error body.
//
// Response bodies used to be decoded with no limit at all, so a broken or
// hostile feed answering 200 and streaming rows forever grew the heap until
// the pod was OOM-killed, and the restart loop took every export down.
package feedhttp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/migel9090/netSoldier/libs/indicator"
)

// DefaultMaxBodyBytes is the per-response cap when none is configured. The
// largest legitimate response, a week of ThreatFox, is a few megabytes; the
// cap leaves an order of magnitude of headroom while keeping a runaway body
// far below the pod's memory limit.
const DefaultMaxBodyBytes int64 = 32 << 20

// ErrTooLarge reports a response body that exceeded its cap. Whatever was
// decoded before the cap is still returned by the clients (see the partial
// result policy in cmd/threat-intel-sync), but the fetch counts as failed.
var ErrTooLarge = errors.New("response body exceeds size limit")

// LimitBody returns a reader that yields at most max bytes of r and then
// fails with ErrTooLarge if r has more. Unlike io.LimitReader it does not
// turn a truncated body into a clean EOF, which a decoder could mistake for
// a complete document.
func LimitBody(r io.Reader, max int64) io.Reader {
	if max <= 0 {
		max = DefaultMaxBodyBytes
	}
	return &limitedBody{r: r, remaining: max, max: max}
}

type limitedBody struct {
	r         io.Reader
	remaining int64
	max       int64
}

func (l *limitedBody) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		var probe [1]byte
		for i := 0; i < 8; i++ {
			n, err := l.r.Read(probe[:])
			if n > 0 {
				return 0, fmt.Errorf("%w (%d bytes)", ErrTooLarge, l.max)
			}
			if err != nil {
				return 0, err
			}
		}
		return 0, io.ErrNoProgress
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.r.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// MaxLineLen bounds one line of a line-oriented feed (Spamhaus DROP, the
// Feodo CSV); real lines are under 200 bytes.
const MaxLineLen = 4096

// Lines calls fn for every complete line of r, without its line ending.
// A final line without a newline is passed on a clean EOF. On any other
// read error — notably ErrTooLarge — the partial line is discarded, never
// passed: a truncated "203.0.113.10" is the different, valid address
// "203.0.113.1". A line longer than MaxLineLen is an error.
func Lines(r io.Reader, fn func(line string) error) error {
	// ReadSlice, not ReadLine: ReadLine hands back a partial line with a nil
	// error when the underlying read fails, which is exactly the case that
	// must not reach fn.
	br := bufio.NewReaderSize(r, MaxLineLen)
	var b []byte
	for {
		chunk, err := br.ReadSlice('\n')
		b = append(b, chunk...)
		if len(b) > MaxLineLen+2 {
			return fmt.Errorf("line longer than %d bytes", MaxLineLen)
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(b) > 0 {
				return fn(trimEOL(b))
			}
			return nil
		case err != nil:
			return err
		}
		if err := fn(trimEOL(b)); err != nil {
			return err
		}
		b = b[:0]
	}
}

func trimEOL(b []byte) string {
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		n--
		if n > 0 && b[n-1] == '\r' {
			n--
		}
	}
	return string(b[:n])
}

// StatusError builds the error for a non-200 response, quoting at most a
// short, control-character-free excerpt of the body so a hostile error page
// cannot forge log lines.
func StatusError(feed string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := indicator.Text(string(body), 200)
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%s %d (credentials rejected — check the API key): %s", feed, resp.StatusCode, msg)
	default:
		return fmt.Errorf("%s %d: %s", feed, resp.StatusCode, msg)
	}
}
