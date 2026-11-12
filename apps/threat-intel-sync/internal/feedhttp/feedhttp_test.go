package feedhttp

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestLimitBody(t *testing.T) {
	exact, err := io.ReadAll(LimitBody(strings.NewReader("12345"), 5))
	if err != nil || string(exact) != "12345" {
		t.Errorf("a body of exactly the cap must read cleanly: %q %v", exact, err)
	}
	over, err := io.ReadAll(LimitBody(strings.NewReader("123456"), 5))
	if !errors.Is(err, ErrTooLarge) || string(over) != "12345" {
		t.Errorf("over the cap: %q %v", over, err)
	}
	if _, err := io.ReadAll(LimitBody(strings.NewReader(strings.Repeat("x", 100)), 0)); err != nil {
		t.Errorf("0 means the default cap: %v", err)
	}
}

func TestLines(t *testing.T) {
	var got []string
	err := Lines(strings.NewReader("a\r\nb\n\nc"), func(l string) error { got = append(got, l); return nil })
	if err != nil || strings.Join(got, "|") != "a|b||c" {
		t.Errorf("got %q, %v", got, err)
	}

	got = nil
	err = Lines(LimitBody(strings.NewReader("203.0.113.20\n203.0.113.10\n"), 24), func(l string) error {
		got = append(got, l)
		return nil
	})
	if !errors.Is(err, ErrTooLarge) || len(got) != 1 {
		t.Errorf("a truncated last line must be discarded: %q, %v", got, err)
	}

	if err := Lines(strings.NewReader(strings.Repeat("x", MaxLineLen*3)), func(string) error { return nil }); err == nil {
		t.Error("an over-long line must be an error")
	}
	stop := errors.New("stop")
	if err := Lines(strings.NewReader("a\nb\n"), func(string) error { return stop }); !errors.Is(err, stop) {
		t.Errorf("callback error not returned: %v", err)
	}
}

func TestStatusErrorIsLogSafe(t *testing.T) {
	resp := &http.Response{StatusCode: 500, Body: io.NopCloser(strings.NewReader("boom\n{\"level\":\"INFO\",\"msg\":\"forged\"}" + strings.Repeat("x", 5000)))}
	err := StatusError("Feed", resp)
	if strings.Contains(err.Error(), "\n") || len(err.Error()) > 260 {
		t.Errorf("error not sanitised: %q", err)
	}
	resp = &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader(""))}
	if !strings.Contains(StatusError("Feed", resp).Error(), "credentials") {
		t.Error("401 should point at the credentials")
	}
}
