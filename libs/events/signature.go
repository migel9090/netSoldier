package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader carries the HMAC of a webhook request.
//
// The value is "t=<unix seconds>,v1=<hex>" where
//
//	v1 = HMAC-SHA256(secret, "<t>." + body)
//
// Covering the body proves the payload was not altered in transit (raising
// confidence, or pointing an action at the router). Covering the timestamp is
// what stops a captured request from being valid forever: the receiver
// rejects a t outside its tolerance, so a recording is only replayable inside
// that window, and inside the window the receiver's idempotency on event id
// makes a replay a no-op. The body-only scheme this replaces could be
// replayed months later and created a new action every time.
const SignatureHeader = "X-Webhook-Signature"

// DefaultSignatureTolerance is how far a signature's timestamp may be from
// the receiver's clock, in either direction.
const DefaultSignatureTolerance = 5 * time.Minute

// legacyPrefix is the body-only scheme of schema 1.x. Recognised only to give
// a precise error: accepting it would reopen the replay hole.
const legacyPrefix = "sha256="

// timestampRe accepts the canonical decimal form only, so the bytes the MAC
// covers are exactly the bytes the sender formatted.
var timestampRe = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

var (
	// ErrNoSignature means the request carried no signature header at all.
	ErrNoSignature = errors.New("missing webhook signature")
	// ErrMalformedSignature means the header could not be parsed.
	ErrMalformedSignature = errors.New("malformed webhook signature")
	// ErrStaleSignature means the MAC is valid but its timestamp is outside
	// the tolerance window: a replay, or a clock that has drifted.
	ErrStaleSignature = errors.New("webhook signature timestamp outside tolerance")
	// ErrSignatureMismatch means no MAC in the header matches the request.
	ErrSignatureMismatch = errors.New("webhook signature mismatch")
)

// SignPayload returns the SignatureHeader value for body, timestamped now.
// Sign at send time, and again for every retry: a signature computed once
// and reused goes stale on the receiver after the tolerance window.
func SignPayload(secret string, body []byte) string {
	return SignPayloadAt(secret, time.Now(), body)
}

// SignPayloadAt returns the SignatureHeader value for body with timestamp at.
func SignPayloadAt(secret string, at time.Time, body []byte) string {
	ts := strconv.FormatInt(at.Unix(), 10)
	return "t=" + ts + ",v1=" + hex.EncodeToString(signatureMAC(secret, ts, body))
}

func signatureMAC(secret, ts string, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return mac.Sum(nil)
}

// SignatureVerifier checks SignatureHeader values.
type SignatureVerifier struct {
	Secret string
	// Tolerance is the allowed |now - t|; zero or negative means
	// DefaultSignatureTolerance.
	Tolerance time.Duration
	// Now is the receiver's clock; nil means time.Now. Tests inject one.
	Now func() time.Time
}

// VerifyPayload checks header against body with the default tolerance and
// the real clock.
func VerifyPayload(secret, header string, body []byte) error {
	return (&SignatureVerifier{Secret: secret}).Verify(header, body)
}

// Verify checks a SignatureHeader value against body. The MAC comparison is
// constant-time. The returned error wraps one of the Err* sentinels and says
// WHY a delivery was rejected — silently dropping a mis-signed enforcement
// request is indistinguishable from the sender being down, which is exactly
// the kind of failure that hides for months.
//
// The MAC is checked before the timestamp, so a stale error means the
// request was genuinely signed with this secret: a replay or clock skew,
// not a forgery.
func (v *SignatureVerifier) Verify(header string, body []byte) error {
	if v.Secret == "" {
		return errors.New("signature verifier has no secret configured")
	}
	header = strings.TrimSpace(header)
	if header == "" {
		return ErrNoSignature
	}
	if strings.HasPrefix(header, legacyPrefix) {
		return fmt.Errorf("%w: the body-only %q scheme is no longer accepted; "+
			"sign with t=<unix>,v1=<hmac>", ErrMalformedSignature, legacyPrefix)
	}

	var ts string
	var macs [][]byte
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return fmt.Errorf("%w: element %q is not key=value", ErrMalformedSignature, part)
		}
		switch key {
		case "t":
			if ts != "" {
				return fmt.Errorf("%w: more than one timestamp", ErrMalformedSignature)
			}
			if !timestampRe.MatchString(value) {
				return fmt.Errorf("%w: timestamp %q is not unix seconds", ErrMalformedSignature, value)
			}
			ts = value
		case "v1":
			mac, err := hex.DecodeString(value)
			if err != nil || len(mac) != sha256.Size {
				return fmt.Errorf("%w: v1 is not a hex HMAC-SHA256", ErrMalformedSignature)
			}
			macs = append(macs, mac)
		default:
			// Unknown schemes are skipped so a sender can add a v2 MAC
			// alongside v1 during a rotation without breaking this receiver.
		}
	}
	if ts == "" {
		return fmt.Errorf("%w: no timestamp", ErrMalformedSignature)
	}
	if len(macs) == 0 {
		return fmt.Errorf("%w: no v1 signature", ErrMalformedSignature)
	}

	want := signatureMAC(v.Secret, ts, body)
	matched := false
	for _, mac := range macs {
		if hmac.Equal(mac, want) {
			matched = true
		}
	}
	if !matched {
		return ErrSignatureMismatch
	}

	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: timestamp %q: %v", ErrMalformedSignature, ts, err)
	}
	skew := v.now().Sub(time.Unix(sec, 0))
	if skew < 0 {
		skew = -skew
	}
	if tol := v.tolerance(); skew > tol {
		return fmt.Errorf("%w: signed %s from now, tolerance %s",
			ErrStaleSignature, skew.Round(time.Second), tol)
	}
	return nil
}

func (v *SignatureVerifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *SignatureVerifier) tolerance() time.Duration {
	if v.Tolerance > 0 {
		return v.Tolerance
	}
	return DefaultSignatureTolerance
}
