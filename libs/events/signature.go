package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SignatureHeader carries the HMAC of a webhook body.
//
// Before step 124 the detection-engine sent the raw shared secret in an
// `X-Webhook-Secret` header. That is not a signature: the secret travelled
// in plaintext on every request (so it landed in the receiver's access logs,
// and any receiver could replay it), and because the body was never covered,
// anything on the path could raise `confidence`/`severity` or rewrite
// `client_mac` to the router and trigger an auto-block. This header replaces
// it with an HMAC over the exact bytes that were sent.
const SignatureHeader = "X-Webhook-Signature"

// signaturePrefix namespaces the algorithm so the scheme can be rotated
// without guessing how to parse an old value.
const signaturePrefix = "sha256="

// ErrNoSignature means the request carried no signature header at all.
var ErrNoSignature = errors.New("missing webhook signature")

// SignPayload returns the value for SignatureHeader over body.
func SignPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// VerifyPayload checks a SignatureHeader value against body using a
// constant-time comparison. It returns an error describing the failure so the
// receiver can log WHY a delivery was rejected — silently dropping a
// mis-signed enforcement request is indistinguishable from the sender being
// down, which is exactly the kind of failure that hides for months.
func VerifyPayload(secret, header string, body []byte) error {
	if strings.TrimSpace(header) == "" {
		return ErrNoSignature
	}
	if !strings.HasPrefix(header, signaturePrefix) {
		return fmt.Errorf("unsupported signature scheme")
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, signaturePrefix))
	if err != nil {
		return fmt.Errorf("malformed signature: %w", err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
