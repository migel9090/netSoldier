package events

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var signedAt = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

// verifierAt returns a verifier whose clock reads now.
func verifierAt(secret string, now time.Time) *SignatureVerifier {
	return &SignatureVerifier{Secret: secret, Now: func() time.Time { return now }}
}

func TestSignAndVerifyRoundtrip(t *testing.T) {
	body := []byte(`{"id":"DET-a-1","confidence":95}`)
	sig := SignPayloadAt("s3cret", signedAt, body)

	if !regexp.MustCompile(`^t=[0-9]+,v1=[0-9a-f]{64}$`).MatchString(sig) {
		t.Fatalf("header should be t=<unix>,v1=<hex>, got %q", sig)
	}
	if !strings.HasPrefix(sig, "t="+strconv.FormatInt(signedAt.Unix(), 10)+",") {
		t.Fatalf("header should carry the signing time, got %q", sig)
	}
	if strings.Contains(sig, "s3cret") {
		t.Fatal("signature must not contain the secret")
	}
	if err := verifierAt("s3cret", signedAt).Verify(sig, body); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
}

// TestSignatureCoversTimestampAndBody pins the exact construction the
// contract specifies, so the switch adapter and any other receiver can
// implement it independently.
func TestSignatureCoversTimestampAndBody(t *testing.T) {
	body := []byte(`{"x":1}`)
	mac := hmac.New(sha256.New, []byte("k"))
	mac.Write([]byte("1789000000." + string(body)))
	want := "t=1789000000,v1=" + hex.EncodeToString(mac.Sum(nil))
	if got := SignPayloadAt("k", time.Unix(1789000000, 0), body); got != want {
		t.Fatalf("SignPayloadAt = %q, want %q", got, want)
	}
}

func TestSignPayloadUsesTheClock(t *testing.T) {
	body := []byte(`{}`)
	if err := VerifyPayload("s", SignPayload("s", body), body); err != nil {
		t.Fatalf("a fresh signature must verify against the real clock: %v", err)
	}
}

// TestVerifyRejectsTamperedBody: a receiver can tell that the payload it
// holds is the payload that was signed.
func TestVerifyRejectsTamperedBody(t *testing.T) {
	body := []byte(`{"id":"DET-a-1","confidence":10,"client_mac":"aa:bb:cc:dd:ee:01"}`)
	sig := SignPayloadAt("s3cret", signedAt, body)
	v := verifierAt("s3cret", signedAt)

	tampered := []byte(`{"id":"DET-a-1","confidence":99,"client_mac":"aa:bb:cc:dd:ee:01"}`)
	if err := v.Verify(sig, tampered); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("raised confidence should fail verification, got %v", err)
	}
	retargeted := []byte(`{"id":"DET-a-1","confidence":10,"client_mac":"00:00:00:00:00:01"}`)
	if err := v.Verify(sig, retargeted); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("rewritten client_mac should fail verification, got %v", err)
	}
}

// TestVerifyRejectsRewrittenTimestamp: the timestamp is inside the MAC, so a
// captured request cannot be refreshed by editing t.
func TestVerifyRejectsRewrittenTimestamp(t *testing.T) {
	body := []byte(`{"id":"DET-a-1"}`)
	old := signedAt.Add(-90 * 24 * time.Hour)
	sig := SignPayloadAt("s3cret", old, body)
	_, mac, _ := strings.Cut(sig, ",")
	refreshed := "t=" + strconv.FormatInt(signedAt.Unix(), 10) + "," + mac

	if err := verifierAt("s3cret", signedAt).Verify(refreshed, body); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("a re-dated signature must not verify, got %v", err)
	}
}

// TestVerifyRejectsReplayedOldSignature is the replay the body-only scheme
// allowed: the same signed event, delivered again 90 days later, verified and
// created a new enforcement action every time.
func TestVerifyRejectsReplayedOldSignature(t *testing.T) {
	body := []byte(`{"id":"DET-a-7","severity":"critical","confidence":95}`)
	sig := SignPayloadAt("whsec", signedAt.Add(-90*24*time.Hour), body)

	err := verifierAt("whsec", signedAt).Verify(sig, body)
	if !errors.Is(err, ErrStaleSignature) {
		t.Fatalf("a 90-day-old signature must be rejected as stale, got %v", err)
	}
}

func TestVerifyToleranceWindow(t *testing.T) {
	body := []byte(`{}`)
	tests := []struct {
		name      string
		skew      time.Duration
		tolerance time.Duration
		wantErr   error
	}{
		{"just signed", 0, 0, nil},
		{"four minutes old", -4 * time.Minute, 0, nil},
		{"exactly at the default edge", -DefaultSignatureTolerance, 0, nil},
		{"six minutes old", -6 * time.Minute, 0, ErrStaleSignature},
		{"six minutes in the future", 6 * time.Minute, 0, ErrStaleSignature},
		{"four minutes in the future", 4 * time.Minute, 0, nil},
		{"configured tighter", -90 * time.Second, time.Minute, ErrStaleSignature},
		{"configured wider", -9 * time.Minute, 10 * time.Minute, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := SignPayloadAt("s", signedAt.Add(tt.skew), body)
			v := verifierAt("s", signedAt)
			v.Tolerance = tt.tolerance
			err := v.Verify(sig, body)
			if tt.wantErr == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	body := []byte(`{}`)
	err := verifierAt("other", signedAt).Verify(SignPayloadAt("s3cret", signedAt, body), body)
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("wrong secret should fail verification, got %v", err)
	}
}

// TestVerifyRejectsLegacyScheme: a 1.x sender must fail loudly, not be
// accepted on a scheme that has no freshness.
func TestVerifyRejectsLegacyScheme(t *testing.T) {
	body := []byte(`{}`)
	mac := hmac.New(sha256.New, []byte("s"))
	mac.Write(body)
	legacy := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	err := verifierAt("s", signedAt).Verify(legacy, body)
	if !errors.Is(err, ErrMalformedSignature) || !strings.Contains(err.Error(), "no longer accepted") {
		t.Fatalf("legacy body-only header should be refused with an explanation, got %v", err)
	}
}

func TestVerifyErrorCases(t *testing.T) {
	body := []byte(`{}`)
	good := SignPayloadAt("s", signedAt, body)
	_, v1, _ := strings.Cut(good, ",")
	ts := strconv.FormatInt(signedAt.Unix(), 10)
	v := verifierAt("s", signedAt)

	for _, h := range []string{"", "   "} {
		if err := v.Verify(h, body); !errors.Is(err, ErrNoSignature) {
			t.Errorf("header %q should report ErrNoSignature, got %v", h, err)
		}
	}
	for _, h := range []string{
		"md5=abcd",
		v1,                       // no timestamp
		"t=" + ts,                // no MAC
		"t=" + ts + ",v1=nothex", // not hex
		"t=" + ts + ",v1=abcd",   // too short
		"t=abc," + v1,            // not a number
		"t=0" + ts + "," + v1,    // non-canonical number
		"t=-5," + v1,             // negative
		"t=" + ts + ",t=" + ts + "," + v1,
		"t=" + ts + ",garbage," + v1,
		"t=99999999999999999999," + v1,
	} {
		if err := v.Verify(h, body); !errors.Is(err, ErrMalformedSignature) {
			t.Errorf("header %q should report ErrMalformedSignature, got %v", h, err)
		}
	}
}

// TestVerifyAcceptsRotation: a sender may attach MACs under two secrets, or
// a future scheme alongside v1, while receivers are being rolled.
func TestVerifyAcceptsRotation(t *testing.T) {
	body := []byte(`{}`)
	ts := strconv.FormatInt(signedAt.Unix(), 10)
	_, oldMAC, _ := strings.Cut(SignPayloadAt("old", signedAt, body), ",")
	_, newMAC, _ := strings.Cut(SignPayloadAt("new", signedAt, body), ",")
	header := "t=" + ts + ", " + oldMAC + ", " + newMAC + ", v9=whatever"

	for _, secret := range []string{"old", "new"} {
		if err := verifierAt(secret, signedAt).Verify(header, body); err != nil {
			t.Errorf("secret %q should verify: %v", secret, err)
		}
	}
	if err := verifierAt("neither", signedAt).Verify(header, body); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("an unrelated secret must not verify, got %v", err)
	}
}

func TestVerifierWithoutSecretRefuses(t *testing.T) {
	body := []byte(`{}`)
	if err := (&SignatureVerifier{}).Verify(SignPayloadAt("", signedAt, body), body); err == nil {
		t.Fatal("a verifier with no secret must refuse rather than accept an empty-key MAC")
	}
}
