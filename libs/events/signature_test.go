package events

import (
	"errors"
	"strings"
	"testing"
)

func TestSignAndVerifyRoundtrip(t *testing.T) {
	body := []byte(`{"id":"DET-1","confidence":95}`)
	sig := SignPayload("s3cret", body)

	if !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("signature should name its algorithm, got %q", sig)
	}
	if strings.Contains(sig, "s3cret") {
		t.Fatal("signature must not contain the secret")
	}
	if err := VerifyPayload("s3cret", sig, body); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
}

// TestVerifyRejectsTamperedBody is the property the old shared-secret header
// did not have: a receiver can tell that the payload it holds is the payload
// that was signed.
func TestVerifyRejectsTamperedBody(t *testing.T) {
	body := []byte(`{"id":"DET-1","confidence":10,"client_mac":"aa:bb:cc:dd:ee:01"}`)
	sig := SignPayload("s3cret", body)

	tampered := []byte(`{"id":"DET-1","confidence":99,"client_mac":"aa:bb:cc:dd:ee:01"}`)
	if err := VerifyPayload("s3cret", sig, tampered); err == nil {
		t.Fatal("raised confidence should fail verification")
	}

	retargeted := []byte(`{"id":"DET-1","confidence":10,"client_mac":"00:00:00:00:00:01"}`)
	if err := VerifyPayload("s3cret", sig, retargeted); err == nil {
		t.Fatal("rewritten client_mac should fail verification")
	}
}

func TestVerifyRejectsWrongSecret(t *testing.T) {
	body := []byte(`{}`)
	if err := VerifyPayload("other", SignPayload("s3cret", body), body); err == nil {
		t.Fatal("wrong secret should fail verification")
	}
}

func TestVerifyErrorCases(t *testing.T) {
	body := []byte(`{}`)
	if err := VerifyPayload("s", "", body); !errors.Is(err, ErrNoSignature) {
		t.Errorf("empty header should report ErrNoSignature, got %v", err)
	}
	if err := VerifyPayload("s", "   ", body); !errors.Is(err, ErrNoSignature) {
		t.Errorf("blank header should report ErrNoSignature, got %v", err)
	}
	if err := VerifyPayload("s", "md5=abcd", body); err == nil {
		t.Error("unknown scheme should be rejected")
	}
	if err := VerifyPayload("s", "sha256=nothex", body); err == nil {
		t.Error("non-hex digest should be rejected")
	}
	if err := VerifyPayload("s", "sha256=", body); err == nil {
		t.Error("empty digest should be rejected")
	}
}
