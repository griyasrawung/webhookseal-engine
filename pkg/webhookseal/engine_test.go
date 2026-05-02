package webhookseal

import (
	"context"
	"errors"
	"testing"

	internalhmac "github.com/griyasrawung/webhookseal-engine/internal/hmac"
)

func TestVerifyGitHubValid(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	payload := []byte(`{"zen":"Keep it logically awesome."}`)
	secret := "github-webhook-secret"
	sig := mustSignature(t, "hmac-sha256", "hex", secret, payload)
	headers := map[string]string{"X-Hub-Signature-256": "sha256=" + sig}

	if err := engine.Verify(context.Background(), "github", payload, headers, secret); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	result, err := engine.VerifyFull(context.Background(), "github", payload, headers, secret)
	if err != nil {
		t.Fatalf("VerifyFull failed: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid result")
	}
	if result.Provider != "github" {
		t.Fatalf("expected provider github, got %q", result.Provider)
	}
	if result.Algorithm != "hmac-sha256" {
		t.Fatalf("expected hmac-sha256, got %q", result.Algorithm)
	}
}

func TestVerifyUnknownProvider(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = engine.VerifyFull(context.Background(), "unknown", []byte("{}"), nil, "secret")
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("expected ErrUnknownProvider, got %v", err)
	}
}

func TestVerifyPayloadTooLarge(t *testing.T) {
	engine, err := New(WithMaxPayloadSize(4))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = engine.VerifyFull(context.Background(), "github", []byte("12345"), nil, "secret")
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected ErrPayloadTooLarge, got %v", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	payload := []byte(`{"action":"opened"}`)
	sig := mustSignature(t, "hmac-sha256", "hex", "correct-secret", payload)
	headers := map[string]string{"X-Hub-Signature-256": "sha256=" + sig}

	_, err = engine.VerifyFull(context.Background(), "github", payload, headers, "wrong-secret")
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestVerifyMissingSignature(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	_, err = engine.VerifyFull(context.Background(), "github", []byte("{}"), map[string]string{}, "secret")
	if !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("expected ErrMissingSignature, got %v", err)
	}
}

func TestVerifyTwilioRequiresURL(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	secret := "twilio-auth-token"
	url := "https://example.com/twilio"
	params := map[string]string{"CallSid": "CA123", "Digits": "1234"}
	signedPayload := []byte("https://example.com/twilioCallSidCA123Digits1234")
	sig := mustSignature(t, "hmac-sha1", "base64", secret, signedPayload)
	headers := map[string]string{"X-Twilio-Signature": sig}

	_, err = engine.VerifyFull(context.Background(), "twilio", nil, headers, secret, WithParams(params))
	if !errors.Is(err, ErrBadFormat) {
		t.Fatalf("expected ErrBadFormat without URL, got %v", err)
	}

	result, err := engine.VerifyFull(context.Background(), "twilio", nil, headers, secret, WithURL(url), WithParams(params))
	if err != nil {
		t.Fatalf("expected valid Twilio verification with URL, got %v", err)
	}
	if !result.Valid || result.Provider != "twilio" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func mustSignature(t *testing.T, algorithm, encoding, secret string, payload []byte) string {
	t.Helper()
	raw, err := internalhmac.Compute(algorithm, []byte(secret), payload)
	if err != nil {
		t.Fatalf("Compute failed: %v", err)
	}
	encoded, err := internalhmac.Encode(raw, encoding)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	return encoded
}
