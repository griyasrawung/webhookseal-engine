package webhookseal

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestStripeMultipleSignatures(t *testing.T) {
	verifyStripeMultipleSignatures(t)
}

func TestTwilioURLTampering(t *testing.T) {
	verifyTwilioURLTampering(t)
}

func TestProviderEdgeCases(t *testing.T) {
	t.Run("StripeMultipleSignatures", verifyStripeMultipleSignatures)
	t.Run("StripeExpiredTimestamp", verifyStripeExpiredTimestamp)
	t.Run("GitHubMissingSHA256Prefix", verifyGitHubMissingSHA256Prefix)
	t.Run("ShopifyWhitespaceChangedBody", verifyShopifyWhitespaceChangedBody)
	t.Run("SlackMissingTimestamp", verifySlackMissingTimestamp)
	t.Run("SlackSignedPayloadRequiresV0Prefix", verifySlackSignedPayloadRequiresV0Prefix)
	t.Run("TwilioURLTampering", verifyTwilioURLTampering)
	t.Run("TwilioParamsSortedLexicographically", verifyTwilioParamsSortedLexicographically)
}

func verifyStripeMultipleSignatures(t *testing.T) {
	t.Helper()

	now := time.Unix(1714600000, 0)
	engine, err := New(WithClock(fixedClock{t: now}))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := []byte(`{"id":"evt_rotation","object":"event"}`)
	secret := "whsec_edge_rotation"
	signedPayload := []byte(fmt.Sprintf("%d.%s", now.Unix(), body))
	validSig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)
	headers := map[string]string{
		"Stripe-Signature": fmt.Sprintf("t=%d,v1=0000000000000000000000000000000000000000000000000000000000000000,v1=%s", now.Unix(), validSig),
	}

	result, err := engine.VerifyFull(context.Background(), "stripe", body, headers, secret)
	if err != nil {
		t.Fatalf("VerifyFull failed with valid second Stripe signature: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid result, got %+v", result)
	}
	if result.SignatureID != "signature" {
		t.Fatalf("expected signature id %q, got %q", "signature", result.SignatureID)
	}
}

func verifyStripeExpiredTimestamp(t *testing.T) {
	t.Helper()

	now := time.Unix(1714600000, 0)
	expired := now.Add(-10 * time.Minute)
	engine, err := New(WithClock(fixedClock{t: now}))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := []byte(`{"id":"evt_expired","object":"event"}`)
	secret := "whsec_edge_expired"
	signedPayload := []byte(fmt.Sprintf("%d.%s", expired.Unix(), body))
	sig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)
	headers := map[string]string{"Stripe-Signature": fmt.Sprintf("t=%d,v1=%s", expired.Unix(), sig)}

	_, err = engine.VerifyFull(context.Background(), "stripe", body, headers, secret)
	if !errors.Is(err, ErrTimestampExpired) {
		t.Fatalf("expected ErrTimestampExpired, got %v", err)
	}
}

func verifyGitHubMissingSHA256Prefix(t *testing.T) {
	t.Helper()

	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := []byte(`{"action":"opened"}`)
	secret := "github-edge-secret"
	sig := mustSignature(t, "hmac-sha256", "hex", secret, body)
	headers := map[string]string{"X-Hub-Signature-256": sig}

	if err := engine.Verify(context.Background(), "github", body, headers, secret); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("expected ErrBadFormat, got %v", err)
	}
}

func verifyShopifyWhitespaceChangedBody(t *testing.T) {
	t.Helper()

	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	originalBody := []byte(`{"order_id":123,"total":"10.00"}`)
	changedBody := []byte(`{"order_id": 123, "total": "10.00"}`)
	secret := "shopify-edge-secret"
	sig := mustSignature(t, "hmac-sha256", "base64", secret, originalBody)
	headers := map[string]string{"X-Shopify-Hmac-Sha256": sig}

	_, err = engine.VerifyFull(context.Background(), "shopify", changedBody, headers, secret)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func verifySlackMissingTimestamp(t *testing.T) {
	t.Helper()

	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := []byte(`token=edge&team_id=T123`)
	secret := "slack-edge-secret"
	sig := mustSignature(t, "hmac-sha256", "hex", secret, []byte("v0:1714600000:"+string(body)))
	headers := map[string]string{"X-Slack-Signature": "v0=" + sig}

	_, err = engine.VerifyFull(context.Background(), "slack", body, headers, secret)
	if !errors.Is(err, ErrMissingTimestamp) {
		t.Fatalf("expected ErrMissingTimestamp, got %v", err)
	}
}

func verifySlackSignedPayloadRequiresV0Prefix(t *testing.T) {
	t.Helper()

	now := time.Unix(1714600000, 0)
	engine, err := New(WithClock(fixedClock{t: now}))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	body := []byte(`token=edge&team_id=T123`)
	secret := "slack-edge-secret"
	wrongPayload := []byte(fmt.Sprintf("%d:%s", now.Unix(), body))
	sig := mustSignature(t, "hmac-sha256", "hex", secret, wrongPayload)
	headers := map[string]string{
		"X-Slack-Signature":         "v0=" + sig,
		"X-Slack-Request-Timestamp": fmt.Sprintf("%d", now.Unix()),
	}

	_, err = engine.VerifyFull(context.Background(), "slack", body, headers, secret)
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func verifyTwilioURLTampering(t *testing.T) {
	t.Helper()

	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	secret := "twilio-edge-token"
	params := map[string]string{"CallSid": "CA123", "Digits": "1234"}
	originalURL := "https://example.com/twilio"
	tamperedURL := "https://evil.example.com/twilio"
	signedPayload := []byte(originalURL + "CallSidCA123Digits1234")
	sig := mustSignature(t, "hmac-sha1", "base64", secret, signedPayload)
	headers := map[string]string{"X-Twilio-Signature": sig}

	_, err = engine.VerifyFull(context.Background(), "twilio", nil, headers, secret, WithURL(tamperedURL), WithParams(params))
	if !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func verifyTwilioParamsSortedLexicographically(t *testing.T) {
	t.Helper()

	engine, err := New()
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	secret := "twilio-edge-token"
	url := "https://example.com/twilio"
	params := map[string]string{"B": "2", "A": "1"}
	signedPayload := []byte(url + "A1B2")
	sig := mustSignature(t, "hmac-sha1", "base64", secret, signedPayload)
	headers := map[string]string{"X-Twilio-Signature": sig}

	result, err := engine.VerifyFull(context.Background(), "twilio", nil, headers, secret, WithURL(url), WithParams(params))
	if err != nil {
		t.Fatalf("VerifyFull failed with lexicographically sorted Twilio params: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected valid result, got %+v", result)
	}
}
