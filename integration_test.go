package webhookseal

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/webhookseal/webhookseal-engine/internal/replay"
)

// TestNewLoadsAllProviders verifies that New() successfully loads all embedded provider specs.
func TestNewLoadsAllProviders(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	// Verify that at least the core providers are loaded
	expectedProviders := []string{"github", "stripe", "slack", "shopify", "twilio"}
	for _, provider := range expectedProviders {
		if _, ok := engine.specs[provider]; !ok {
			t.Errorf("expected provider %q to be loaded, but it was not found", provider)
		}
	}

	if len(engine.specs) < len(expectedProviders) {
		t.Errorf("expected at least %d providers, got %d", len(expectedProviders), len(engine.specs))
	}
}

// TestVerifyErrorOnlyAPI verifies that Verify() returns only errors without metadata.
func TestVerifyErrorOnlyAPI(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	payload := []byte(`{"action":"opened"}`)
	secret := "test-secret"
	sig := mustSignature(t, "hmac-sha256", "hex", secret, payload)
	headers := map[string]string{"X-Hub-Signature-256": "sha256=" + sig}

	// Valid signature should return nil error
	err = engine.Verify(context.Background(), "github", payload, headers, secret)
	if err != nil {
		t.Errorf("Verify() with valid signature failed: %v", err)
	}

	// Invalid signature should return error
	badHeaders := map[string]string{"X-Hub-Signature-256": "sha256=deadbeef"}
	err = engine.Verify(context.Background(), "github", payload, badHeaders, secret)
	if err == nil {
		t.Error("Verify() with invalid signature should return error")
	}
	if !errors.Is(err, ErrBadSignature) {
		t.Errorf("expected ErrBadSignature, got %v", err)
	}
}

// TestVerifyFullReturnsMetadata verifies that VerifyFull() returns structured Result with metadata.
func TestVerifyFullReturnsMetadata(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	payload := []byte(`{"zen":"Keep it logically awesome."}`)
	secret := "github-webhook-secret"
	sig := mustSignature(t, "hmac-sha256", "hex", secret, payload)
	headers := map[string]string{"X-Hub-Signature-256": "sha256=" + sig}

	result, err := engine.VerifyFull(context.Background(), "github", payload, headers, secret)
	if err != nil {
		t.Fatalf("VerifyFull() failed: %v", err)
	}

	// Verify metadata fields
	if !result.Valid {
		t.Error("expected Valid=true")
	}
	if result.Provider != "github" {
		t.Errorf("expected Provider=github, got %q", result.Provider)
	}
	if result.Algorithm != "hmac-sha256" {
		t.Errorf("expected Algorithm=hmac-sha256, got %q", result.Algorithm)
	}
	if result.SignatureID != "signature" {
		t.Errorf("expected SignatureID=signature, got %q", result.SignatureID)
	}
	if result.Reason != "" {
		t.Errorf("expected empty Reason for valid signature, got %q", result.Reason)
	}

	// Test invalid signature returns metadata with Valid=false
	badHeaders := map[string]string{"X-Hub-Signature-256": "sha256=deadbeef"}
	result, err = engine.VerifyFull(context.Background(), "github", payload, badHeaders, secret)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
	if result.Valid {
		t.Error("expected Valid=false for invalid signature")
	}
	if result.Provider != "github" {
		t.Errorf("expected Provider=github even on failure, got %q", result.Provider)
	}
	if result.Reason == "" {
		t.Error("expected non-empty Reason for invalid signature")
	}
}

// TestWithMaxPayloadSizeRejectsLargePayload verifies that WithMaxPayloadSize option rejects oversized payloads.
func TestWithMaxPayloadSizeRejectsLargePayload(t *testing.T) {
	maxSize := int64(100)
	engine, err := New(WithMaxPayloadSize(maxSize))
	if err != nil {
		t.Fatalf("New() with WithMaxPayloadSize failed: %v", err)
	}

	// Payload within limit should work
	smallPayload := make([]byte, maxSize)
	for i := range smallPayload {
		smallPayload[i] = 'a'
	}
	secret := "test-secret"
	sig := mustSignature(t, "hmac-sha256", "hex", secret, smallPayload)
	headers := map[string]string{"X-Hub-Signature-256": "sha256=" + sig}

	result, err := engine.VerifyFull(context.Background(), "github", smallPayload, headers, secret)
	if err != nil {
		t.Errorf("VerifyFull() with payload at max size failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid result for payload at max size")
	}

	// Payload exceeding limit should fail
	largePayload := make([]byte, maxSize+1)
	for i := range largePayload {
		largePayload[i] = 'b'
	}
	sigLarge := mustSignature(t, "hmac-sha256", "hex", secret, largePayload)
	headersLarge := map[string]string{"X-Hub-Signature-256": "sha256=" + sigLarge}

	result, err = engine.VerifyFull(context.Background(), "github", largePayload, headersLarge, secret)
	if err == nil {
		t.Fatal("expected error for payload exceeding max size")
	}
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("expected ErrPayloadTooLarge, got %v", err)
	}
	if result.Valid {
		t.Error("expected Valid=false for oversized payload")
	}
}

// TestWithReplayStoreDetectsReplay verifies that replay detection works when replay store is configured.
func TestWithReplayStoreDetectsReplay(t *testing.T) {
	store := replay.NewMemoryStore()
	fixedTime := time.Unix(1714600000, 0)
	engine, err := New(WithReplayStore(store), WithClock(fixedClock{t: fixedTime}), WithTolerance("stripe", 5*time.Minute))
	if err != nil {
		t.Fatalf("New() with WithReplayStore failed: %v", err)
	}

	timestamp := fixedTime.Unix()
	payload := []byte(`{"id":"evt_replay","object":"event"}`)
	secret := "whsec_replay_test"
	signedPayload := []byte(fmt.Sprintf("%d.%s", timestamp, payload))
	sig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)
	headers := map[string]string{"Stripe-Signature": fmt.Sprintf("t=%d,v1=%s", timestamp, sig)}
	replayID := "evt_unique_12345"

	// First verification should succeed
	result, err := engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(replayID))
	if err != nil {
		t.Fatalf("first VerifyFull() with replay ID failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected first verification to be valid")
	}
	if result.ReplayDetected {
		t.Error("expected ReplayDetected=false on first verification")
	}

	// Second verification with same replay ID should fail
	result, err = engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(replayID))
	if err == nil {
		t.Fatal("expected error on replay detection")
	}
	if !errors.Is(err, ErrReplayDetected) {
		t.Errorf("expected ErrReplayDetected, got %v", err)
	}
	if result.Valid {
		t.Error("expected Valid=false on replay detection")
	}
	if !result.ReplayDetected {
		t.Error("expected ReplayDetected=true on second verification")
	}

	// Different replay ID should succeed
	differentReplayID := "evt_unique_67890"
	result, err = engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(differentReplayID))
	if err != nil {
		t.Errorf("VerifyFull() with different replay ID failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected verification with different replay ID to be valid")
	}
}

// TestWithToleranceOverride verifies that WithTolerance overrides provider default timestamp window.
func TestVerifyFullMetadata(t *testing.T) {
	engine, err := New()
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	payload := []byte(`{"zen":"Keep it logically awesome."}`)
	secret := "github-webhook-secret"
	sig := mustSignature(t, "hmac-sha256", "hex", secret, payload)
	headers := map[string]string{"X-Hub-Signature-256": "sha256=" + sig}

	result, err := engine.VerifyFull(context.Background(), "github", payload, headers, secret)
	if err != nil {
		t.Fatalf("VerifyFull() failed: %v", err)
	}
	if !result.Valid {
		t.Fatal("expected valid result")
	}
	if result.Provider != "github" {
		t.Fatalf("expected provider github, got %q", result.Provider)
	}
	if result.Algorithm != "hmac-sha256" {
		t.Fatalf("expected algorithm hmac-sha256, got %q", result.Algorithm)
	}
	if result.SignatureID == "" {
		t.Fatal("expected non-empty SignatureID")
	}
	if result.Reason != "" {
		t.Fatalf("expected empty reason for valid verify, got %q", result.Reason)
	}
}

func TestReplayStoreIntegration(t *testing.T) {
	store := replay.NewMemoryStore()
	fixedTime := time.Unix(1714600000, 0)
	engine, err := New(WithReplayStore(store), WithClock(fixedClock{t: fixedTime}), WithTolerance("stripe", 5*time.Minute))
	if err != nil {
		t.Fatalf("New() with replay store failed: %v", err)
	}

	timestamp := fixedTime.Unix()
	payload := []byte(`{"id":"evt_replay","object":"event"}`)
	secret := "whsec_replay_test"
	signedPayload := []byte(fmt.Sprintf("%d.%s", timestamp, payload))
	sig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)
	headers := map[string]string{"Stripe-Signature": fmt.Sprintf("t=%d,v1=%s", timestamp, sig)}
	replayID := "evt_required_name_case"

	first, err := engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(replayID))
	if err != nil {
		t.Fatalf("first verification failed: %v", err)
	}
	if !first.Valid || first.ReplayDetected {
		t.Fatalf("expected first verification valid and non-replay, got %+v", first)
	}

	second, err := engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(replayID))
	if err == nil {
		t.Fatal("expected replay detection error on second verification")
	}
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
	if second.Valid || !second.ReplayDetected {
		t.Fatalf("expected invalid replay-detected result on second verification, got %+v", second)
	}
}

func TestWithToleranceOverride(t *testing.T) {
	// Use a fixed clock for deterministic timestamp testing
	fixedTime := time.Unix(1714600000, 0)

	// Create engine with very short tolerance for stripe (which has timestamp validation)
	shortTolerance := 10 * time.Second
	engine, err := New(WithClock(fixedClock{t: fixedTime}), WithTolerance("stripe", shortTolerance))
	if err != nil {
		t.Fatalf("New() with WithTolerance failed: %v", err)
	}

	// Stripe webhook with timestamp matching fixed clock
	timestamp := fixedTime.Unix()
	payload := []byte(`{"id":"evt_test","type":"charge.succeeded"}`)
	secret := "stripe-secret"

	// Build signed payload: timestamp.payload
	signedPayload := []byte(fmt.Sprintf("%d.%s", timestamp, payload))
	sig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)

	headers := map[string]string{
		"Stripe-Signature": fmt.Sprintf("t=%d,v1=%s", timestamp, sig),
	}

	// Verification within tolerance should succeed
	result, err := engine.VerifyFull(context.Background(), "stripe", payload, headers, secret)
	if err != nil {
		t.Fatalf("VerifyFull() within tolerance failed: %v", err)
	}
	if !result.Valid {
		t.Error("expected valid result within tolerance window")
	}

	// Move clock forward beyond tolerance window
	futureTime := fixedTime.Add(shortTolerance + 5*time.Second)
	futureClock := fixedClock{t: futureTime}
	engineFuture, err := New(WithClock(futureClock), WithTolerance("stripe", shortTolerance))
	if err != nil {
		t.Fatalf("New() with future clock failed: %v", err)
	}

	// Verification beyond tolerance should fail
	result, err = engineFuture.VerifyFull(context.Background(), "stripe", payload, headers, secret)
	if err == nil {
		t.Fatal("expected error for timestamp beyond tolerance")
	}
	if result.Valid {
		t.Error("expected Valid=false for expired timestamp")
	}
	// Should be timestamp expiry error
	if !errors.Is(err, ErrTimestampExpired) {
		t.Errorf("expected ErrTimestampExpired, got %v", err)
	}
}

