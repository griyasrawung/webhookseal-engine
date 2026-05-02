package webhookseal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/griyasrawung/webhookseal-engine/internal/replay"
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

func TestEngineExplicitScenariosD5(t *testing.T) {
	t.Run("valid signature", func(t *testing.T) {
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
	})

	t.Run("tampered body", func(t *testing.T) {
		engine, _ := New()
		original := []byte(`{"order_id":123,"total":"10.00"}`)
		tampered := []byte(`{"order_id": 123, "total": "10.00"}`)
		secret := "shopify-edge-secret"
		sig := mustSignature(t, "hmac-sha256", "base64", secret, original)
		headers := map[string]string{"X-Shopify-Hmac-Sha256": sig}
		_, err := engine.VerifyFull(context.Background(), "shopify", tampered, headers, secret)
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("expected ErrBadSignature, got %v", err)
		}
	})

	t.Run("expired timestamp", func(t *testing.T) {
		now := time.Unix(1714600000, 0)
		expired := now.Add(-10 * time.Minute)
		engine, _ := New(WithClock(fixedClock{t: now}))
		body := []byte(`{"id":"evt_expired","object":"event"}`)
		secret := "whsec_edge_expired"
		signedPayload := []byte(fmt.Sprintf("%d.%s", expired.Unix(), body))
		sig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)
		headers := map[string]string{"Stripe-Signature": fmt.Sprintf("t=%d,v1=%s", expired.Unix(), sig)}
		_, err := engine.VerifyFull(context.Background(), "stripe", body, headers, secret)
		if !errors.Is(err, ErrTimestampExpired) {
			t.Fatalf("expected ErrTimestampExpired, got %v", err)
		}
	})

	t.Run("replayed ID/nonce via WithReplayID", func(t *testing.T) {
		store := replay.NewMemoryStore()
		now := time.Unix(1714600000, 0)
		engine, _ := New(WithReplayStore(store), WithClock(fixedClock{t: now}), WithTolerance("stripe", 5*time.Minute))
		timestamp := now.Unix()
		payload := []byte(`{"id":"evt_replay","object":"event"}`)
		secret := "whsec_replay_test"
		signedPayload := []byte(fmt.Sprintf("%d.%s", timestamp, payload))
		sig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)
		headers := map[string]string{"Stripe-Signature": fmt.Sprintf("t=%d,v1=%s", timestamp, sig)}
		replayID := "evt_unique_12345"
		if _, err := engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(replayID)); err != nil {
			t.Fatalf("first verify failed: %v", err)
		}
		_, err := engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(replayID))
		if !errors.Is(err, ErrReplayDetected) {
			t.Fatalf("expected ErrReplayDetected, got %v", err)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		engine, _ := New()
		payload := []byte(`{"action":"opened"}`)
		sig := mustSignature(t, "hmac-sha256", "hex", "correct-secret", payload)
		headers := map[string]string{"X-Hub-Signature-256": "sha256=" + sig}
		_, err := engine.VerifyFull(context.Background(), "github", payload, headers, "wrong-secret")
		if !errors.Is(err, ErrBadSignature) {
			t.Fatalf("expected ErrBadSignature, got %v", err)
		}
	})

	t.Run("missing signature header", func(t *testing.T) {
		engine, _ := New()
		_, err := engine.VerifyFull(context.Background(), "github", []byte("{}"), map[string]string{}, "secret")
		if !errors.Is(err, ErrMissingSignature) {
			t.Fatalf("expected ErrMissingSignature, got %v", err)
		}
	})

	t.Run("missing timestamp header", func(t *testing.T) {
		engine, _ := New()
		body := []byte(`token=edge&team_id=T123`)
		secret := "slack-edge-secret"
		sig := mustSignature(t, "hmac-sha256", "hex", secret, []byte("v0:1714600000:"+string(body)))
		headers := map[string]string{"X-Slack-Signature": "v0=" + sig}
		_, err := engine.VerifyFull(context.Background(), "slack", body, headers, secret)
		if !errors.Is(err, ErrMissingTimestamp) {
			t.Fatalf("expected ErrMissingTimestamp, got %v", err)
		}
	})

	t.Run("malformed signature", func(t *testing.T) {
		engine, _ := New()
		body := []byte(`{"action":"opened"}`)
		secret := "github-edge-secret"
		sig := mustSignature(t, "hmac-sha256", "hex", secret, body)
		headers := map[string]string{"X-Hub-Signature-256": sig}
		if err := engine.Verify(context.Background(), "github", body, headers, secret); !errors.Is(err, ErrBadFormat) {
			t.Fatalf("expected ErrBadFormat, got %v", err)
		}
	})
}

func TestReplayStoreConcurrentAtomicity(t *testing.T) {
	store := replay.NewMemoryStore()
	now := time.Unix(1714600000, 0)
	engine, err := New(WithReplayStore(store), WithClock(fixedClock{t: now}), WithTolerance("stripe", 5*time.Minute))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	timestamp := now.Unix()
	payload := []byte(`{"id":"evt_replay","object":"event"}`)
	secret := "whsec_replay_test"
	signedPayload := []byte(fmt.Sprintf("%d.%s", timestamp, payload))
	sig := mustSignature(t, "hmac-sha256", "hex", secret, signedPayload)
	headers := map[string]string{"Stripe-Signature": fmt.Sprintf("t=%d,v1=%s", timestamp, sig)}
	replayID := "evt_concurrent_once"

	const workers = 32
	var accepted int32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			_, callErr := engine.VerifyFull(context.Background(), "stripe", payload, headers, secret, WithReplayID(replayID))
			if callErr == nil {
				atomic.AddInt32(&accepted, 1)
				return
			}
			if !errors.Is(callErr, ErrReplayDetected) {
				t.Errorf("expected ErrReplayDetected for rejected concurrent call, got %v", callErr)
			}
		}()
	}
	wg.Wait()

	if accepted != 1 {
		t.Fatalf("expected exactly one accepted replay ID, got %d", accepted)
	}
}

