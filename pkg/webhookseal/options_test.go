package webhookseal

import (
	"context"
	"testing"
	"time"

	"github.com/webhookseal/webhookseal-engine/internal/specs"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.clock == nil {
		t.Error("expected default clock to be set")
	}

	if _, ok := cfg.clock.(systemClock); !ok {
		t.Errorf("expected systemClock, got %T", cfg.clock)
	}

	if cfg.toleranceMap == nil {
		t.Error("expected tolerance map to be initialized")
	}

	if len(cfg.toleranceMap) != 0 {
		t.Errorf("expected empty tolerance map, got %d entries", len(cfg.toleranceMap))
	}

	if cfg.replayStore != nil {
		t.Error("expected nil replay store by default")
	}

	expectedMaxSize := int64(10 * 1024 * 1024)
	if cfg.maxPayloadSize != expectedMaxSize {
		t.Errorf("expected max payload size %d, got %d", expectedMaxSize, cfg.maxPayloadSize)
	}

	if cfg.providerSpecs != nil {
		t.Error("expected nil provider specs by default")
	}
}

type mockClock struct {
	now time.Time
}

func (m mockClock) Now() time.Time {
	return m.now
}

func TestWithClock(t *testing.T) {
	fixedTime := time.Date(2026, 5, 2, 12, 0, 0, 0, time.UTC)
	mock := mockClock{now: fixedTime}

	cfg := defaultConfig()
	opt := WithClock(mock)

	if err := opt(cfg); err != nil {
		t.Fatalf("WithClock failed: %v", err)
	}

	if cfg.clock.Now() != fixedTime {
		t.Errorf("expected clock to return %v, got %v", fixedTime, cfg.clock.Now())
	}
}

func TestWithClockNil(t *testing.T) {
	cfg := defaultConfig()
	opt := WithClock(nil)

	err := opt(cfg)
	if err == nil {
		t.Error("expected error when setting nil clock")
	}
}

func TestWithTolerance(t *testing.T) {
	cfg := defaultConfig()
	opt := WithTolerance("github", 10*time.Minute)

	if err := opt(cfg); err != nil {
		t.Fatalf("WithTolerance failed: %v", err)
	}

	if cfg.toleranceMap["github"] != 10*time.Minute {
		t.Errorf("expected tolerance 10m, got %v", cfg.toleranceMap["github"])
	}
}

func TestWithToleranceEmptyProvider(t *testing.T) {
	cfg := defaultConfig()
	opt := WithTolerance("", 5*time.Minute)

	err := opt(cfg)
	if err == nil {
		t.Error("expected error for empty provider")
	}
}

func TestWithToleranceNegative(t *testing.T) {
	cfg := defaultConfig()
	opt := WithTolerance("stripe", -5*time.Minute)

	err := opt(cfg)
	if err == nil {
		t.Error("expected error for negative tolerance")
	}
}

func TestWithToleranceZero(t *testing.T) {
	cfg := defaultConfig()
	opt := WithTolerance("stripe", 0)

	err := opt(cfg)
	if err == nil {
		t.Error("expected error for zero tolerance")
	}
}

func TestWithReplayStore(t *testing.T) {
	cfg := defaultConfig()
	mockStore := &mockReplayStore{}
	opt := WithReplayStore(mockStore)

	if err := opt(cfg); err != nil {
		t.Fatalf("WithReplayStore failed: %v", err)
	}

	if cfg.replayStore != mockStore {
		t.Error("expected replay store to be set")
	}
}

func TestWithReplayStoreNil(t *testing.T) {
	cfg := defaultConfig()
	opt := WithReplayStore(nil)

	if err := opt(cfg); err != nil {
		t.Fatalf("WithReplayStore(nil) should not error: %v", err)
	}

	if cfg.replayStore != nil {
		t.Error("expected replay store to remain nil")
	}
}

func TestWithMaxPayloadSize(t *testing.T) {
	cfg := defaultConfig()
	opt := WithMaxPayloadSize(5 * 1024 * 1024)

	if err := opt(cfg); err != nil {
		t.Fatalf("WithMaxPayloadSize failed: %v", err)
	}

	if cfg.maxPayloadSize != 5*1024*1024 {
		t.Errorf("expected max payload size 5MB, got %d", cfg.maxPayloadSize)
	}
}

func TestWithMaxPayloadSizeZero(t *testing.T) {
	cfg := defaultConfig()
	opt := WithMaxPayloadSize(0)

	err := opt(cfg)
	if err == nil {
		t.Error("expected error for zero max payload size")
	}
}

func TestWithMaxPayloadSizeNegative(t *testing.T) {
	cfg := defaultConfig()
	opt := WithMaxPayloadSize(-100)

	err := opt(cfg)
	if err == nil {
		t.Error("expected error for negative max payload size")
	}
}

func TestWithSpecs(t *testing.T) {
	cfg := defaultConfig()
	testSpecs := make(map[string]*specs.ProviderSpec)
	opt := WithSpecs(testSpecs)

	if err := opt(cfg); err != nil {
		t.Fatalf("WithSpecs failed: %v", err)
	}

	if cfg.providerSpecs == nil {
		t.Error("expected provider specs to be set")
	}
}

// mockReplayStore for testing
type mockReplayStore struct{}

func (m *mockReplayStore) MarkIfAbsent(ctx context.Context, scope string, id string, ttl time.Duration) (bool, error) {
	return true, nil
}
