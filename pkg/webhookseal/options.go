package webhookseal

import (
	"fmt"
	"time"

	"github.com/griyasrawung/webhookseal-engine/internal/specs"
)

// Option configures the webhook verification engine.
type Option func(*config) error

// config holds internal configuration for the engine.
type config struct {
	clock            Clock
	toleranceMap     map[string]time.Duration
	replayStore      ReplayStore
	maxPayloadSize   int64
	providerSpecs    map[string]*specs.ProviderSpec
}

// defaultConfig returns a config with sensible defaults.
func defaultConfig() *config {
	return &config{
		clock:          systemClock{},
		toleranceMap:   make(map[string]time.Duration),
		replayStore:    nil,
		maxPayloadSize: 10 * 1024 * 1024, // 10MB
		providerSpecs:  nil,
	}
}

// systemClock implements Clock using time.Now.
type systemClock struct{}

func (systemClock) Now() time.Time {
	return time.Now()
}

// WithClock sets a custom time source for timestamp validation.
func WithClock(clock Clock) Option {
	return func(c *config) error {
		if clock == nil {
			return fmt.Errorf("clock cannot be nil")
		}
		c.clock = clock
		return nil
	}
}

// WithTolerance overrides the timestamp tolerance for a specific provider.
func WithTolerance(provider string, d time.Duration) Option {
	return func(c *config) error {
		if provider == "" {
			return fmt.Errorf("provider cannot be empty")
		}
		if d <= 0 {
			return fmt.Errorf("tolerance must be positive")
		}
		c.toleranceMap[provider] = d
		return nil
	}
}

// WithReplayStore sets the replay attack prevention store.
func WithReplayStore(store ReplayStore) Option {
	return func(c *config) error {
		c.replayStore = store
		return nil
	}
}

// WithMaxPayloadSize sets the maximum allowed payload size in bytes.
func WithMaxPayloadSize(bytes int64) Option {
	return func(c *config) error {
		if bytes <= 0 {
			return fmt.Errorf("max payload size must be positive")
		}
		c.maxPayloadSize = bytes
		return nil
	}
}

// WithSpecs sets custom provider specifications.
func WithSpecs(specs map[string]*specs.ProviderSpec) Option {
	return func(c *config) error {
		c.providerSpecs = specs
		return nil
	}
}
