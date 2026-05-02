package fixtures

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// FixtureCase defines one verification scenario from a provider fixture file.
type FixtureCase struct {
	Name          string            `json:"name"`
	Secret        string            `json:"secret"`
	Headers       map[string]string `json:"headers"`
	Body          string            `json:"body"`
	URL           string            `json:"url"`
	Params        map[string]string `json:"params"`
	Timestamp     int64             `json:"timestamp"`
	ExpectedError *string           `json:"expected_error"`
}

// ProviderFixtures is the top-level fixture file structure.
type ProviderFixtures struct {
	ProviderID string        `json:"provider_id"`
	Cases      []FixtureCase `json:"cases"`
}

// LoadProviderFixtures loads a provider fixture JSON from internal fixture storage.
func LoadProviderFixtures(filePath string) (*ProviderFixtures, error) {
	abs, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("resolve fixture path: %w", err)
	}

	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("read fixture file %q: %w", abs, err)
	}

	var fixtures ProviderFixtures
	if err := json.Unmarshal(data, &fixtures); err != nil {
		return nil, fmt.Errorf("unmarshal fixture file %q: %w", abs, err)
	}

	if fixtures.ProviderID == "" {
		return nil, fmt.Errorf("fixture file %q has empty provider_id", abs)
	}

	return &fixtures, nil
}
