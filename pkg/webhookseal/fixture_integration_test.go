package webhookseal

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/griyasrawung/webhookseal-engine/internal/fixtures"
)

// fixedClock returns a fixed time for fixture testing.
type fixedClock struct {
	t time.Time
}

func (c fixedClock) Now() time.Time {
	return c.t
}

func TestProviderFixtures(t *testing.T) {
	// Use a fixed clock that matches fixture timestamps
	// Most fixtures use timestamps around 1714600000 (May 2024)
	fixedTime := time.Unix(1714600000, 0)
	
	engine, err := New(WithClock(fixedClock{t: fixedTime}))
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	providers := []string{"github", "stripe", "slack", "shopify", "twilio"}
	totalCases := 0
	totalPassed := 0

	for _, provider := range providers {
		fixturePath := filepath.Join("..", "..", "internal", "fixtures", "providers", provider+".fixtures.json")
		providerFixtures, err := fixtures.LoadProviderFixtures(fixturePath)
		if err != nil {
			t.Fatalf("LoadProviderFixtures(%q) failed: %v", provider, err)
		}

		if providerFixtures.ProviderID != provider {
			t.Fatalf("provider mismatch: fixture has %q, expected %q", providerFixtures.ProviderID, provider)
		}

		for _, tc := range providerFixtures.Cases {
			totalCases++
			caseName := provider + "/" + tc.Name

			var opts []VerifyOption
			if tc.URL != "" {
				opts = append(opts, WithURL(tc.URL))
			}
			if len(tc.Params) > 0 {
				opts = append(opts, WithParams(tc.Params))
			}

			_, err := engine.VerifyFull(context.Background(), provider, []byte(tc.Body), tc.Headers, tc.Secret, opts...)

			if tc.ExpectedError == nil {
				// Case should pass
				if err != nil {
					t.Errorf("[%s] expected success, got error: %v", caseName, err)
				} else {
					totalPassed++
				}
			} else {
				// Case should fail with specific error
				expectedSentinel := CodeToSentinel[*tc.ExpectedError]
				if expectedSentinel == nil {
					t.Fatalf("[%s] unknown expected_error code: %q", caseName, *tc.ExpectedError)
				}

				if err == nil {
					t.Errorf("[%s] expected error %q, got success", caseName, *tc.ExpectedError)
				} else if !errors.Is(err, expectedSentinel) {
					t.Errorf("[%s] expected error %q (sentinel: %v), got: %v", caseName, *tc.ExpectedError, expectedSentinel, err)
				} else {
					totalPassed++
				}
			}
		}
	}

	t.Logf("Fixture integration: %d/%d cases passed", totalPassed, totalCases)

	if totalPassed != totalCases {
		t.Fatalf("Expected all %d cases to pass, but only %d passed", totalCases, totalPassed)
	}

	// Assert expected total of 40 cases
	expectedTotal := 40
	if totalCases != expectedTotal {
		t.Fatalf("Expected %d total fixture cases, got %d", expectedTotal, totalCases)
	}
}
