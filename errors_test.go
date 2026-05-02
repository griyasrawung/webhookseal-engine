package webhookseal

import (
	"errors"
	"strings"
	"testing"
)

func TestVerificationError(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		provider string
		message  string
		hint     string
		wantErr  error
	}{
		{
			name:     "missing signature",
			code:     "ERR_MISSING_SIGNATURE",
			provider: "github",
			message:  "X-Hub-Signature-256 header not found",
			hint:     "Ensure webhook is configured with secret",
			wantErr:  ErrMissingSignature,
		},
		{
			name:     "missing timestamp",
			code:     "ERR_MISSING_TIMESTAMP",
			provider: "stripe",
			message:  "Stripe-Signature missing timestamp",
			hint:     "Check webhook endpoint configuration",
			wantErr:  ErrMissingTimestamp,
		},
		{
			name:     "bad format",
			code:     "ERR_BAD_FORMAT",
			provider: "shopify",
			message:  "Invalid HMAC format",
			hint:     "Verify header encoding",
			wantErr:  ErrBadFormat,
		},
		{
			name:     "bad signature",
			code:     "ERR_BAD_SIGNATURE",
			provider: "github",
			message:  "Signature mismatch",
			hint:     "Verify secret matches webhook configuration",
			wantErr:  ErrBadSignature,
		},
		{
			name:     "timestamp expired",
			code:     "ERR_TIMESTAMP_EXPIRED",
			provider: "stripe",
			message:  "Timestamp outside tolerance window",
			hint:     "Check server clock synchronization",
			wantErr:  ErrTimestampExpired,
		},
		{
			name:     "replay detected",
			code:     "ERR_REPLAY_DETECTED",
			provider: "svix",
			message:  "Message ID already processed",
			hint:     "Duplicate webhook delivery detected",
			wantErr:  ErrReplayDetected,
		},
		{
			name:     "unknown provider",
			code:     "ERR_UNKNOWN_PROVIDER",
			provider: "",
			message:  "Provider not recognized",
			hint:     "Check provider name spelling",
			wantErr:  ErrUnknownProvider,
		},
		{
			name:     "payload too large",
			code:     "ERR_PAYLOAD_TOO_LARGE",
			provider: "generic",
			message:  "Payload exceeds 10MB limit",
			hint:     "Reduce payload size or increase limit",
			wantErr:  ErrPayloadTooLarge,
		},
		{
			name:     "spec load failed",
			code:     "ERR_SPEC_LOAD",
			provider: "custom",
			message:  "Failed to load provider spec",
			hint:     "Verify spec file exists and is valid YAML",
			wantErr:  ErrSpecLoad,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewVerificationError(tt.code, tt.provider, tt.message, tt.hint)

			// Test errors.Is compatibility
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("errors.Is() failed: want %v, got %v", tt.wantErr, err)
			}

			// Test Error() formatting
			errStr := err.Error()
			if errStr == "" {
				t.Error("Error() returned empty string")
			}

			// Test Unwrap
			if unwrapped := errors.Unwrap(err); unwrapped != tt.wantErr {
				t.Errorf("Unwrap() = %v, want %v", unwrapped, tt.wantErr)
			}

			// Test fields
			if err.Code != tt.code {
				t.Errorf("Code = %v, want %v", err.Code, tt.code)
			}
			if err.Provider != tt.provider {
				t.Errorf("Provider = %v, want %v", err.Provider, tt.provider)
			}
			if err.Message != tt.message {
				t.Errorf("Message = %v, want %v", err.Message, tt.message)
			}
			if err.Hint != tt.hint {
				t.Errorf("Hint = %v, want %v", err.Hint, tt.hint)
			}
		})
	}
}

func TestCodeToSentinel(t *testing.T) {
	expectedMappings := map[string]error{
		"ERR_MISSING_SIGNATURE":  ErrMissingSignature,
		"ERR_MISSING_TIMESTAMP":  ErrMissingTimestamp,
		"ERR_BAD_FORMAT":         ErrBadFormat,
		"ERR_BAD_SIGNATURE":      ErrBadSignature,
		"ERR_TIMESTAMP_EXPIRED":  ErrTimestampExpired,
		"ERR_REPLAY_DETECTED":    ErrReplayDetected,
		"ERR_UNKNOWN_PROVIDER":   ErrUnknownProvider,
		"ERR_PAYLOAD_TOO_LARGE":  ErrPayloadTooLarge,
		"ERR_SPEC_LOAD":          ErrSpecLoad,
	}

	for code, expectedErr := range expectedMappings {
		t.Run(code, func(t *testing.T) {
			sentinel, ok := CodeToSentinel[code]
			if !ok {
				t.Errorf("CodeToSentinel missing mapping for %s", code)
			}
			if sentinel != expectedErr {
				t.Errorf("CodeToSentinel[%s] = %v, want %v", code, sentinel, expectedErr)
			}
		})
	}
}

func TestVerificationErrorWrapping(t *testing.T) {
	// Test that wrapped errors preserve sentinel identity through multiple layers
	err := NewVerificationError("ERR_BAD_SIGNATURE", "github", "test", "hint")
	wrapped := &VerificationError{
		Code:     "WRAPPED",
		Provider: "wrapper",
		Message:  "wrapped error",
		Hint:     "unwrap to see cause",
		Cause:    err,
	}

	// Should be able to detect the original sentinel through wrapping
	if !errors.Is(wrapped, ErrBadSignature) {
		t.Error("errors.Is() failed to detect sentinel through wrapping")
	}
}

func TestVerificationErrorFormatting(t *testing.T) {
	tests := []struct {
		name     string
		err      *VerificationError
		contains []string
	}{
		{
			name: "with provider",
			err: &VerificationError{
				Code:     "ERR_BAD_SIGNATURE",
				Provider: "github",
				Message:  "signature mismatch",
				Cause:    ErrBadSignature,
			},
			contains: []string{"github", "ERR_BAD_SIGNATURE", "signature mismatch"},
		},
		{
			name: "without provider",
			err: &VerificationError{
				Code:     "ERR_SPEC_LOAD",
				Provider: "",
				Message:  "failed to load",
				Cause:    ErrSpecLoad,
			},
			contains: []string{"ERR_SPEC_LOAD", "failed to load"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			for _, substr := range tt.contains {
				if !contains(errStr, substr) {
					t.Errorf("Error() = %q, want to contain %q", errStr, substr)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
