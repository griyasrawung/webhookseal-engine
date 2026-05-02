package webhookseal

import (
	"errors"
	"fmt"
)

// Sentinel errors for webhook verification failures
var (
	// ErrMissingSignature indicates the signature header is missing
	ErrMissingSignature = errors.New("missing signature header")

	// ErrMissingTimestamp indicates the timestamp header is missing
	ErrMissingTimestamp = errors.New("missing timestamp header")

	// ErrBadFormat indicates malformed headers or payload structure
	ErrBadFormat = errors.New("bad format")

	// ErrBadSignature indicates signature verification failed
	ErrBadSignature = errors.New("bad signature")

	// ErrTimestampExpired indicates the timestamp is outside tolerance window
	ErrTimestampExpired = errors.New("timestamp expired")

	// ErrReplayDetected indicates a replay attack was detected
	ErrReplayDetected = errors.New("replay detected")

	// ErrUnknownProvider indicates the provider is not recognized
	ErrUnknownProvider = errors.New("unknown provider")

	// ErrPayloadTooLarge indicates the payload exceeds size limits
	ErrPayloadTooLarge = errors.New("payload too large")

	// ErrSpecLoad indicates failure to load provider specification
	ErrSpecLoad = errors.New("spec load failed")
)

// VerificationError wraps verification failures with structured context
type VerificationError struct {
	// Code is the canonical error code (e.g., "ERR_MISSING_SIGNATURE")
	Code string

	// Provider is the webhook provider name (e.g., "github", "stripe")
	Provider string

	// Message is a human-readable error description
	Message string

	// Hint provides actionable guidance for resolving the error
	Hint string

	// Cause is the underlying sentinel error
	Cause error
}

// Error implements the error interface
func (e *VerificationError) Error() string {
	if e.Provider != "" {
		return fmt.Sprintf("[%s] %s: %s", e.Provider, e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause for errors.Is compatibility
func (e *VerificationError) Unwrap() error {
	return e.Cause
}

// CodeToSentinel maps canonical error codes to sentinel errors
var CodeToSentinel = map[string]error{
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

// NewVerificationError creates a VerificationError from a canonical code
func NewVerificationError(code, provider, message, hint string) *VerificationError {
	sentinel, ok := CodeToSentinel[code]
	if !ok {
		sentinel = errors.New("unknown error")
	}

	return &VerificationError{
		Code:     code,
		Provider: provider,
		Message:  message,
		Hint:     hint,
		Cause:    sentinel,
	}
}
