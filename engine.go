package webhookseal

import (
	"context"
	"errors"
	"strings"
	"time"

	internalhmac "github.com/webhookseal/webhookseal-engine/internal/hmac"
	"github.com/webhookseal/webhookseal-engine/internal/payload"
	"github.com/webhookseal/webhookseal-engine/internal/signature"
	"github.com/webhookseal/webhookseal-engine/internal/specs"
	"github.com/webhookseal/webhookseal-engine/internal/timestamp"
)

// Engine verifies webhook signatures using provider specifications.
type Engine struct {
	specs  map[string]*specs.ProviderSpec
	config config
}

// New creates an Engine and loads provider specifications once.
func New(opts ...Option) (*Engine, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	loadedSpecs := cfg.providerSpecs
	if loadedSpecs == nil {
		var err error
		loadedSpecs, err = specs.LoadAll(specs.ProviderFS)
		if err != nil {
			return nil, errorFor("ERR_SPEC_LOAD", "", err)
		}
	}

	cfg.providerSpecs = loadedSpecs
	return &Engine{specs: loadedSpecs, config: *cfg}, nil
}

// Verify verifies a webhook signature and returns only the verification error.
func (e *Engine) Verify(ctx context.Context, provider string, payload []byte, headers map[string]string, secret string) error {
	_, err := e.VerifyFull(ctx, provider, payload, headers, secret)
	return err
}

// VerifyFull verifies a webhook signature and returns structured metadata.
func (e *Engine) VerifyFull(ctx context.Context, provider string, body []byte, headers map[string]string, secret string, opts ...VerifyOption) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if int64(len(body)) > e.config.maxPayloadSize {
		return Result{Valid: false, Provider: provider, Reason: ErrPayloadTooLarge.Error()}, errorFor("ERR_PAYLOAD_TOO_LARGE", provider, ErrPayloadTooLarge)
	}

	spec, ok := e.specs[provider]
	if !ok {
		return Result{Valid: false, Provider: provider, Reason: ErrUnknownProvider.Error()}, errorFor("ERR_UNKNOWN_PROVIDER", provider, ErrUnknownProvider)
	}

	verifyCfg := defaultVerifyConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(verifyCfg); err != nil {
			return Result{Valid: false, Provider: provider, Algorithm: spec.Algorithm, Reason: err.Error()}, errorFor("ERR_BAD_FORMAT", provider, err)
		}
	}

	// Extract signature first to ensure missing signature takes precedence over missing timestamp
	received, err := signature.Extract(spec, headers)
	if err != nil {
		return Result{Valid: false, Provider: provider, Algorithm: spec.Algorithm, Reason: err.Error()}, mapSignatureError(provider, err)
	}

	ts, tsValue, err := timestamp.Extract(spec, headers)
	if err != nil {
		return Result{Valid: false, Provider: provider, Algorithm: spec.Algorithm, Reason: err.Error()}, mapTimestampError(provider, err)
	}

	window := e.replayWindow(provider, spec)
	if window > 0 {
		if err := timestamp.ValidateWindow(e.config.clock, ts, window); err != nil {
			return Result{Valid: false, Provider: provider, Timestamp: ts, Algorithm: spec.Algorithm, Reason: err.Error()}, errorFor("ERR_TIMESTAMP_EXPIRED", provider, err)
		}
	}

	builtPayload, err := payload.Build(spec, payload.Input{Body: body, URL: verifyCfg.url, Params: verifyCfg.params}, tsValue)
	if err != nil {
		return Result{Valid: false, Provider: provider, Timestamp: ts, Algorithm: spec.Algorithm, Reason: err.Error()}, errorFor("ERR_BAD_FORMAT", provider, err)
	}

	computed, err := internalhmac.Compute(spec.Algorithm, []byte(secret), builtPayload)
	if err != nil {
		return Result{Valid: false, Provider: provider, Timestamp: ts, Algorithm: spec.Algorithm, Reason: err.Error()}, errorFor("ERR_BAD_FORMAT", provider, err)
	}

	matchedIndex := -1
	for i, sig := range received {
		if internalhmac.TimingSafeEqual(computed, sig) {
			matchedIndex = i
			break
		}
	}
	if matchedIndex == -1 {
		return Result{Valid: false, Provider: provider, Timestamp: ts, Algorithm: spec.Algorithm, Reason: ErrBadSignature.Error()}, errorFor("ERR_BAD_SIGNATURE", provider, ErrBadSignature)
	}

	if e.config.replayStore != nil && verifyCfg.replayID != "" {
		scope := verifyCfg.replayScope
		if scope == "" {
			scope = provider
		}
		inserted, err := e.config.replayStore.MarkIfAbsent(ctx, scope, verifyCfg.replayID, window)
		if err != nil {
			return Result{Valid: false, Provider: provider, Timestamp: ts, Algorithm: spec.Algorithm, Reason: err.Error()}, errorFor("ERR_BAD_FORMAT", provider, err)
		}
		if !inserted {
			return Result{Valid: false, Provider: provider, Timestamp: ts, Algorithm: spec.Algorithm, ReplayDetected: true, Reason: ErrReplayDetected.Error()}, errorFor("ERR_REPLAY_DETECTED", provider, ErrReplayDetected)
		}
	}

	return Result{Valid: true, Provider: provider, Timestamp: ts, Algorithm: spec.Algorithm, SignatureID: signatureID(matchedIndex)}, nil
}

func (e *Engine) replayWindow(provider string, spec *specs.ProviderSpec) time.Duration {
	if d, ok := e.config.toleranceMap[provider]; ok {
		return d
	}
	if spec.ReplayWindowSeconds == nil || *spec.ReplayWindowSeconds <= 0 {
		return 0
	}
	return time.Duration(*spec.ReplayWindowSeconds) * time.Second
}

func mapTimestampError(provider string, err error) error {
	switch {
	case errors.Is(err, timestamp.ErrMissingTimestamp):
		return errorFor("ERR_MISSING_TIMESTAMP", provider, err)
	case errors.Is(err, timestamp.ErrTimestampExpired):
		return errorFor("ERR_TIMESTAMP_EXPIRED", provider, err)
	default:
		return errorFor("ERR_BAD_FORMAT", provider, err)
	}
}

func mapSignatureError(provider string, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, signature.ErrMissingSignature):
		return errorFor("ERR_MISSING_SIGNATURE", provider, err)
	case errors.Is(err, signature.ErrBadFormat):
		if strings.Contains(err.Error(), "empty signature") || strings.Contains(err.Error(), "uppercase not allowed") || strings.Contains(err.Error(), "decode base64 signature") {
			return errorFor("ERR_BAD_SIGNATURE", provider, err)
		}
		return errorFor("ERR_BAD_FORMAT", provider, err)
	default:
		return errorFor("ERR_BAD_FORMAT", provider, err)
	}
}

func signatureID(index int) string {
	if index < 0 {
		return ""
	}
	return "signature"
}
