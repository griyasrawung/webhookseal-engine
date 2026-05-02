# API reference

This page covers public API surfaces in `webhookseal-engine` and the behavior of configuration options.

## Engine construction

```go
func New(opts ...Option) (*Engine, error)
```

Builds an engine and loads provider specs.

Behavior:

- Applies options in order.
- Ignores nil options.
- Loads embedded provider specs when `WithSpecs` is not provided.
- Returns `ERR_SPEC_LOAD` wrapped as `ErrSpecLoad` when spec loading fails.

## Verification methods

```go
func (e *Engine) Verify(ctx context.Context, provider string, payload []byte, headers map[string]string, secret string) error
```

`Verify` is a convenience method. It calls `VerifyFull` and returns only the error.

```go
func (e *Engine) VerifyFull(ctx context.Context, provider string, body []byte, headers map[string]string, secret string, opts ...VerifyOption) (Result, error)
```

`VerifyFull` performs full verification and returns both `Result` and `error`.

High-level behavior:

- Uses `context.Background()` if `ctx` is nil.
- Checks payload size against configured max.
- Resolves provider spec by name.
- Applies verify options in order.
- Extracts and validates signature and timestamp.
- Builds canonical payload according to provider spec.
- Computes HMAC and compares with timing-safe equality.
- Executes replay store check when configured and replay id is provided.

## Result

```go
type Result struct {
    Valid          bool
    Provider       string
    Timestamp      time.Time
    Algorithm      string
    ReplayDetected bool
    Reason         string
    SignatureID    string
}
```

Field notes:

- `Valid`: true when verification succeeds.
- `Provider`: provider passed to verification.
- `Timestamp`: extracted provider timestamp when available.
- `Algorithm`: HMAC algorithm from provider spec.
- `ReplayDetected`: true when replay store rejects `(scope,id)` as seen.
- `Reason`: failure reason text.
- `SignatureID`: currently `signature` when a signature candidate matches.

## Engine options

```go
type Option func(*config) error
```

### WithClock

```go
func WithClock(clock Clock) Option
```

Sets custom clock source.

Behavior:

- Returns error if `clock` is nil.
- Affects timestamp window validation.

### WithTolerance

```go
func WithTolerance(provider string, d time.Duration) Option
```

Overrides replay and timestamp tolerance window per provider.

Behavior:

- Returns error if provider is empty.
- Returns error if duration is zero or negative.
- Overrides provider spec replay window for that provider.

### WithReplayStore

```go
func WithReplayStore(store ReplayStore) Option
```

Sets replay store used by `VerifyFull` when `WithReplayID` is passed.

Behavior:

- Accepts nil, meaning replay detection disabled.

### WithMaxPayloadSize

```go
func WithMaxPayloadSize(bytes int64) Option
```

Sets maximum payload size.

Behavior:

- Returns error if `bytes <= 0`.
- Verification returns `ErrPayloadTooLarge` on oversize body.

### WithSpecs

```go
func WithSpecs(specs map[string]*specs.ProviderSpec) Option
```

Injects provider specs instead of loading embedded defaults.

Behavior:

- Useful for tests and custom spec loading flows.

## Verify options

```go
type VerifyOption func(*verifyConfig) error
```

### WithURL

```go
func WithURL(url string) VerifyOption
```

Sets full URL for providers that include URL in canonical payload.

### WithParams

```go
func WithParams(params map[string]string) VerifyOption
```

Sets canonicalization parameters for providers that include parameter maps.

### WithReplayID

```go
func WithReplayID(id string) VerifyOption
```

Sets unique event id used for replay detection.

Behavior:

- Replay store check only runs when replay store is configured and replay id is non-empty.

### WithReplayScope

```go
func WithReplayScope(scope string) VerifyOption
```

Sets replay namespace.

Behavior:

- Defaults to provider name when empty.

## ReplayStore

```go
type ReplayStore interface {
    MarkIfAbsent(ctx context.Context, scope string, id string, ttl time.Duration) (inserted bool, err error)
}
```

Contract summary:
- Return `true` when `(scope,id)` was not present and is now recorded.
- Return `false` when `(scope,id)` already exists and is still valid.
- Return non-nil error for backend failures.

## Sentinel errors

Use `errors.Is` with sentinels:

- `ErrMissingSignature`
- `ErrMissingTimestamp`
- `ErrBadFormat`
- `ErrBadSignature`
- `ErrTimestampExpired`
- `ErrReplayDetected`
- `ErrUnknownProvider`
- `ErrPayloadTooLarge`
- `ErrSpecLoad`
