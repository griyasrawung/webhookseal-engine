# Replay store contract and design guidance

`webhookseal-engine` defines a replay abstraction, then leaves persistence to callers.

```go
type ReplayStore interface {
    MarkIfAbsent(ctx context.Context, scope string, id string, ttl time.Duration) (inserted bool, err error)
}
```

## Interface contract

`MarkIfAbsent` receives:
- `scope`: logical namespace, usually provider or tenant-qualified provider.
- `id`: provider event identifier.
- `ttl`: how long the key should remain replay-protected.

Return values:
- `inserted=true, err=nil`: id was absent, now recorded.
- `inserted=false, err=nil`: id already exists, replay detected.
- `err!=nil`: storage failure, verification returns failure.

Expected semantics:
- Insert and existence check must be atomic.
- TTL should be applied on first insert.
- Reusing an expired id should be treated as absent.

## Engine interaction details

Replay check runs only when both conditions are true:
1. Engine was built with `WithReplayStore(store)`.
2. Verification call includes `WithReplayID(id)` with non-empty `id`.

Scope behavior:
- Explicit `WithReplayScope(scope)` takes priority.
- Empty scope falls back to provider name.

TTL behavior:
- Uses per-provider replay window from spec.
- `WithTolerance(provider, duration)` overrides spec window.
- If resolved window is zero, caller store should still handle request consistently, with immediate expiration policy if desired.

## Redis design guidance

No implementation code here, design only.

Recommended key model:
- Key: `ws:replay:{scope}:{id}`
- Value: constant marker like `1`
- TTL: resolved replay window

Atomic insert pattern:
- Use `SET key value NX EX ttl_seconds`
- Success means `inserted=true`
- Nil reply means `inserted=false`

Operational notes:
- Keep scope bounded, avoid untrusted high-cardinality prefixes.
- Add metrics for insert success, duplicate hits, and backend failures.
- Consider network timeout handling through context propagation.

## SQL design guidance

No implementation code here, design only.

Recommended schema concept:
- Columns: `scope`, `event_id`, `expires_at`, `created_at`
- Unique constraint: `(scope, event_id)`

Atomic insert pattern:
- Insert row with unique key.
- If unique violation occurs and existing row is unexpired, treat as replay.
- If existing row is expired, either delete then insert, or upsert with expiration-aware condition.

Cleanup strategy:
- Periodic job removes rows where `expires_at < now()`.
- Index `expires_at` for cleanup scans.

Isolation and correctness:
- Keep duplicate detection in a single transaction boundary.
- Avoid read-then-write races without unique constraint enforcement.

## Reliability checklist

- Respect `context.Context` cancellation and deadlines.
- Return deterministic results under concurrent duplicates.
- Separate backend outage errors from duplicate replay outcomes.
- Log with scope and provider context, never log secrets.
