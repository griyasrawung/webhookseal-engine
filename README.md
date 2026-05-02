# webhookseal-engine

`webhookseal-engine` is a Go library that verifies webhook signatures in a provider-aware way. It loads provider signing rules, normalizes verification behavior, and returns either a simple error or a structured verification result.

## How this relates to `webhookseal-providers`

This repository includes `webhookseal-providers` as a git submodule. That submodule is the source of truth for provider signature specifications. The engine consumes generated spec artifacts from those definitions.

- Provider rules live in `webhookseal-providers`
- Engine runtime verification logic lives in `webhookseal-engine`
- Generated embedded specs are refreshed with `make generate`

## Install

```bash
go get github.com/griyasrawung/webhookseal-engine
```

## Import

```go
import webhookseal "github.com/griyasrawung/webhookseal-engine/pkg/webhookseal"
```

## Quick start, `Verify()`

Use `Verify()` when you only need pass or fail.

```go
package main

import (
	"context"
	"errors"

	webhookseal "github.com/griyasrawung/webhookseal-engine/pkg/webhookseal"
)

func verifySimple(body []byte, headers map[string]string, secret string) error {
	eng, err := webhookseal.New()
	if err != nil {
		return err
	}

	err = eng.Verify(context.Background(), "stripe", body, headers, secret)
	if err == nil {
		return nil
	}

	if errors.Is(err, webhookseal.ErrBadSignature) {
		// signature mismatch
		return err
	}
	if errors.Is(err, webhookseal.ErrTimestampExpired) {
		// request too old
		return err
	}

	return err
}
```

## Advanced usage, `VerifyFull()` and `Result`

Use `VerifyFull()` when you need metadata like timestamp, algorithm, signature slot, or replay detection output.

```go
package main

import (
	"context"
	"fmt"

	webhookseal "github.com/griyasrawung/webhookseal-engine/pkg/webhookseal"
)

func verifyDetailed(body []byte, headers map[string]string, secret string, eventID string) error {
	eng, err := webhookseal.New()
	if err != nil {
		return err
	}

	res, err := eng.VerifyFull(
		context.Background(),
		"github",
		body,
		headers,
		secret,
		webhookseal.WithReplayID(eventID),
		webhookseal.WithReplayScope("github:repo:123"),
	)
	if err != nil {
		return err
	}

	fmt.Printf("valid=%v provider=%s algorithm=%s signature_id=%s replay=%v\n",
		res.Valid,
		res.Provider,
		res.Algorithm,
		res.SignatureID,
		res.ReplayDetected,
	)
	return nil
}
```

`Result` fields:

- `Valid bool`
- `Provider string`
- `Timestamp time.Time`
- `Algorithm string`
- `ReplayDetected bool`
- `Reason string`
- `SignatureID string`

## ReplayStore interface usage

The engine does not ship a concrete store. You provide one with `WithReplayStore`.

```go
package main

import (
	"context"
	"sync"
	"time"

	webhookseal "github.com/griyasrawung/webhookseal-engine/pkg/webhookseal"
)

type memoryReplayStore struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newMemoryReplayStore() *memoryReplayStore {
	return &memoryReplayStore{seen: make(map[string]time.Time)}
}

func (m *memoryReplayStore) MarkIfAbsent(_ context.Context, scope string, id string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := scope + ":" + id
	now := time.Now()

	if exp, ok := m.seen[key]; ok && now.Before(exp) {
		return false, nil
	}
	m.seen[key] = now.Add(ttl)
	return true, nil
}

func buildEngine() (*webhookseal.Engine, error) {
	return webhookseal.New(
		webhookseal.WithReplayStore(newMemoryReplayStore()),
	)
}
```

For production patterns, see `docs/replay-store.md`.

## Spec embedding and generation flow

The engine embeds generated provider specs from internal generated assets.

Typical refresh flow:

1. Update submodule data.
2. Regenerate embedded artifacts.
3. Run tests.

```bash
git submodule update --init --remote webhookseal-providers
make generate
go test ./...
```

## CI/local verification commands

Run from `webhookseal-engine/`:

```bash
make generate
go test ./... -v
```

Expected passing outcome:
- `make generate` exits `0` with generated assets refreshed.
- `go test ./... -v` exits `0` with package test summaries ending in `PASS`.

CI additionally runs `go test ./... -v -race -coverprofile=coverage.txt`, but `-race` is not required for local verification in this environment.

## Supported providers

Provider support comes from embedded specs generated from `webhookseal-providers`.

| Provider | Source of behavior | Notes |
| --- | --- | --- |
| github | Generated provider spec | Uses provider spec signature and timestamp rules |
| stripe | Generated provider spec | Uses provider spec signature and timestamp rules |
| shopify | Generated provider spec | Uses provider spec signature and timestamp rules |
| slack | Generated provider spec | Uses provider spec signature and timestamp rules |
| twilio | Generated provider spec | Uses provider spec signature and timestamp rules |

Actual provider list depends on currently embedded generated specs.

## Error handling with `errors.Is`

Returned errors wrap sentinel values and are compatible with `errors.Is`.

```go
import "errors"

if err != nil {
	switch {
	case errors.Is(err, webhookseal.ErrMissingSignature):
		// required signature header not present
	case errors.Is(err, webhookseal.ErrMissingTimestamp):
		// required timestamp header not present
	case errors.Is(err, webhookseal.ErrBadSignature):
		// signature mismatch
	case errors.Is(err, webhookseal.ErrReplayDetected):
		// duplicate replay ID detected
	}
}
```

## Open-core boundary and secret handling

`webhookseal-engine` is an open verification library focused on provider-aware signature validation.

What this repository includes:
- Signature verification runtime.
- Replay-detection interfaces.
- Provider-spec consumption from open registry data.

What this repository does not include:
- Any proprietary/closed service deployment layer.
- Secret storage/vault implementations.
- Operational secret management workflows.

Secret handling expectations:
- Secrets are inputs at runtime and are not persisted by default by this library.
- Replay/verification metadata should be handled without exposing raw secret values.
- Production secret lifecycle concerns are outside this repository scope.

## Explicit non-goals

`webhookseal-engine` does not include:

- An API server or HTTP middleware stack
- Concrete replay store implementations, like Redis or SQL drivers
- Provider spec authoring workflows (these are maintained in the provider registry repository)

## Additional docs

- `docs/api.md`
- `docs/replay-store.md`
- `docs/provider-specs.md`
