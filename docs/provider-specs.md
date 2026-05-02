# Provider specs source and refresh workflow

`webhookseal-engine` verifies requests based on provider specs, not hardcoded provider branches. Specs are sourced from the `webhookseal-providers` submodule and then generated into embedded engine assets.

## Source of truth

- Submodule path: `webhookseal-providers/`
- Submodule repository contains provider signature definitions.
- Engine runtime loads generated provider spec artifacts.

## Why this split exists

- Provider definitions evolve independently from engine internals.
- Engine logic stays generic.
- Updating provider behavior becomes a data refresh flow.

## Submodule update workflow

From repository root:

```bash
git submodule update --init --remote webhookseal-providers
```

Then inspect submodule diff and pin the new commit as part of your branch.

## Generate and refresh steps

After submodule update:

```bash
make generate
```

`make generate` refreshes generated artifacts that are embedded or loaded by the engine.

After generation:

```bash
go test ./...
```

## Suggested update checklist

1. Update `webhookseal-providers` submodule.
2. Run `make generate`.
3. Run `go test ./...`.
4. Review generated diffs for expected provider changes.
5. Commit submodule pointer and generated artifacts together.

## Troubleshooting

If provider is reported unknown:

- Confirm provider exists in submodule definitions.
- Re-run `make generate`.
- Confirm generated artifacts are present in working tree.

If signatures suddenly fail after refresh:

- Confirm upstream provider spec change details.
- Re-check local integration fixtures.
- Validate headers and canonical payload inputs used by your caller.
