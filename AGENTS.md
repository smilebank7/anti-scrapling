# Anti-Scrapling — Agent Orientation

Quick map for AI agents picking up work in this repo.

## Where things live

- `cmd/` — Go binaries (`antiscrapling` daemon, `antiscrapling-cli` admin)
- `internal/` — private Go packages; `internal/types` is the FROZEN shared contract
- `internal/signal/*` — detection modules (TLS, HTTP/2, headers, IP, fingerprint, behavior)
- `web/challenge/` — TypeScript-built JS bundle served as the browser challenge
- `sdk/` — language SDKs (Node, Python)
- `deploy/` — Docker, Helm, reverse-proxy examples
- `policies/` — YAML policy files (default, strict)
- `testdata/` — captured browser/scraper fingerprints (real bytes, not generated)
- `tests/` — `scrapling/` adversarial E2E; `integration/` real-browser pass-through

## Build commands

- `make build` — compile both binaries to `bin/`
- `make test` — Go unit tests
- `make test-race` — with race detector
- `make lint` — golangci-lint
- `make js-bundle` — build the challenge bundle
- `make e2e` — adversarial Scrapling tests (docker-compose)

## Conventions

- Atomic commits, Conventional Commits format
- All `internal/types/*.go` exports are FROZEN — adding fields is OK, removing or renaming is not
- Tests must use real data from `testdata/` whenever possible
- `lsp_diagnostics` must be clean on every changed Go file before commit
