# Anti-Scrapling: Parallel Build Plan

> **Status: COMPLETED.** All waves executed. See per-wave status below.

5 waves of parallel agent execution. Wave N+1 depends on Wave N outputs.

## Confirmed assumptions
- License: Apache-2.0
- Go version: 1.23
- JWT lib: `github.com/golang-jwt/jwt/v5`
- CEL: `github.com/google/cel-go`
- TLS reference: `github.com/refraction-networking/utls`
- IP data: embed GeoLite2-ASN.mmdb snapshot
- Scrapling pinning for E2E: `D4Vinci/Scrapling@b31dc50`
- Node SDK arch: thin HTTP-proxy to daemon (`/v1/decide`)
- Helm Redis: external (off by default)
- v1 includes both Node + Python SDKs

## Wave 0 — Foundation (2 parallel)
**Status: COMPLETED**

- **W0-T1**: Repo skeleton + Go module + shared types + tooling [unspecified-high] — Done. `go.mod`, `internal/types`, Makefile, golangci-lint config, `.github/` CI skeleton all in place.
- **W0-T2**: Test-vector corpus (public JA3/JA4 + synthesized FingerprintReport JSON) [unspecified-high] — Done. `testdata/` populated with real browser and scraper fingerprints.

## Wave 1 — Independent packages (12 parallel)
**Status: COMPLETED**

- **W1-T1**: `internal/signal/tls` JA3/JA4 [ultrabrain] — Done. JA3/JA4/JA4H computation from raw ClientHello bytes.
- **W1-T2**: `internal/signal/http2` JA4H + Akamai H2 [ultrabrain] — Done. H2 SETTINGS frame parser and Akamai fingerprint matcher.
- **W1-T3**: `internal/signal/headers` order + UA↔CH [unspecified-high] — Done. Header-order anomaly detection and UA/Client-Hints consistency checks.
- **W1-T4**: `internal/signal/ip` ASN + datacenter + Tor [unspecified-high] — Done. GeoLite2-ASN embedded, datacenter ASN list, Tor exit node list.
- **W1-T5**: `internal/signal/fingerprint` JS report scorer (CRITICAL PATH) [ultrabrain] — Done. 40+ signal probes scored against the JS fingerprint report.
- **W1-T6**: `internal/signal/behavior` telemetry [unspecified-high] — Done. Telemetry beacon ingestion and behavioral signal scoring.
- **W1-T7**: `internal/policy` YAML + CEL [unspecified-high] — Done. YAML policy parser, CEL expression evaluator, shorthand key compiler.
- **W1-T8**: `internal/decision` score combiner [unspecified-high] — Done. Signal aggregation, score computation, verdict determination.
- **W1-T9**: `internal/token` JWT pass-tokens [unspecified-high] — Done. HS256 JWT issue/verify with multi-dimension binding.
- **W1-T10**: `internal/cache` memory + Redis [unspecified-low] — Done. In-memory LRU cache; Redis backend wired but off by default.
- **W1-T11**: `internal/observability` Prom + slog + audit [unspecified-high] — Done. Prometheus metrics, structured slog JSON, audit ring buffer.
- **W1-T12**: `web/challenge` PoW + fingerprint collector JS (CRITICAL PATH) [ultrabrain] — Done. TypeScript bundle: SHA-256 PoW worker, 40+ browser probes, POST to `/verify`.

## Wave 2 — Composition (5 parallel)
**Status: COMPLETED**

- **W2-T1**: `internal/server` TLS listener + ClientHello capture [ultrabrain] — Done. Raw-conn TLS interception, ClientHello bytes forwarded to signal/tls.
- **W2-T2**: `internal/proxy` reverse-proxy forwarder [unspecified-high] — Done. `httputil.ReverseProxy` wrapper with request-ID injection and upstream latency metrics.
- **W2-T3**: `internal/challenge` challenge service + /verify [unspecified-high] — Done. Challenge page serving, PoW verification, fingerprint scoring, token issuance.
- **W2-T4**: `internal/pipeline` signal pipeline orchestrator [unspecified-high] — Done. Parallel signal collection, score aggregation, policy evaluation, verdict enforcement.
- **W2-T5**: `policies/default.yaml` + `strict.yaml` [writing] — Done. Both policy files shipped with full signal weight tables.

## Wave 3 — Binaries + SDKs + packaging (7 in 3 sub-batches)
**Status: COMPLETED**

Batch 3a:
- **W3-T1**: `cmd/antiscrapling` main daemon [unspecified-high] — Done. Single binary, all flags wired, graceful shutdown.
- **W3-T2**: `cmd/antiscrapling-cli` admin CLI [unspecified-low] — Done. `config validate`, `token issue`, `token revoke` subcommands.

Batch 3b:
- **W3-T3**: `sdk/node` Express + NestJS [unspecified-high] — Done. `@anti-scrapling/node` package with Express middleware and NestJS guard.
- **W3-T4**: `sdk/python` FastAPI [unspecified-high] — Done. `anti-scrapling` PyPI package with ASGI middleware and Flask decorator.
- **W3-T5**: `deploy/docker` multi-stage image [unspecified-low] — Done. Multi-stage Dockerfile, docker-compose example, ~25-35 MB Alpine image.
- **W3-T7**: `deploy/examples` nginx/Caddy/Traefik [writing] — Done. Reverse-proxy config examples for all three.

Batch 3c:
- **W3-T6**: `deploy/helm` Helm chart [unspecified-low] — Done. Helm chart with values for target, token secret, resource limits, HPA.

## Wave 4 — Adversarial verification + docs + CI (4 in 2 sub-batches)
**Status: COMPLETED**

Batch 4a:
- **W4-T1**: `tests/scrapling/` adversarial E2E harness (real Scrapling) [unspecified-high] — Done. Docker-compose harness spins up Scrapling at pinned commit, verifies block.
- **W4-T2**: `tests/integration/` real-browser pass-through [unspecified-high] — Done. Playwright test suite verifies real Chrome passes the challenge and reaches upstream.
- **W4-T3**: docs finalization [writing] — Done. README, getting-started, policy reference, SDK integration, operations, FAQ.

Batch 4b:
- **W4-T4**: CI gates on adversarial + browser [unspecified-low] — Done. GitHub Actions workflow runs unit tests, lint, adversarial E2E, and browser pass-through on every PR.

## Critical path
W0-T1 → W1-T5 → W2-T3 → W3-T1 → W3-T5 → W4-T1 → W4-T4
