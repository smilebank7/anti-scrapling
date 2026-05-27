# Anti-Scrapling: Parallel Build Plan

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
- **W0-T1**: Repo skeleton + Go module + shared types + tooling [unspecified-high]
- **W0-T2**: Test-vector corpus (public JA3/JA4 + synthesized FingerprintReport JSON) [unspecified-high]

## Wave 1 — Independent packages (12 parallel)
- **W1-T1**: `internal/signal/tls` JA3/JA4 [ultrabrain]
- **W1-T2**: `internal/signal/http2` JA4H + Akamai H2 [ultrabrain]
- **W1-T3**: `internal/signal/headers` order + UA↔CH [unspecified-high]
- **W1-T4**: `internal/signal/ip` ASN + datacenter + Tor [unspecified-high]
- **W1-T5**: `internal/signal/fingerprint` JS report scorer (CRITICAL PATH) [ultrabrain]
- **W1-T6**: `internal/signal/behavior` telemetry [unspecified-high]
- **W1-T7**: `internal/policy` YAML + CEL [unspecified-high]
- **W1-T8**: `internal/decision` score combiner [unspecified-high]
- **W1-T9**: `internal/token` JWT pass-tokens [unspecified-high]
- **W1-T10**: `internal/cache` memory + Redis [unspecified-low]
- **W1-T11**: `internal/observability` Prom + slog + audit [unspecified-high]
- **W1-T12**: `web/challenge` PoW + fingerprint collector JS (CRITICAL PATH) [ultrabrain]

## Wave 2 — Composition (5 parallel)
- **W2-T1**: `internal/server` TLS listener + ClientHello capture [ultrabrain]
- **W2-T2**: `internal/proxy` reverse-proxy forwarder [unspecified-high]
- **W2-T3**: `internal/challenge` challenge service + /verify [unspecified-high]
- **W2-T4**: `internal/pipeline` signal pipeline orchestrator [unspecified-high]
- **W2-T5**: `policies/default.yaml` + `strict.yaml` [writing]

## Wave 3 — Binaries + SDKs + packaging (7 in 3 sub-batches)
Batch 3a (parallel):
- **W3-T1**: `cmd/antiscrapling` main daemon [unspecified-high]
- **W3-T2**: `cmd/antiscrapling-cli` admin CLI [unspecified-low]

Batch 3b (parallel after 3a):
- **W3-T3**: `sdk/node` Express + NestJS [unspecified-high]
- **W3-T4**: `sdk/python` FastAPI [unspecified-high]
- **W3-T5**: `deploy/docker` multi-stage image [unspecified-low]
- **W3-T7**: `deploy/examples` nginx/Caddy/Traefik [writing]

Batch 3c (after 3b):
- **W3-T6**: `deploy/helm` Helm chart [unspecified-low]

## Wave 4 — Adversarial verification + docs + CI (4 in 2 sub-batches)
Batch 4a (parallel):
- **W4-T1**: `tests/scrapling/` adversarial E2E harness (real Scrapling) [unspecified-high]
- **W4-T2**: `tests/integration/` real-browser pass-through [unspecified-high]
- **W4-T3**: docs finalization [writing]

Batch 4b (after 4a):
- **W4-T4**: CI gates on adversarial + browser [unspecified-low]

## Critical path
W0-T1 → W1-T5 → W2-T3 → W3-T1 → W3-T5 → W4-T1 → W4-T4
