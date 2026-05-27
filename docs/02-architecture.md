# Anti-Scrapling: Architecture Decision

## Product positioning

**Anti-Scrapling** is a security middleware that defends HTTP services against modern scraping toolchains (Scrapling, curl-impersonate, undetected-playwright, camoufox, etc.). It positions as **open-source security software**, comparable to Anubis / CrowdSec but specifically tuned against the Scrapling threat profile documented in `01-threat-model.md`.

## Deployment modes

The product supports two integration modes, both backed by the same decision core:

### Mode A — Reverse proxy / sidecar
```
[client] → [Anti-Scrapling proxy:8080] → [origin app]
```
- Single Go binary, Docker image
- Listens on `BIND`, forwards to `TARGET`
- All detection layers active
- TLS termination optional (recommended)
- Ideal for ops/devops teams; drop-in deployment

### Mode B — SDK middleware
```
[client] → [your app w/ anti-scrapling SDK as middleware] → [route handler]
```
- Express/NestJS adapter (Node SDK)
- FastAPI/Starlette adapter (Python SDK)
- Go `net/http` adapter (Go SDK)
- Layer 1 (TLS) detection unavailable in SDK mode unless the listener is TLS-aware; falls back to L2+ detection
- Ideal for app developers; finer-grained per-route policy

## Core language: **Go**

| Criterion | Go | Rust | Node.js |
|---|---|---|---|
| Single-binary distribution | ★★★★★ | ★★★★ | ★★ |
| HTTP/2 stdlib (server) | ★★★★★ | ★★★ | ★★★ |
| TLS ClientHello capture | ★★★★ | ★★★★★ | ★★ |
| Cross-platform | ★★★★★ | ★★★★ | ★★★ |
| Plugin ecosystem (Caddy/CrowdSec parity) | ★★★★★ | ★★★ | ★★ |
| Container image size | ★★★★ | ★★★★★ | ★★ |

**Decision: Go for the core proxy/daemon.** SDK adapters in their native language (TypeScript, Python).

## Module boundaries

```
anti-scrapling/
├── cmd/
│   ├── antiscrapling/         # main proxy daemon (Mode A)
│   └── antiscrapling-cli/     # admin CLI: config validate, token issue, etc.
├── internal/
│   ├── server/                # HTTP listener, TLS termination, raw-conn capture
│   ├── proxy/                 # reverse-proxy forwarder
│   ├── signal/                # signal collectors
│   │   ├── tls/               # JA3/JA4 from ClientHello
│   │   ├── http2/             # H2 SETTINGS + pseudo-header order
│   │   ├── headers/           # header order, UA/CH consistency
│   │   ├── ip/                # IP reputation, ASN
│   │   ├── fingerprint/       # JS-collected fingerprint parser/scorer
│   │   └── behavior/          # telemetry beacon ingestion
│   ├── policy/                # YAML policy engine + CEL expressions
│   ├── decision/              # scoring + verdict combine
│   ├── challenge/             # JS challenge issuance + verification
│   │   ├── pow/               # proof-of-work (SHA-256 like Anubis)
│   │   └── fingerprint/       # fingerprint collection JS
│   ├── token/                 # pass-token (JWT) issue/verify
│   ├── cache/                 # decision cache (in-memory + Redis optional)
│   └── observability/         # Prometheus metrics, structured logs, audit
├── web/                       # client-side assets
│   ├── challenge/             # challenge page HTML + JS bundle
│   └── widget/                # embeddable widget for Mode B SDK
├── sdk/
│   ├── node/                  # @anti-scrapling/node (Express, NestJS, FastAPI-via-py)
│   └── python/                # anti-scrapling-py (FastAPI, Flask, Django)
├── deploy/
│   ├── docker/                # Dockerfile + compose example
│   ├── helm/                  # Helm chart
│   └── examples/              # nginx/Caddy/Traefik samples
├── docs/                      # markdown documentation
├── tests/
│   ├── unit/                  # Go unit tests
│   ├── integration/           # end-to-end with real browsers
│   └── scrapling/             # adversarial tests: spin up Scrapling, verify block
└── policies/
    ├── default.yaml           # ship-with-product baseline
    └── strict.yaml            # paranoid mode
```

## Decision pipeline

```
┌──────────────┐
│ Raw conn     │  capture TLS ClientHello bytes
└──────┬───────┘
       v
┌──────────────┐
│ TLS signal   │  → JA3, JA4 hashes
└──────┬───────┘
       v
┌──────────────┐
│ HTTP layer   │  → JA4H, header-order, UA/CH consistency
└──────┬───────┘
       v
┌──────────────┐
│ IP layer     │  → ASN, datacenter, Tor, prior-decision cache
└──────┬───────┘
       v
┌──────────────┐
│ Policy match │  match against YAML rules, compute risk score
└──────┬───────┘
       v
┌──────────────┐
│ Verdict      │  → ALLOW | CHALLENGE | DENY
└──────┬───────┘
       v
┌──────────────┐
│ Enforce      │  → forward / 403 / serve challenge page
└──────────────┘
```

For CHALLENGE verdict:
```
┌─────────────────┐
│ Serve challenge │  HTML + JS bundle
└────────┬────────┘
         v
┌─────────────────┐
│ Client solves   │  PoW + collect fingerprint
└────────┬────────┘
         v
┌─────────────────┐
│ POST /verify    │  fingerprint + PoW solution
└────────┬────────┘
         v
┌─────────────────┐
│ Score JS sigs   │  navigator/webgl/canvas/audio/timing/headless probes
└────────┬────────┘
         v
┌─────────────────┐
│ Issue pass-tok  │  signed JWT in cookie, bound to fingerprint+IP+UA
└────────┬────────┘
         v
┌─────────────────┐
│ Re-request orig │  302 to original URL
└─────────────────┘
```

## Policy file (YAML)

```yaml
# anti-scrapling.yaml
version: 1
listener:
  bind: ":8080"
  target: "http://upstream:3000"
  tls:
    cert: /etc/anti-scrapling/cert.pem
    key:  /etc/anti-scrapling/key.pem

token:
  secret_file: /etc/anti-scrapling/token.key
  ttl: 24h
  bind_to: [ip, ua, ja3]   # fingerprint binding

policy:
  default: challenge

  rules:
    - name: allow-healthcheck
      match: { path: "/healthz" }
      action: allow

    - name: deny-known-scrapers
      match: { ja3_in: ["@curl_cffi/*", "@python-requests"] }
      action: deny
      reason: "TLS signature matches known scraper library"

    - name: deny-datacenter-ip
      match: { ip_category: datacenter, score: ">=80" }
      action: deny

    - name: challenge-suspicious
      match: { score: ">=50" }
      action: challenge

    - name: allow-verified
      match: { has_valid_token: true }
      action: allow

scoring:
  weights:
    ja3_mismatch: 40
    h2_mismatch: 35
    header_order_anomaly: 20
    ua_ch_mismatch: 25
    datacenter_ip: 30
    no_referer: 5
    google_referer_anomaly: 10
    fingerprint_lie: 50
    headless_signal: 60
    behavior_anomaly: 15

challenge:
  pow_difficulty: 4    # leading zero bits (Anubis default)
  collect_fingerprint: true
```

## Token format

JWT (HS256), claims:
```json
{
  "sub": "fingerprint-sha256",
  "iat": 1700000000,
  "exp": 1700086400,
  "ip": "1.2.3.4",
  "ua": "Mozilla/5.0...",
  "ja3": "771,4865-4866...",
  "score": 12,
  "ver": 1
}
```

Cookie name: `__as_pass`, `HttpOnly; Secure; SameSite=Lax`.

## Observability

- **Prometheus metrics**: `anti_scrapling_decisions_total{verdict, reason}`, histogram of decision latency
- **Structured JSON logs**: per-request with all signals + verdict
- **Audit endpoint**: `/admin/audit?since=…` returns recent decisions for FP review
- **Health/ready**: `/healthz`, `/readyz`

## Performance targets

- Decision latency P99: <2ms (Mode A pre-challenge)
- Challenge solve time (PoW difficulty 4): ~500ms client-side
- Memory: <100MB resident
- Throughput: >10k req/s on a single core (Go)

## Distribution

1. **Docker image**: `ghcr.io/yourorg/anti-scrapling:latest` (~15MB Alpine)
2. **Single binary**: `antiscrapling` (~12MB statically linked)
3. **Node SDK**: `@anti-scrapling/node` on npm
4. **Python SDK**: `anti-scrapling` on PyPI
5. **Helm chart**: `helm install anti-scrapling …`

## Out of scope (v1)

- Full ML scoring (use weighted rules)
- Mobile app SDK
- Distributed cluster mode (Redis cache is the extension point)
- Visual CAPTCHA fallback (PoW + invisible fingerprint only)
- Active probing of suspicious IPs (passive only)
