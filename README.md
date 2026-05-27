# Anti-Scrapling

**Block modern scraping tools (Scrapling, curl-impersonate, undetected-playwright, camoufox) at the HTTP layer.**

[![Build](https://img.shields.io/github/actions/workflow/status/anti-scrapling/anti-scrapling/ci.yml?branch=main)](https://github.com/anti-scrapling/anti-scrapling/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Version](https://img.shields.io/github/v/release/anti-scrapling/anti-scrapling)](https://github.com/anti-scrapling/anti-scrapling/releases)

---

## What it does

- **Fingerprints the full stack.** TLS ClientHello (JA3/JA4), HTTP/2 SETTINGS frames, header order, and a JS challenge that probes 40+ browser properties — all combined into a single risk score.
- **Blocks without a CAPTCHA.** Real users pass silently via a proof-of-work challenge and a bound pass-token. Scrapers get a 403.
- **Runs anywhere.** Drop-in Docker reverse proxy, Helm chart for Kubernetes, or SDK middleware for Express, NestJS, FastAPI, and Flask.

---

## How it works

```
                        ┌─────────────────────────────────────────────────────┐
                        │              Detection pipeline                      │
                        │                                                     │
  [client request]      │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
  ─────────────────────►│  │ TLS/JA3  │  │ HTTP/H2  │  │  IP reputation   │  │
                        │  │ JA4/JA4H │─►│ headers  │─►│  ASN / datactr  │  │
                        │  └──────────┘  └──────────┘  └────────┬─────────┘  │
                        │                                        │            │
                        │                               ┌────────▼─────────┐  │
                        │                               │  Policy engine   │  │
                        │                               │  (YAML + CEL)    │  │
                        │                               └────────┬─────────┘  │
                        │                                        │            │
                        │                          ┌─────────────▼──────────┐ │
                        │                          │  Verdict: ALLOW /      │ │
                        │                          │  CHALLENGE / DENY      │ │
                        │                          └─────────────┬──────────┘ │
                        └────────────────────────────────────────┼────────────┘
                                                                 │
                    ┌────────────────────────────────────────────┤
                    │                                            │
              ALLOW │                                  CHALLENGE │                DENY
                    ▼                                            ▼                  ▼
           [upstream app]                          [JS challenge page]          [403]
                                                   PoW + fingerprint
                                                   collect → score
                                                   → pass-token cookie
                                                   → 302 original URL
```

---

## Quick start

### 1. Docker

```bash
docker run -p 8080:8080 \
  -e AS_TARGET=http://your-app:3000 \
  ghcr.io/anti-scrapling/anti-scrapling:latest
```

Your app is now protected at `http://localhost:8080`. All traffic is proxied through the detection pipeline.

### 2. Kubernetes (Helm)

```bash
helm repo add anti-scrapling https://anti-scrapling.github.io/charts
helm install anti-scrapling anti-scrapling/anti-scrapling \
  --set config.target=http://your-app-service:3000 \
  --set config.tokenSecretFile=/etc/anti-scrapling/token.key
```

See [`deploy/helm/README.md`](deploy/helm/README.md) for full values reference.

### 3. SDK middleware

**Node / Express:**

```typescript
import express from 'express';
import { antiScrapling } from '@anti-scrapling/node/express';

const app = express();
app.use(antiScrapling({ daemonUrl: 'http://localhost:9092' }));
app.get('/', (req, res) => res.json({ ok: true }));
app.listen(3000);
```

**Python / FastAPI:**

```python
from fastapi import FastAPI
from anti_scrapling import Client, AntiScraplingMiddleware

app = FastAPI()
client = Client(daemon_url="http://localhost:9092")
app.add_middleware(AntiScraplingMiddleware, client=client)
```

SDK mode requires the daemon running separately. TLS-layer signals (JA3/JA4) are only available when the daemon terminates TLS.

---

## Detection layers

| Layer | What it checks | Signals |
|-------|---------------|---------|
| **TLS** | JA3/JA4 hash, JA4H header fingerprint, H2 SETTINGS frame, QUIC pivot | `ja3_mismatch`, `ja3_known_scraper`, `h2_akamai_mismatch` |
| **HTTP semantics** | Header order, `User-Agent` vs `Sec-CH-UA` consistency, `Sec-Fetch-*` validity, BrowserForge quirks | `ua_ch_mismatch`, `browserforge_quirk`, `header_order_anomaly` |
| **IP reputation** | Datacenter ASN, Tor exit nodes, mobile carrier (trust boost) | `datacenter_ip`, `tor_exit`, `mobile_ip` |
| **JS challenge** | 40+ browser property probes: navigator, WebGL, canvas, audio, fonts, speech, service worker, shadow DOM | `nav_webdriver_set`, `canvas_seeded_noise`, `runtime_console_debug_disabled`, ... |
| **Behavioral** | Resource-blocking patterns, mouse path geometry, Turnstile auto-click timing | `behavior_resource_block`, `behavior_smooth_path`, `behavior_turnstile_clicker` |
| **Honeypots** | Hidden links and form fields; any access triggers an instant ban | (implicit deny) |

---

## Architecture

```
anti-scrapling/
├── cmd/
│   ├── antiscrapling/         # main proxy daemon
│   └── antiscrapling-cli/     # admin CLI
├── internal/
│   ├── server/                # TLS listener + ClientHello capture
│   ├── proxy/                 # reverse-proxy forwarder
│   ├── signal/
│   │   ├── tls/               # JA3/JA4 computation
│   │   ├── http2/             # H2 SETTINGS + pseudo-header order
│   │   ├── headers/           # header order, UA/CH consistency
│   │   ├── ip/                # ASN, datacenter, Tor
│   │   ├── fingerprint/       # JS report parser and scorer
│   │   └── behavior/          # telemetry beacon ingestion
│   ├── policy/                # YAML policy engine + CEL expressions
│   ├── decision/              # score combiner + verdict
│   ├── challenge/             # PoW issuance and verification
│   ├── token/                 # pass-token (JWT) issue/verify
│   ├── cache/                 # in-memory + optional Redis
│   └── observability/         # Prometheus, slog, audit endpoint
├── web/challenge/             # JS bundle served as the challenge page
├── sdk/
│   ├── node/                  # @anti-scrapling/node
│   └── python/                # anti-scrapling (PyPI)
├── deploy/
│   ├── docker/
│   ├── helm/
│   └── examples/              # nginx, Caddy, Traefik configs
└── policies/
    ├── default.yaml           # balanced baseline
    └── strict.yaml            # paranoid mode
```

---

## Comparison

| Feature | Anti-Scrapling | Anubis | Cloudflare Turnstile | CrowdSec |
|---------|---------------|--------|---------------------|----------|
| Open source | Yes (Apache-2.0) | Yes (AGPL-3.0) | No | Yes (MIT) |
| Deployment model | Reverse proxy or SDK middleware | Reverse proxy | CDN / JS snippet | Agent + bouncer |
| TLS fingerprinting (JA3/JA4) | Yes | No | Yes (opaque) | No |
| HTTP/2 fingerprinting | Yes | No | Yes (opaque) | No |
| JS challenge | Yes (PoW + 40+ probes) | Yes (PoW only) | Yes (invisible) | No |
| Behavioral analysis | Yes | No | Yes (opaque) | Partial |
| IP reputation | Yes (embedded GeoLite2-ASN) | No | Yes (opaque) | Yes |
| Multi-protocol fingerprinting | Yes (TLS + H2 + HTTP + JS) | No | No | No |
| Self-hosted | Yes | Yes | No | Yes |
| Scrapling-specific signals | Yes (40+ targeted probes) | No | No | No |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Threat Model](docs/01-threat-model.md) | Full catalog of Scrapling bypass techniques and our counters |
| [Architecture](docs/02-architecture.md) | Design decisions, module boundaries, pipeline diagrams |
| [Build Plan](docs/03-build-plan.md) | Wave-by-wave build plan with completion status |
| [Getting Started](docs/04-getting-started.md) | 5-minute walkthrough: install, configure, verify, tune |
| [Policy Reference](docs/05-policy-reference.md) | Complete YAML schema reference with all fields and signal weights |
| [SDK Integration](docs/06-sdk-integration.md) | Node, Python integration guide with all configuration options |
| [Operations](docs/07-operations.md) | Capacity planning, observability, logging, false-positive debugging |
| [FAQ](docs/08-faq.md) | Common questions about accuracy, privacy, CDN compatibility |
| [Policies](policies/README.md) | Shipped policy files: schema, rules, scoring weights |
| [Docker deploy](deploy/docker/README.md) | Docker image, environment variables, compose example |
| [Helm deploy](deploy/helm/README.md) | Helm chart values reference |
| [Reverse proxy examples](deploy/examples/README.md) | nginx, Caddy, Traefik integration samples |

---

## Project status

**Alpha — active development.** The core detection pipeline, policy engine, JS challenge, and both SDKs are implemented. The project is not yet recommended for production without review of your specific threat model.

### Roadmap

- **v0.2** — Redis cache backend, hot-reload policy without restart
- **v0.3** — Distributed decision sharing across instances
- **v0.4** — ML-based behavioral scoring (replace weighted rules)
- **v1.0** — Production-hardened, stable API, full test coverage

---

## Contributing

1. Fork the repo and create a branch from `main`.
2. Run `make test` and `make lint` before opening a PR.
3. All `internal/types/*.go` exports are frozen — adding fields is fine, removing or renaming is not.
4. Tests must use real data from `testdata/` wherever possible.
5. Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).

---

## License

Apache-2.0. See [LICENSE](LICENSE).

---

## Acknowledgements

Anti-Scrapling builds on ideas and prior art from:

- [Anubis](https://github.com/TecharoHQ/anubis) — PoW challenge design and inspiration for the overall approach
- [FoxIO JA4+](https://github.com/FoxIO-LLC/ja4) — JA4 fingerprint specification
- [salesforce/ja3](https://github.com/salesforce/ja3) — original JA3 fingerprint specification
- [FingerprintJS](https://github.com/fingerprintjs/fingerprintjs) — browser fingerprinting techniques
- [CreepJS](https://github.com/abrahamjuliot/creepjs) — comprehensive headless detection probes
- [BotD](https://github.com/fingerprintjs/BotD) — bot detection signal catalog
- [D4Vinci/Scrapling](https://github.com/D4Vinci/Scrapling) — the adversary we model against
