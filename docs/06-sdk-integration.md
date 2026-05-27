# SDK Integration

The Anti-Scrapling SDKs let you embed bot detection directly into your application as middleware, without running a separate reverse proxy in front of it. The SDK calls the daemon's `/v1/decide` endpoint over HTTP and enforces the verdict before your route handler runs.

**Trade-off vs. proxy mode:** SDK mode can't collect TLS-layer signals (JA3/JA4) unless your application terminates TLS and exposes the raw ClientHello. In practice, SDK mode relies on HTTP-layer, IP, and JS fingerprint signals. This is still effective against most scrapers.

---

## Prerequisites

The daemon must be running and reachable from your application. Start it with the `--decide-bind` flag to expose the decision API:

```bash
./bin/antiscrapling \
  --config policies/default.yaml \
  --decide-bind :9092
```

Or with Docker:

```bash
docker run -p 9092:9092 \
  -e AS_TARGET=http://your-app:3000 \
  -e AS_DECIDE_BIND=:9092 \
  ghcr.io/anti-scrapling/anti-scrapling:latest
```

The daemon's proxy port (8080) is not used in SDK mode. Only the decision API port (9092) matters.

---

## Node.js SDK

### Install

```bash
npm install @anti-scrapling/node
```

### Express middleware

```typescript
import express from 'express';
import { antiScrapling } from '@anti-scrapling/node/express';

const app = express();

app.use(antiScrapling({
  daemonUrl: 'http://localhost:9092',
  timeoutMs: 200,
  failOpen: true,
}));

app.get('/', (req, res) => {
  res.json({ hello: 'world' });
});

app.listen(3000);
```

The middleware intercepts every request, calls `/v1/decide`, and enforces the verdict:

- `ALLOW` — request proceeds to your route handler
- `CHALLENGE` — 302 redirect to `/__as/challenge?origin=<original-url>`
- `DENY` — 403 with a plain-text reason

### Express: per-route protection

Apply the middleware to specific routes instead of globally:

```typescript
import { antiScrapling } from '@anti-scrapling/node/express';

const botGuard = antiScrapling({ daemonUrl: 'http://localhost:9092' });

// Only protect the scrape-sensitive endpoints
app.get('/api/products', botGuard, (req, res) => { ... });
app.get('/api/prices',   botGuard, (req, res) => { ... });
```

### NestJS guard

```typescript
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AntiScraplingGuard } from '@anti-scrapling/node/nestjs';

@Module({
  providers: [
    {
      provide: APP_GUARD,
      useFactory: () => new AntiScraplingGuard({
        daemonUrl: 'http://localhost:9092',
        timeoutMs: 200,
        failOpen: true,
      }),
    },
  ],
})
export class AppModule {}
```

The guard runs before every controller method. To exempt specific routes, use the `@SkipAntiScrapling()` decorator:

```typescript
import { SkipAntiScrapling } from '@anti-scrapling/node/nestjs';

@Controller('health')
export class HealthController {
  @Get()
  @SkipAntiScrapling()
  check() {
    return { status: 'ok' };
  }
}
```

### Node SDK configuration options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `daemonUrl` | string | required | Base URL of the daemon's decision API, e.g. `http://localhost:9092` |
| `timeoutMs` | number | `200` | Timeout for the `/v1/decide` HTTP call in milliseconds. If the daemon doesn't respond within this window, `failOpen` determines the outcome. |
| `failOpen` | boolean | `true` | `true` = allow the request if the daemon is unreachable. `false` = deny. Set to `false` only if you're confident the daemon has high availability. |
| `challengeUrl` | string | `/__as/challenge` | URL to redirect to on a CHALLENGE verdict. The original URL is appended as `?origin=<url>`. |

---

## Python SDK

### Install

```bash
# FastAPI / Starlette (ASGI)
pip install "anti-scrapling[fastapi]"

# Flask (WSGI)
pip install "anti-scrapling[flask]"

# Bare client only (no framework adapters)
pip install "anti-scrapling"
```

### FastAPI / Starlette ASGI middleware

```python
from fastapi import FastAPI
from anti_scrapling import Client, AntiScraplingMiddleware

app = FastAPI()

client = Client(
    daemon_url="http://localhost:9092",
    timeout=0.2,
    fail_open=True,
)

app.add_middleware(AntiScraplingMiddleware, client=client)

@app.get("/api/data")
def data():
    return {"ok": True}
```

The middleware wraps the ASGI app. Every request passes through the decision pipeline before reaching your route.

Custom challenge redirect URL:

```python
app.add_middleware(
    AntiScraplingMiddleware,
    client=client,
    challenge_url="/bot-gate",
)
```

### FastAPI: per-route dependency

For finer-grained control, use a FastAPI dependency instead of global middleware:

```python
from fastapi import FastAPI, Depends
from anti_scrapling import Client, require_clean

app = FastAPI()
client = Client(daemon_url="http://localhost:9092")

@app.get("/api/prices", dependencies=[Depends(require_clean(client))])
def prices():
    return {"price": 9.99}
```

`require_clean` raises `HTTPException(403)` on DENY and `HTTPException(302)` on CHALLENGE.

### Flask decorator

```python
from flask import Flask, jsonify
from anti_scrapling import Client, flask_middleware

app = Flask(__name__)
client = Client(daemon_url="http://localhost:9092")

@app.route("/api/data")
@flask_middleware(client)
def data():
    return jsonify({"ok": True})
```

The decorator wraps the route function. It calls the daemon synchronously (blocking) before the route handler runs.

### Flask: global middleware

To protect all routes:

```python
from flask import Flask
from anti_scrapling import Client, FlaskMiddleware

app = Flask(__name__)
client = Client(daemon_url="http://localhost:9092")
app = FlaskMiddleware(app, client=client)
```

### Python SDK configuration options

```python
Client(
    daemon_url="http://localhost:9092",   # daemon base URL
    timeout=0.2,                           # per-request timeout in seconds
    fail_open=True,                        # True = allow on daemon error
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `daemon_url` | str | required | Base URL of the daemon's decision API |
| `timeout` | float | `0.2` | Per-request timeout in seconds |
| `fail_open` | bool | `True` | `True` = allow on daemon error; `False` = deny |

### Sync vs. async

The client exposes both sync and async methods:

```python
# Sync (Flask, Django, WSGI)
decision = client.decide(request)

# Async (FastAPI, Starlette, ASGI)
decision = await client.decide_async(request)
```

The ASGI middleware uses `decide_async` automatically. The Flask decorator uses `decide`.

---

## Token handling

When a client passes the JS challenge, the daemon issues a `__as_pass` JWT cookie. On subsequent requests, the SDK forwards this cookie to the daemon's `/v1/decide` endpoint. The daemon validates the token and returns `ALLOW` without re-running the full pipeline.

The SDK handles this automatically. You don't need to read or write the cookie yourself.

**Token binding:** The token is bound to the client's IP, User-Agent, and JA3 hash (configurable via `token.bind_to` in the policy). If any bound dimension changes, the token is rejected and the client must re-challenge.

**Token TTL:** Controlled by `token.ttl` in the policy. Default is 24h. After expiry, the next request triggers a new challenge.

---

## Custom rules in SDK mode

Custom rules work the same way in SDK mode as in proxy mode. The daemon evaluates the policy YAML on every `/v1/decide` call.

To add a rule that only applies to SDK-mode traffic (e.g., to allow a specific API key header):

```yaml
policy:
  rules:
    - name: allow-internal-service
      match:
        expr: "request.headers['X-Service-Token'] == 'my-internal-token'"
      action: allow
```

The SDK forwards all request headers to the daemon, so custom header-based rules work as expected.

---

## Decision API reference

The SDK calls `POST /v1/decide` on the daemon. The request and response format is documented here for custom integrations.

### Request

```http
POST /v1/decide HTTP/1.1
Content-Type: application/json

{
  "method": "GET",
  "path": "/api/products",
  "host": "example.com",
  "remote_addr": "1.2.3.4",
  "headers": {
    "User-Agent": "Mozilla/5.0...",
    "Accept": "text/html...",
    "Cookie": "__as_pass=eyJ..."
  }
}
```

### Response

```json
{
  "verdict": "allow",
  "reason": "valid_token",
  "score": 0,
  "signals": {}
}
```

Possible `verdict` values: `allow`, `challenge`, `deny`.

On `challenge`, the response also includes:

```json
{
  "verdict": "challenge",
  "challenge_url": "/__as/challenge?origin=%2Fapi%2Fproducts",
  "score": 45,
  "signals": {
    "datacenter_ip": 30,
    "header_order_anomaly": 20
  }
}
```

---

## Error handling and fail-open

If the daemon is unreachable or returns a non-200 response, the SDK behavior depends on `failOpen`:

- `failOpen: true` (default) — the request is allowed through. Your app continues to serve traffic even if the daemon is down. Recommended for most deployments.
- `failOpen: false` — the request is denied with a 503. Use this only if you'd rather drop traffic than risk serving scrapers during a daemon outage.

Log the daemon errors regardless of `failOpen` setting. The SDK emits a structured log entry on every daemon failure:

```json
{
  "level": "warn",
  "msg": "anti-scrapling daemon unreachable",
  "daemon_url": "http://localhost:9092",
  "error": "connection refused",
  "fail_open": true
}
```
