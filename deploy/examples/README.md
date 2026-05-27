# Reverse Proxy Integration Examples

anti-scrapling ships as a standalone HTTP daemon. These examples show two ways to put it in front of your application: **standalone** (AS is the front door) and **sidecar** (your existing proxy consults AS as an auth gate).

## Patterns at a glance

| | Standalone | Sidecar |
|---|---|---|
| Who terminates TLS | nginx / Caddy / Traefik | nginx / Caddy / Traefik |
| Who routes requests | anti-scrapling | nginx / Caddy / Traefik |
| Challenge page served by | anti-scrapling | anti-scrapling (proxied back) |
| Extra latency per request | none | ~1ms (loopback sub-request) |
| Requires AS v1.1 | no | yes (`/v1/decide`) |
| Best for | new deployments | adding AS to an existing stack |

---

## Standalone

anti-scrapling sits directly behind the TLS terminator. The proxy's only job is to unwrap TLS and forward the real client IP. AS handles everything else: fingerprinting, challenge pages, upstream forwarding.

```
client -> proxy:443 (TLS) -> anti-scrapling:8080 -> upstream
```

**When to use this:**
- You're starting fresh and don't have an existing proxy config to preserve.
- You want the simplest possible setup.
- You need AS to control the full response (custom challenge pages, redirects).

**When it's awkward:**
- You already have complex nginx/Caddy routing rules you don't want to move into AS.
- You need per-route middleware (caching, auth) that lives in the proxy layer.

---

## Sidecar

Your existing proxy stays in charge. Before forwarding each request to the backend, it fires a sub-request to AS's `/v1/decide` endpoint. AS returns 200 (allow), 401 (challenge), or 403 (block). The proxy acts on that verdict.

```
client -> proxy:443 -> sub-request -> AS:8080/v1/decide
                    -> 200 -> backend
                    -> 401/403 -> AS challenge page (proxied back)
```

**When to use this:**
- You have an existing nginx or Caddy deployment you don't want to restructure.
- You want per-route granularity: protect `/api/*` but skip `/static/*`.
- You need proxy-layer features (caching, rate-limiting) to run alongside AS.

**When it's awkward:**
- You need AS to modify response headers from the backend (it can't in sidecar mode).
- The extra loopback hop matters at very high request rates (>50k RPS on a single host).

> **Note:** The sidecar pattern requires the `/v1/decide` endpoint, which ships in anti-scrapling v1.1. The nginx and Caddy sidecar configs are ready to use once that version is available.

---

## Files

```
nginx/
  standalone.conf          nginx as TLS terminator, AS as front door
  sidecar.conf             nginx auth_request to AS /v1/decide

caddy/
  Caddyfile.standalone     Caddy reverse_proxy to AS (auto-HTTPS)
  Caddyfile.sidecar        Caddy forward_auth to AS /v1/decide

traefik/
  docker-compose.yaml      Traefik + AS + dummy upstream, all in Docker
  dynamic.yaml             File provider config (use outside Docker)
```

---

## TLS termination

All examples terminate TLS at the proxy layer, not inside anti-scrapling. This is intentional:

- Proxies like Caddy handle ACME cert renewal automatically.
- TLS offloading at the edge means AS and the upstream communicate over plain HTTP on loopback, which is faster and simpler to debug.
- If you need end-to-end TLS (e.g. compliance requirements), configure your upstream with a self-signed cert and point AS's upstream URL at `https://`.

---

## Performance notes

- **Keepalive connections** between the proxy and AS matter. All examples configure keepalive. Without it, each request pays a TCP handshake to loopback (~0.1ms, but it adds up).
- **Sidecar latency** is roughly one extra loopback round-trip per request. On a modern host that's under 1ms. At 10k RPS it's measurable but rarely the bottleneck.
- **Compression** belongs at the proxy layer (nginx `gzip`, Caddy `encode gzip`), not inside AS. Compressing before AS sees the response body would break AS's ability to inject challenge scripts.

---

## Quick smoke tests

Replace `example.com` with your actual domain or `localhost` as appropriate.

### nginx standalone

```bash
# Reload config without downtime
nginx -t && nginx -s reload

# Verify TLS and that AS is responding
curl -I https://example.com/

# Check that a known-bad User-Agent gets challenged
curl -I -A "python-scrapling/1.0" https://example.com/
```

### nginx sidecar

```bash
nginx -t && nginx -s reload

# Confirm the auth sub-request location is internal-only
curl http://localhost/__as_check
# Expected: 404 (internal locations reject external requests)

# Normal request should pass through to backend
curl -I https://example.com/
```

### Caddy standalone

```bash
# Validate Caddyfile syntax
caddy validate --config Caddyfile.standalone

# Start (Caddy fetches a cert automatically)
caddy run --config Caddyfile.standalone

curl -I https://example.com/
```

### Caddy sidecar

```bash
caddy validate --config Caddyfile.sidecar
caddy run --config Caddyfile.sidecar

# forward_auth fires on every request; confirm backend is reached
curl -v https://example.com/ 2>&1 | grep "< HTTP"
```

### Traefik (Docker)

```bash
cd traefik/
docker compose up -d

# Traefik dashboard (if enabled)
open http://localhost:8081

# Confirm routing
curl -I https://example.com/

# Watch AS logs
docker compose logs -f antiscrapling
```

### Traefik (file provider, no Docker)

```bash
# Point Traefik at dynamic.yaml in traefik.yaml, then:
traefik --configFile=traefik.yaml

# Confirm the router is active
curl http://localhost:8081/api/http/routers | jq '.[] | select(.name=="antiscrapling")'
```

---

## Anti-scrapling ports reference

| Port | Purpose |
|------|---------|
| 8080 | Main proxy (receives traffic from the proxy layer) |
| 9090 | Prometheus metrics (`/metrics`) |
| 9091 | Admin API (`/v1/policy`, `/v1/rules`, etc.) |

Keep 9090 and 9091 off the public internet. All examples either bind them to loopback or restrict access via IP allowlist.
