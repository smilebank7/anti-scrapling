# Getting Started

This guide walks you from zero to a running Anti-Scrapling instance in about five minutes. It covers Docker (the fastest path), building from source, and verifying that the protection actually works.

---

## 1. Install

### Option A: Docker (recommended)

Pull the image:

```bash
docker pull ghcr.io/anti-scrapling/anti-scrapling:latest
```

The image is ~25-35 MB (Alpine runtime, statically-linked Go binary).

### Option B: Build from source

Requirements: Go 1.23+, Node.js 20+, Make.

```bash
git clone https://github.com/anti-scrapling/anti-scrapling.git
cd anti-scrapling

# Build the JS challenge bundle first, then the Go binaries
make js-bundle
make build

# Binaries land in bin/
ls bin/
# antiscrapling  antiscrapling-cli
```

---

## 2. Configure

Anti-Scrapling needs two things to start: a target upstream URL and a token signing secret.

### Generate a token secret

```bash
openssl rand -hex 32 > token.key
```

This file is the HMAC secret used to sign pass-tokens. Keep it out of version control.

### Choose a policy file

The repo ships two policies in `policies/`:

| File | Default action | Best for |
|------|---------------|----------|
| `policies/default.yaml` | `challenge` | Most production sites |
| `policies/strict.yaml` | `deny` | Login walls, high-value APIs |

Copy one as your starting point:

```bash
cp policies/default.yaml my-policy.yaml
```

Edit `my-policy.yaml` to set your upstream:

```yaml
listener:
  bind: ":8080"
  target: "http://your-app:3000"   # change this

token:
  secret_file: /etc/anti-scrapling/token.key
  ttl: 24h
  bind_to: [ip, ua, ja3]
```

See [Policy Reference](05-policy-reference.md) for every available field.

---

## 3. Run

### Docker

```bash
docker run -p 8080:8080 \
  -e AS_TARGET=http://your-app:3000 \
  -v $(pwd)/token.key:/etc/anti-scrapling/token.key:ro \
  -v $(pwd)/my-policy.yaml:/etc/anti-scrapling/policy.yaml:ro \
  ghcr.io/anti-scrapling/anti-scrapling:latest
```

The proxy listens on port 8080. Your app is now behind the detection pipeline.

### Binary

```bash
./bin/antiscrapling \
  --config my-policy.yaml \
  --token-secret-file token.key
```

### Docker Compose

A full compose example is in `deploy/docker/`. Copy and start it:

```bash
cp deploy/docker/docker-compose.example.yaml docker-compose.yaml
echo "$(openssl rand -hex 32)" > token.key
docker compose up
```

---

## 4. Verify

### Clean request passes through

A normal browser request should reach your upstream without interruption. Test with a plain curl:

```bash
curl -v http://localhost:8080/
```

This will likely get a challenge response (302 to `/__as/challenge`) because curl has no browser fingerprint. That's expected. A real browser would solve the PoW and receive a pass-token cookie.

To simulate a pre-cleared request (for testing your upstream is reachable), hit the health endpoint directly:

```bash
curl http://localhost:8080/healthz
# → 200 OK
```

### Scraper-like request gets blocked

Test with a curl_cffi-style TLS fingerprint. If you have Python and `curl_cffi` installed:

```python
from curl_cffi import requests

r = requests.get("http://localhost:8080/", impersonate="chrome110")
print(r.status_code)   # expect 403 or 302 to challenge
```

Or simulate a known-bad JA3 with a raw curl that sends a recognizable TLS fingerprint. The daemon logs will show the signal that fired:

```json
{
  "level": "info",
  "time": "2024-01-15T10:23:45Z",
  "msg": "decision",
  "verdict": "deny",
  "reason": "ja3_known_scraper",
  "score": 100,
  "ip": "127.0.0.1",
  "ja3": "771,4865-4866-4867-49195-49199...",
  "path": "/"
}
```

### Browser passes after challenge

Open `http://localhost:8080/` in a real browser. You'll see a brief loading screen while the PoW solves (typically under a second). After that, the browser receives a `__as_pass` cookie and is redirected to the original URL. Subsequent requests from the same browser skip the challenge entirely until the token expires.

---

## 5. View metrics

The daemon exposes Prometheus metrics on port 9091:

```bash
curl http://localhost:9091/metrics | grep anti_scrapling
```

Key metrics:

```
anti_scrapling_decisions_total{verdict="allow"}    1234
anti_scrapling_decisions_total{verdict="challenge"} 89
anti_scrapling_decisions_total{verdict="deny"}      23
anti_scrapling_decision_latency_seconds{quantile="0.99"} 0.0018
```

See [Operations](07-operations.md) for the full metrics list and a Grafana dashboard skeleton.

---

## 6. View the audit log

The admin API exposes recent decisions for false-positive review:

```bash
curl "http://localhost:9090/admin/audit?limit=20" | jq .
```

Each entry includes the full signal map, score, verdict, and request metadata. Use this to understand why a specific request was blocked or challenged.

Filter by time range:

```bash
curl "http://localhost:9090/admin/audit?since=2024-01-15T10:00:00Z" | jq .
```

---

## 7. Tune the policy

Once you've seen real traffic, you'll likely want to adjust thresholds or add custom rules.

### Lower the challenge threshold

If too many real users are getting challenged, raise the threshold:

```yaml
scoring:
  challenge_threshold: 60   # was 40
  deny_threshold: 90        # was 80
```

### Disable a signal

If a signal is causing false positives (e.g., `datacenter_ip` if you serve API clients from cloud environments):

```yaml
scoring:
  weights:
    datacenter_ip: 0   # disabled
```

### Allow a specific path unconditionally

```yaml
policy:
  rules:
    - name: allow-my-api
      match: { path_prefix: "/api/v1/webhook" }
      action: allow
```

Insert this rule before the deny/challenge rules so it takes priority.

### Reload the policy

Policy hot-reload is not yet implemented. Restart the daemon to pick up changes:

```bash
docker compose restart anti-scrapling
# or
kill -SIGTERM $(pgrep antiscrapling) && ./bin/antiscrapling --config my-policy.yaml
```

Hot-reload is planned for v0.2. See [docs/03-build-plan.md](03-build-plan.md).

---

## Next steps

- [Policy Reference](05-policy-reference.md) — every YAML field documented
- [SDK Integration](06-sdk-integration.md) — embed as middleware instead of a proxy
- [Operations](07-operations.md) — production sizing, Grafana dashboards, token rotation
- [FAQ](08-faq.md) — common questions about false positives, CDN compatibility, GDPR
