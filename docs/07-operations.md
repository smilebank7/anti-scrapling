# Operations

This guide covers running Anti-Scrapling in production: sizing, observability, logging, health checks, false-positive debugging, and operational procedures.

---

## Capacity planning

### Sizing

Anti-Scrapling is designed to be lightweight. The decision pipeline runs in under 2ms P99 for pre-challenge requests (no JS fingerprint scoring). The JS fingerprint scoring path (after a client submits a challenge response) takes 5-15ms depending on the number of signals.

| Deployment size | Recommended resources | Expected throughput |
|----------------|----------------------|---------------------|
| Small (< 500 req/s) | 0.25 CPU, 64 MB RAM | Comfortable headroom |
| Medium (500-5k req/s) | 1 CPU, 256 MB RAM | ~10k req/s per core |
| Large (> 5k req/s) | 2+ CPU, 512 MB RAM | Scale horizontally |

These numbers assume the in-memory cache backend. With Redis, add ~1ms per cache lookup.

### Horizontal scaling

Anti-Scrapling is stateless except for the decision cache. To scale horizontally:

1. Switch the cache backend to Redis so all instances share the same decision cache.
2. Put a load balancer in front of the instances.
3. Ensure all instances use the same `token.key` file so pass-tokens issued by one instance are accepted by others.

```yaml
cache:
  backend: redis
  redis:
    addr: "redis:6379"
  ttl_seconds: 300
```

### Memory

The in-memory cache holds recent decisions. At 60-second TTL and 10k unique IPs per minute, expect ~50-100 MB for the cache alone. The GeoLite2-ASN database adds ~10 MB at startup.

Total resident memory: typically 50-150 MB depending on traffic volume and cache TTL.

---

## Observability

### Prometheus metrics

The daemon exposes metrics at `http://<host>:9091/metrics`. All metrics are prefixed with `anti_scrapling_`.

#### Decision metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `anti_scrapling_decisions_total` | Counter | `verdict` (`allow`, `challenge`, `deny`), `reason` | Total decisions by verdict and reason |
| `anti_scrapling_decision_latency_seconds` | Histogram | `verdict` | Decision pipeline latency |
| `anti_scrapling_challenge_solves_total` | Counter | `result` (`pass`, `fail`) | Challenge solve attempts |
| `anti_scrapling_tokens_issued_total` | Counter | | Pass-tokens issued |
| `anti_scrapling_tokens_rejected_total` | Counter | `reason` | Pass-tokens rejected (expired, tampered, binding mismatch) |

#### Signal metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `anti_scrapling_signal_fired_total` | Counter | `signal` | Times each signal fired across all requests |
| `anti_scrapling_score_histogram` | Histogram | | Distribution of risk scores |

#### Cache metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `anti_scrapling_cache_hits_total` | Counter | | Cache hits (decision served from cache) |
| `anti_scrapling_cache_misses_total` | Counter | | Cache misses (full pipeline run) |

#### Infrastructure metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `anti_scrapling_upstream_latency_seconds` | Histogram | `status_code` | Upstream response latency |
| `anti_scrapling_upstream_errors_total` | Counter | `error` | Upstream connection errors |

### Grafana dashboard skeleton

The following panel definitions can be imported into Grafana. Replace `$datasource` with your Prometheus data source name.

```json
{
  "panels": [
    {
      "title": "Decisions per second",
      "type": "timeseries",
      "targets": [
        {
          "expr": "sum by (verdict) (rate(anti_scrapling_decisions_total[1m]))",
          "legendFormat": "{{verdict}}"
        }
      ]
    },
    {
      "title": "Decision latency P99",
      "type": "timeseries",
      "targets": [
        {
          "expr": "histogram_quantile(0.99, rate(anti_scrapling_decision_latency_seconds_bucket[5m]))",
          "legendFormat": "P99"
        },
        {
          "expr": "histogram_quantile(0.50, rate(anti_scrapling_decision_latency_seconds_bucket[5m]))",
          "legendFormat": "P50"
        }
      ]
    },
    {
      "title": "Top signals fired",
      "type": "bargauge",
      "targets": [
        {
          "expr": "topk(10, sum by (signal) (rate(anti_scrapling_signal_fired_total[5m])))",
          "legendFormat": "{{signal}}"
        }
      ]
    },
    {
      "title": "Score distribution",
      "type": "heatmap",
      "targets": [
        {
          "expr": "sum(rate(anti_scrapling_score_histogram_bucket[5m])) by (le)",
          "legendFormat": "{{le}}"
        }
      ]
    },
    {
      "title": "Cache hit rate",
      "type": "stat",
      "targets": [
        {
          "expr": "rate(anti_scrapling_cache_hits_total[5m]) / (rate(anti_scrapling_cache_hits_total[5m]) + rate(anti_scrapling_cache_misses_total[5m]))",
          "legendFormat": "Hit rate"
        }
      ]
    },
    {
      "title": "Challenge solve rate",
      "type": "stat",
      "targets": [
        {
          "expr": "rate(anti_scrapling_challenge_solves_total{result='pass'}[5m]) / rate(anti_scrapling_challenge_solves_total[5m])",
          "legendFormat": "Pass rate"
        }
      ]
    }
  ]
}
```

---

## Logging

Anti-Scrapling uses Go's `slog` package with JSON output. Every log line is a valid JSON object.

### Log levels

| Level | When |
|-------|------|
| `debug` | Per-signal details (disabled by default; enable with `--log-level debug`) |
| `info` | Per-request decision |
| `warn` | Daemon errors, cache failures, upstream errors |
| `error` | Startup failures, fatal configuration errors |

### Per-request decision log

Every request produces one `info`-level log line:

```json
{
  "level": "info",
  "time": "2024-01-15T10:23:45.123Z",
  "msg": "decision",
  "request_id": "01HN2X3Y4Z5A6B7C8D9E0F1G2H",
  "method": "GET",
  "path": "/api/products",
  "host": "example.com",
  "remote_addr": "1.2.3.4",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...",
  "verdict": "deny",
  "reason": "ja3_known_scraper",
  "score": 100,
  "rule": "deny-known-scraper-libs",
  "latency_ms": 0.8,
  "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392...",
  "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
  "ip_category": "datacenter",
  "ip_asn": "AS16509",
  "signals": {
    "ja3_known_scraper": 100,
    "datacenter_ip": 30
  }
}
```

Key fields:

| Field | Description |
|-------|-------------|
| `request_id` | Unique request identifier (ULID). Use this to correlate with upstream logs. |
| `verdict` | `allow`, `challenge`, or `deny` |
| `reason` | The signal or rule name that drove the verdict |
| `score` | Total risk score |
| `rule` | Name of the matching policy rule |
| `latency_ms` | Decision pipeline latency in milliseconds |
| `ja3` | JA3 fingerprint hash |
| `ja4` | JA4 fingerprint hash |
| `ip_category` | IP classification |
| `ip_asn` | ASN of the client IP |
| `signals` | Map of signal names to their fired weights |

### Shipping logs

The daemon writes to stdout. Use your container runtime or log shipper to forward to your log aggregation system:

```bash
# Docker: forward to a log driver
docker run --log-driver=fluentd --log-opt fluentd-address=localhost:24224 ...

# Kubernetes: logs are collected by the node's log agent automatically
# Use a DaemonSet (Fluentd, Fluent Bit, Vector) to ship to your backend
```

---

## Audit log endpoint

The admin API exposes recent decisions for false-positive review:

```
GET http://localhost:9090/admin/audit
```

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `limit` | Number of entries to return (default 100, max 1000) |
| `since` | ISO-8601 timestamp; return entries after this time |
| `verdict` | Filter by verdict: `allow`, `challenge`, `deny` |
| `ip` | Filter by client IP |

Example:

```bash
# Last 50 denied requests
curl "http://localhost:9090/admin/audit?verdict=deny&limit=50" | jq .

# All decisions in the last hour
curl "http://localhost:9090/admin/audit?since=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ)" | jq .
```

The audit endpoint is on the admin port (9090), which should not be exposed publicly. Restrict access with a firewall rule or network policy.

---

## Health and readiness probes

| Endpoint | Port | Description |
|----------|------|-------------|
| `GET /healthz` | 8080 | Liveness probe. Returns 200 if the process is running. |
| `GET /readyz` | 8080 | Readiness probe. Returns 200 when the daemon is ready to serve traffic (GeoLite2 loaded, cache connected). Returns 503 during startup or if Redis is unreachable. |

Kubernetes probe configuration:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 5
```

---

## Common false-positive scenarios

### Mobile users getting challenged repeatedly

**Symptom:** Mobile users on carrier networks get challenged on every visit because their IP changes between requests, invalidating the pass-token.

**Diagnosis:** Check the audit log for `tokens_rejected` with `reason: ip_binding_mismatch` from mobile ASNs.

**Fix:** Remove `ip` from `token.bind_to`:

```yaml
token:
  bind_to: [ua, ja3]   # removed ip
```

This weakens token binding slightly but eliminates false positives for mobile users.

### Corporate proxy users blocked

**Symptom:** Users behind a corporate proxy get `datacenter_ip` signal fired because the proxy's IP is in a cloud ASN.

**Diagnosis:** Check the audit log for `ip_category: datacenter` with `ip_asn` matching your corporate proxy provider.

**Fix:** Either set `datacenter_ip` weight to 0, or add an allow rule for the specific ASN:

```yaml
- name: allow-corporate-proxy
  match:
    expr: "ip.asn == 'AS12345'"
  action: allow
```

Or reduce the weight so datacenter IPs alone don't trigger a challenge:

```yaml
scoring:
  weights:
    datacenter_ip: 0
```

### Headless browser used by your own automation

**Symptom:** Your own CI/CD or monitoring scripts get blocked because they use Playwright or Puppeteer.

**Fix:** Issue a long-lived pass-token for your automation and include it in requests:

```bash
./bin/antiscrapling-cli token issue \
  --ttl 8760h \
  --bind-to none \
  --reason "CI automation"
# → eyJhbGciOiJIUzI1NiJ9...
```

Set the token as a cookie in your automation:

```python
# Playwright
context.add_cookies([{
    "name": "__as_pass",
    "value": "eyJhbGciOiJIUzI1NiJ9...",
    "domain": "example.com",
    "path": "/",
}])
```

### API clients from cloud environments

**Symptom:** Legitimate API clients running in AWS/GCP/Azure get `datacenter_ip` signal.

**Fix:** If you serve API clients from cloud environments, disable the `datacenter_ip` signal or add an allow rule for authenticated API paths:

```yaml
- name: allow-api-with-token
  match:
    expr: "request.path.startsWith('/api/') && has_valid_token"
  action: allow
```

---

## Updating policies

Policy hot-reload is not yet implemented. To apply policy changes:

1. Edit your policy YAML file.
2. Validate the new policy:
   ```bash
   ./bin/antiscrapling-cli config validate --config my-policy.yaml
   ```
3. Restart the daemon:
   ```bash
   # Docker Compose
   docker compose restart anti-scrapling

   # Kubernetes
   kubectl rollout restart deployment/anti-scrapling

   # Systemd
   systemctl restart anti-scrapling
   ```

Hot-reload (SIGHUP) is planned for v0.2.

---

## Token rotation

The token signing secret (`token.key`) should be rotated periodically. Rotating the secret invalidates all existing pass-tokens, so all clients will need to re-solve the challenge after rotation.

### Rotation procedure

1. Generate a new secret:
   ```bash
   openssl rand -hex 32 > token.key.new
   ```

2. Schedule a maintenance window or accept that all users will re-challenge once.

3. Replace the secret file:
   ```bash
   mv token.key.new token.key
   ```

4. Restart the daemon to pick up the new secret:
   ```bash
   docker compose restart anti-scrapling
   ```

5. Verify the daemon started with the new secret by checking the startup log:
   ```json
   {"level":"info","msg":"token secret loaded","fingerprint":"sha256:abc123..."}
   ```

### Rotation without downtime (future)

A dual-key rotation mode (accept old and new keys during a transition window) is planned for a future release. Until then, rotation causes a brief re-challenge wave for all active users.
