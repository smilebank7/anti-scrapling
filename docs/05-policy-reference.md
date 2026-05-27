# Policy Reference

This document covers every field in the Anti-Scrapling policy YAML, all signal names with their default weights, and example custom rules.

---

## File structure

```yaml
version: 1          # always 1 for now

listener:           # network binding
  ...

token:              # pass-token configuration
  ...

policy:             # rules and default action
  ...

scoring:            # signal weights and thresholds
  ...

challenge:          # PoW and fingerprint collection settings
  ...

cache:              # decision cache backend
  ...
```

---

## `listener`

Controls where the proxy listens and where it forwards traffic.

```yaml
listener:
  bind: ":8080"                    # address:port to listen on
  target: "http://upstream:3000"   # upstream origin URL

  tls:                             # optional TLS termination
    cert: /etc/anti-scrapling/cert.pem
    key:  /etc/anti-scrapling/key.pem
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `bind` | string | Yes | Listen address. `":8080"` binds all interfaces. `"127.0.0.1:8080"` binds loopback only. |
| `target` | string | Yes | Upstream origin. All allowed/challenged-and-cleared requests are forwarded here. |
| `tls.cert` | string | No | Path to PEM certificate. If omitted, TLS termination is disabled. |
| `tls.key` | string | No | Path to PEM private key. Required if `tls.cert` is set. |

TLS termination is required for JA3/JA4 signal collection. Without it, the TLS layer signals are unavailable and the score relies on HTTP-layer and IP signals only.

---

## `token`

Pass-tokens are signed JWTs stored in the `__as_pass` cookie. A valid token lets a client skip the challenge pipeline on subsequent requests.

```yaml
token:
  secret_file: /etc/anti-scrapling/token.key   # path to HMAC secret
  ttl: 24h                                      # token lifetime
  bind_to: [ip, ua, ja3]                        # binding dimensions
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `secret_file` | string | Yes | Path to a file containing the raw HMAC-SHA256 secret. Generate with `openssl rand -hex 32 > token.key`. |
| `ttl` | duration | No | Token lifetime. Default `24h`. Accepts Go duration strings: `1h`, `30m`, `7d`. |
| `bind_to` | list | No | Dimensions the token is bound to. A token presented from a different value for any bound dimension is rejected. Options: `ip`, `ua`, `ja3`, `ja4`. Default `[ip, ua, ja3]`. |

**Binding trade-offs:**

- `ip` binding breaks for users on mobile networks with rotating IPs. Remove it if you see false positives from mobile users.
- `ja3` binding is the strongest signal. Keep it unless you're in SDK mode without TLS termination.
- Adding `ja4` tightens binding further but may cause issues if the client's TLS stack changes between requests.

---

## `policy`

The policy block defines the default action and the ordered list of rules.

```yaml
policy:
  default: challenge   # action when no rule matches: allow | challenge | deny

  rules:
    - name: allow-healthcheck
      match: { path: "/healthz" }
      action: allow

    - name: deny-known-scrapers
      match:
        expr: "signals['ja3_known_scraper'] > 0"
      action: deny
      reason: "TLS fingerprint matches known scraper"
```

### `policy.default`

The fallback action when no rule matches. Options: `allow`, `challenge`, `deny`.

- `default.yaml` uses `challenge` — unknown traffic gets challenged.
- `strict.yaml` uses `deny` — unknown traffic is blocked outright.

### Rule fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique rule identifier. Used in logs and audit entries. |
| `match` | object | Yes | Match conditions. See match keys below. |
| `action` | string | Yes | `allow`, `challenge`, or `deny`. |
| `reason` | string | No | Human-readable reason logged with the decision. |

Rules are evaluated top-to-bottom. The first matching rule wins. If no rule matches, `policy.default` applies.

### Match shorthand keys

These keys compile to CEL expressions internally. Use them for common conditions without writing raw CEL.

| Key | Type | Compiles to | Example |
|-----|------|-------------|---------|
| `path` | string | `request.path == "..."` | `{ path: "/healthz" }` |
| `path_prefix` | string | `request.path.startsWith("...")` | `{ path_prefix: "/api/" }` |
| `has_valid_token` | bool | `has_valid_token == true/false` | `{ has_valid_token: true }` |
| `ip_category` | string | `ip.category == "..."` | `{ ip_category: "datacenter" }` |
| `score` | string | `score >= N` (any comparison) | `{ score: ">=50" }` |
| `ja3_in` | list | `ja3.matches_family([...])` | `{ ja3_in: ["@curl_cffi/*"] }` |

Multiple shorthand keys in one `match` block are ANDed together:

```yaml
match:
  ip_category: datacenter
  score: ">=30"
# equivalent to: ip.category == 'datacenter' && score >= 30
```

### `match.expr` (CEL)

For anything not covered by shorthand keys, use a [CEL](https://cel.dev) expression:

```yaml
match:
  expr: "signals['canvas_seeded_noise'] > 0 || signals['audio_seeded_noise'] > 0"
```

Available CEL variables:

| Variable | Type | Description |
|----------|------|-------------|
| `request.path` | string | URL path, e.g. `"/api/users"` |
| `request.method` | string | HTTP method, e.g. `"GET"` |
| `request.host` | string | `Host` header value |
| `request.user_agent` | string | `User-Agent` header value |
| `ip.address` | string | Client IP address |
| `ip.category` | string | `"residential"`, `"datacenter"`, `"tor"`, `"mobile"` |
| `ip.asn` | string | ASN string, e.g. `"AS15169"` |
| `ja3` | string | JA3 hash or family name |
| `ja4` | string | JA4 hash |
| `score` | int | Computed risk score (sum of fired signal weights) |
| `has_valid_token` | bool | Whether a valid pass-token is present |
| `signals` | map[string]int | Per-signal values. `0` = not fired. |

---

## `scoring`

Controls how the risk score is computed and the thresholds used by shorthand score rules.

```yaml
scoring:
  challenge_threshold: 40   # score >= this → challenge (informational)
  deny_threshold: 80        # score >= this → deny (informational)
  weights:
    ja3_mismatch: 40
    ja3_known_scraper: 100
    # ... (full list below)
```

The `challenge_threshold` and `deny_threshold` fields are informational for external tooling. Actual enforcement happens through the `score` shorthand or `expr` rules in `policy.rules`.

### Signal weights reference

The score is the sum of weights for every signal that fired on a request. A signal weight of `0` disables the signal entirely.

#### TLS signals

| Signal | Default weight | Description |
|--------|---------------|-------------|
| `ja3_mismatch` | 40 | JA3 hash doesn't match the claimed browser version |
| `ja3_known_scraper` | 100 | JA3 is in the known-scraper fingerprint database (curl_cffi, python-requests, etc.) |
| `ja4_unknown` | 30 | JA4 hash not seen in any real browser corpus |
| `h2_akamai_mismatch` | 35 | HTTP/2 SETTINGS frame doesn't match the browser's known profile |

#### HTTP signals

| Signal | Default weight | Description |
|--------|---------------|-------------|
| `ja4h_unknown` | 20 | JA4H header fingerprint not seen in any real browser corpus |
| `header_order_anomaly` | 20 | Header order doesn't match any known browser |
| `ua_ch_mismatch` | 25 | `User-Agent` and `Sec-CH-UA` describe different browsers |
| `secfetch_invalid` | 15 | `Sec-Fetch-*` headers are missing or logically inconsistent |
| `browserforge_quirk` | 40 | Header combination matches a BrowserForge-generated profile |
| `no_referer` | 5 | No `Referer` header on a navigation request |
| `google_referer_anomaly` | 10 | `Referer` claims Google but the request pattern doesn't match organic search behavior |

#### IP signals

| Signal | Default weight | Description |
|--------|---------------|-------------|
| `datacenter_ip` | 30 | IP belongs to a cloud/hosting ASN (AWS, GCP, Azure, DigitalOcean, etc.) |
| `tor_exit` | 50 | IP is a known Tor exit node |
| `mobile_ip` | -5 | IP is a mobile carrier (slight trust boost; negative weight) |
| `residential_ip` | 0 | Residential IP (neutral; weight is 0) |

#### JS / browser fingerprint signals

| Signal | Default weight | Description |
|--------|---------------|-------------|
| `nav_platform_ua_mismatch` | 50 | `navigator.platform` doesn't match the OS in `User-Agent`. Caused by playwright-stealth's `navigator_plaftorm` typo. |
| `nav_hardware_concurrency_trap` | 30 | `navigator.hardwareConcurrency` is exactly 4 (playwright-stealth hardcodes this value) |
| `nav_webdriver_set` | 60 | `navigator.webdriver === true` |
| `nav_plugins_anomaly` | 20 | Plugin list is empty or matches headless defaults |
| `nav_vendor_ua_mismatch` | 25 | `navigator.vendor` doesn't match the browser family in `User-Agent` |
| `nav_oscpu_firefox_only` | 15 | `navigator.oscpu` is present in a non-Firefox browser |
| `webgl_vendor_renderer_impossible` | 40 | WebGL vendor/renderer combination doesn't exist in any known GPU database |
| `webgl_unmasked_missing` | 20 | `WEBGL_debug_renderer_info` extension is missing |
| `webgl_extensions_anomaly` | 15 | Extension list doesn't match any known GPU profile |
| `canvas_seeded_noise` | 50 | Canvas fingerprint has seeded noise (camoufox `setCanvasSeed()`) |
| `audio_seeded_noise` | 40 | AudioContext fingerprint has seeded noise (camoufox `setAudioFingerprintSeed()`) |
| `codec_rare_missing` | 20 | A common codec is missing from `MediaCapabilities` |
| `font_os_bundled_missing` | 25 | An OS-bundled font is not found (camoufox `setFontList()` doesn't include all system fonts) |
| `window_outer_height_85_trap` | 50 | `window.outerHeight` is exactly `innerHeight + 85` (playwright-stealth constant) |
| `chrome_runtime_connect_failure` | 40 | `chrome.runtime.connect()` throws in a Chrome-claiming browser (mocked runtime) |
| `chrome_present_for_firefox` | 60 | `window.chrome` exists in a Firefox-claiming browser |
| `permissions_midi_inconsistent` | 35 | MIDI permission state is inconsistent with the browser's expected behavior |
| `webrtc_no_local_ips` | 15 | WebRTC ICE candidates contain no local IPs (camoufox `setWebRTCIPv4()`) |
| `dom_iframe_contentwindow_anomaly` | 40 | `iframe.contentWindow` behaves unexpectedly (playwright-stealth patch) |
| `dom_closed_shadow_root_accessible` | 50 | A closed shadow root is accessible from JS (Playwright CDP leak) |
| `runtime_console_debug_disabled` | 60 | `console.debug` is a no-op (Patchright/undetected-playwright console patch) |
| `runtime_to_string_proxy` | 35 | `Function.prototype.toString` returns proxy-patched source |
| `runtime_error_stack_pw_signature` | 70 | Error stack trace contains Playwright internal frames |
| `speech_voices_empty` | 15 | `speechSynthesis.getVoices()` returns an empty list |
| `sw_register_noop` | 45 | `navigator.serviceWorker.register` silently fails (Patchright no-op patch) |
| `hairline_non_modernizr_anomaly` | 20 | Hairline detection result is inconsistent with the browser |

#### Behavioral signals

| Signal | Default weight | Description |
|--------|---------------|-------------|
| `behavior_resource_block` | 40 | Requests for images, fonts, or CSS are blocked (Scrapling's default resource-type blocking) |
| `behavior_smooth_path` | 30 | Mouse path is geometrically smooth (bot-generated, not human) |
| `behavior_turnstile_clicker` | 60 | Click pattern matches Scrapling's Turnstile auto-solver (`randint(100, 200)` delay) |
| `behavior_hidden_dominant` | 20 | Most session time is spent on a hidden/background tab |

---

## `challenge`

Controls the proof-of-work challenge and fingerprint collection.

```yaml
challenge:
  pow_difficulty: 4      # leading zero bits required in PoW solution
  collect_fingerprint: true
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `pow_difficulty` | int | `4` | Number of leading zero bits required in the SHA-256 PoW solution. Each +1 roughly doubles client-side solve time. Difficulty 4 takes ~200-500ms on a modern laptop. Difficulty 6 takes ~1-2s. |
| `collect_fingerprint` | bool | `true` | Whether to collect and score the JS fingerprint during the challenge. Set to `false` to use PoW-only mode (faster challenge, less signal). |

---

## `cache`

The decision cache stores recent verdicts to avoid re-running the full pipeline on every request from the same client.

```yaml
cache:
  backend: memory        # memory | redis
  ttl_seconds: 60

  redis:                 # only used when backend: redis
    addr: "redis:6379"
    password: ""
    db: 0
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `backend` | string | `memory` | Cache backend. `memory` is in-process (lost on restart). `redis` enables distributed caching across instances. |
| `ttl_seconds` | int | `60` | How long a cached decision is valid. After expiry, the next request re-runs the pipeline. |
| `redis.addr` | string | | Redis address in `host:port` format. |
| `redis.password` | string | | Redis password. Leave empty if not set. |
| `redis.db` | int | `0` | Redis database index. |

---

## Example custom rules

### 1. Allow a specific API key header

```yaml
- name: allow-internal-api
  match:
    expr: "request.headers['X-Internal-Key'] == 'my-secret-key'"
  action: allow
```

### 2. Deny all Tor traffic regardless of score

```yaml
- name: deny-tor
  match: { ip_category: "tor" }
  action: deny
  reason: "Tor exit node"
```

### 3. Challenge only on specific paths

```yaml
- name: challenge-checkout
  match:
    expr: "request.path.startsWith('/checkout') && score >= 20"
  action: challenge
```

### 4. Allow datacenter IPs on the API (you serve API clients from cloud)

```yaml
- name: allow-api-datacenter
  match:
    expr: "request.path.startsWith('/api/') && ip.category == 'datacenter' && has_valid_token"
  action: allow
```

### 5. Deny any request that fires the canvas noise signal

```yaml
- name: deny-canvas-noise
  match:
    expr: "signals['canvas_seeded_noise'] > 0"
  action: deny
  reason: "Canvas fingerprint seeded noise detected (camoufox)"
```

---

## Full annotated example

```yaml
version: 1

listener:
  bind: ":8080"
  target: "http://my-app:3000"
  tls:
    cert: /etc/certs/tls.crt
    key:  /etc/certs/tls.key

token:
  secret_file: /etc/anti-scrapling/token.key
  ttl: 12h
  bind_to: [ip, ua, ja3]

policy:
  default: challenge

  rules:
    # Infrastructure paths that must never be blocked
    - name: allow-healthcheck
      match: { path: "/healthz" }
      action: allow

    - name: allow-readyz
      match: { path: "/readyz" }
      action: allow

    - name: allow-metrics-internal
      match: { path_prefix: "/metrics" }
      action: allow

    # Challenge assets must be reachable before the token is issued
    - name: allow-challenge-assets
      match: { path_prefix: "/__as/" }
      action: allow

    # Clients that already passed the challenge
    - name: allow-valid-token
      match: { has_valid_token: true }
      action: allow

    # High-confidence scraper signals: deny immediately
    - name: deny-known-scraper-libs
      match:
        expr: "signals['ja3_known_scraper'] > 0 || signals['runtime_error_stack_pw_signature'] > 0"
      action: deny
      reason: "TLS or runtime fingerprint matches known scraper"

    # Very high score: deny without challenge
    - name: deny-extreme-score
      match: { score: ">=80" }
      action: deny

    # Suspicious: challenge
    - name: challenge-suspicious
      match: { score: ">=40" }
      action: challenge

scoring:
  challenge_threshold: 40
  deny_threshold: 80
  weights:
    ja3_known_scraper: 100
    runtime_error_stack_pw_signature: 70
    nav_webdriver_set: 60
    runtime_console_debug_disabled: 60
    chrome_present_for_firefox: 60
    behavior_turnstile_clicker: 60
    tor_exit: 50
    canvas_seeded_noise: 50
    dom_closed_shadow_root_accessible: 50
    nav_platform_ua_mismatch: 50
    window_outer_height_85_trap: 50
    sw_register_noop: 45
    ja3_mismatch: 40
    browserforge_quirk: 40
    webgl_vendor_renderer_impossible: 40
    chrome_runtime_connect_failure: 40
    dom_iframe_contentwindow_anomaly: 40
    behavior_resource_block: 40
    audio_seeded_noise: 40
    h2_akamai_mismatch: 35
    permissions_midi_inconsistent: 35
    runtime_to_string_proxy: 35
    datacenter_ip: 30
    nav_hardware_concurrency_trap: 30
    ja4_unknown: 30
    behavior_smooth_path: 30
    ua_ch_mismatch: 25
    font_os_bundled_missing: 25
    nav_vendor_ua_mismatch: 25
    header_order_anomaly: 20
    ja4h_unknown: 20
    nav_plugins_anomaly: 20
    webgl_unmasked_missing: 20
    codec_rare_missing: 20
    hairline_non_modernizr_anomaly: 20
    behavior_hidden_dominant: 20
    nav_oscpu_firefox_only: 15
    secfetch_invalid: 15
    webrtc_no_local_ips: 15
    speech_voices_empty: 15
    webgl_extensions_anomaly: 15
    google_referer_anomaly: 10
    no_referer: 5
    residential_ip: 0
    mobile_ip: -5

challenge:
  pow_difficulty: 4
  collect_fingerprint: true

cache:
  backend: memory
  ttl_seconds: 60
```
