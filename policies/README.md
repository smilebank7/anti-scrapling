# Anti-Scrapling Policies

This directory ships two ready-to-use policy files. Pick one as your starting point and tune from there.

| File | Default action | PoW difficulty | Token TTL | Best for |
|------|---------------|----------------|-----------|----------|
| `default.yaml` | `challenge` | 4 | 24h | Most production sites |
| `strict.yaml` | `deny` | 6 | 8h | High-value targets, login walls, APIs |

---

## How the decision pipeline works

Every request passes through rules in order. The first rule whose `match` conditions are all true wins. If no rule matches, the `policy.default` action applies.

```
request arrives
  → rule 1 match? → yes → action
  → rule 2 match? → yes → action
  → ...
  → no match → policy.default
```

Actions are: `allow`, `challenge`, `deny`.

---

## `default.yaml` — Balanced

Designed to let real users through with minimal friction while blocking obvious bots and challenging anything suspicious.

### Rules (in evaluation order)

| Rule | Match | Action | Why |
|------|-------|--------|-----|
| `allow-healthcheck` | `path == /healthz` | allow | Load balancer probes must never be blocked |
| `allow-readyz` | `path == /readyz` | allow | Kubernetes readiness probes |
| `allow-metrics-internal` | `path` starts with `/metrics` | allow | Prometheus scraping from inside the cluster |
| `allow-challenge-assets` | `path` starts with `/__as/` | allow | The challenge page's own JS/CSS assets |
| `allow-valid-token` | `has_valid_token == true` | allow | Passed the challenge previously; skip re-evaluation |
| `deny-known-scraper-libs` | `ja3_known_scraper > 0` or `runtime_error_stack_pw_signature > 0` | deny | TLS fingerprint or Playwright stack trace matches a known scraper |
| `deny-headless-extreme` | `score >= 80` | deny | Score this high means near-certain bot |
| `challenge-suspicious` | `score >= 40` | challenge | Suspicious but not certain; make them solve PoW + collect fingerprint |

Anything that falls through all rules gets `challenge` (the default).

### When to use

- General-purpose web apps
- E-commerce, content sites, SaaS dashboards
- When you want to minimize false positives on real users

---

## `strict.yaml` — Paranoid

Denies by default. Only explicitly allowed traffic gets through. Datacenter and Tor IPs are denied outright regardless of score.

### Rules (in evaluation order)

| Rule | Match | Action | Why |
|------|-------|--------|-----|
| `allow-healthcheck` | `path == /healthz` | allow | Same as default |
| `allow-readyz` | `path == /readyz` | allow | Same as default |
| `allow-challenge-assets` | `path` starts with `/__as/` | allow | Challenge assets must be reachable |
| `allow-valid-token` | `has_valid_token == true` | allow | Cleared the harder PoW; let them through |
| `deny-datacenter-ip` | `ip.category == datacenter` or `tor` | deny | No legitimate user traffic from cloud ranges or Tor |
| `deny-any-high-weight-signal` | Any of: `ja3_known_scraper`, `runtime_error_stack_pw_signature`, `runtime_console_debug_disabled`, `canvas_seeded_noise`, `nav_webdriver_set` | deny | Single high-confidence signal is enough to block |
| `challenge-everyone-else` | `score >= 10` | challenge | Very low threshold; almost everyone gets challenged |
| `allow-residential-clean` | `ip.category == residential` and `score < 10` | allow | Clean residential IP with no signals; safe to pass |

Anything that falls through all rules gets `deny` (the default).

### When to use

- Login endpoints, password reset, account creation
- High-value APIs (payment, PII)
- Sites that have already been actively scraped
- When false negatives are more costly than false positives

---

## Scoring weights

The score is the sum of weights for every signal that fired. Rules then compare `score` against thresholds.

| Signal | Default weight | Category | Notes |
|--------|---------------|----------|-------|
| `ja3_mismatch` | 40 | TLS | JA3 hash doesn't match the claimed browser |
| `ja3_known_scraper` | 100 | TLS | JA3 is in the known-scraper fingerprint database |
| `ja4_unknown` | 30 | TLS | JA4 hash not seen in any real browser corpus |
| `h2_akamai_mismatch` | 35 | HTTP/2 | H2 SETTINGS frame doesn't match browser's known profile |
| `ja4h_unknown` | 20 | HTTP | JA4H header fingerprint unknown |
| `header_order_anomaly` | 20 | HTTP | Header order doesn't match any known browser |
| `ua_ch_mismatch` | 25 | HTTP | `User-Agent` and `Sec-CH-UA` describe different browsers |
| `secfetch_invalid` | 15 | HTTP | `Sec-Fetch-*` headers are missing or logically inconsistent |
| `browserforge_quirk` | 40 | HTTP | Fingerprint matches a BrowserForge-generated profile |
| `no_referer` | 5 | HTTP | No `Referer` on a navigation request |
| `google_referer_anomaly` | 10 | HTTP | `Referer` claims Google but request pattern doesn't match |
| `datacenter_ip` | 30 | IP | IP belongs to a cloud/hosting ASN |
| `tor_exit` | 50 | IP | IP is a known Tor exit node |
| `mobile_ip` | -5 | IP | IP is a mobile carrier (slight trust boost) |
| `residential_ip` | 0 | IP | Residential IP (neutral) |
| `nav_platform_ua_mismatch` | 50 | JS | `navigator.platform` doesn't match `User-Agent` OS |
| `nav_hardware_concurrency_trap` | 30 | JS | `navigator.hardwareConcurrency` is a trap value |
| `nav_webdriver_set` | 60 | JS | `navigator.webdriver === true` |
| `nav_plugins_anomaly` | 20 | JS | Plugin list is empty or matches headless defaults |
| `nav_vendor_ua_mismatch` | 25 | JS | `navigator.vendor` doesn't match browser family |
| `nav_oscpu_firefox_only` | 15 | JS | `navigator.oscpu` present in a non-Firefox browser |
| `webgl_vendor_renderer_impossible` | 40 | JS | WebGL vendor/renderer combination doesn't exist |
| `webgl_unmasked_missing` | 20 | JS | `WEBGL_debug_renderer_info` extension missing |
| `webgl_extensions_anomaly` | 15 | JS | Extension list doesn't match any known GPU |
| `canvas_seeded_noise` | 50 | JS | Canvas fingerprint has seeded noise (anti-fingerprint tool) |
| `audio_seeded_noise` | 40 | JS | AudioContext fingerprint has seeded noise |
| `codec_rare_missing` | 20 | JS | Common codec missing from `MediaCapabilities` |
| `font_os_bundled_missing` | 25 | JS | OS-bundled font not found |
| `window_outer_height_85_trap` | 50 | JS | `window.outerHeight` is exactly 85% of `innerHeight` (headless default) |
| `chrome_runtime_connect_failure` | 40 | JS | `chrome.runtime.connect` throws in a Chrome-claiming browser |
| `chrome_present_for_firefox` | 60 | JS | `window.chrome` exists in a Firefox-claiming browser |
| `permissions_midi_inconsistent` | 35 | JS | MIDI permission state is inconsistent with browser |
| `webrtc_no_local_ips` | 15 | JS | WebRTC ICE candidates contain no local IPs |
| `dom_iframe_contentwindow_anomaly` | 40 | JS | `iframe.contentWindow` behaves unexpectedly |
| `dom_closed_shadow_root_accessible` | 50 | JS | Closed shadow root is accessible (Playwright leak) |
| `runtime_console_debug_disabled` | 60 | JS | `console.debug` is a no-op (Patchright/undetected-playwright) |
| `runtime_to_string_proxy` | 35 | JS | `Function.prototype.toString` returns proxy-patched source |
| `runtime_error_stack_pw_signature` | 70 | JS | Error stack trace contains Playwright internal frames |
| `speech_voices_empty` | 15 | JS | `speechSynthesis.getVoices()` returns empty list |
| `sw_register_noop` | 45 | JS | `navigator.serviceWorker.register` silently fails |
| `hairline_non_modernizr_anomaly` | 20 | JS | Hairline detection result inconsistent with browser |
| `behavior_resource_block` | 40 | Behavior | Requests for images/fonts are blocked (headless default) |
| `behavior_smooth_path` | 30 | Behavior | Mouse path is geometrically smooth (bot-generated) |
| `behavior_turnstile_clicker` | 60 | Behavior | Click pattern matches Turnstile auto-solver |
| `behavior_hidden_dominant` | 20 | Behavior | Most time spent on hidden/background tab |

---

## Threshold logic

```
score = sum of weights for all fired signals

if score >= deny_threshold  → deny  (unless a rule already decided)
if score >= challenge_threshold → challenge
else → allow (or policy.default)
```

| Policy | `challenge_threshold` | `deny_threshold` |
|--------|-----------------------|-----------------|
| default | 40 | 80 |
| strict | 10 | 50 |

The thresholds in `scoring` are informational for external tooling. The actual enforcement happens through the `expr`-based rules in `policy.rules`.

---

## Customizing

### Add a rule

Rules are evaluated top-to-bottom. Insert your rule before the catch-all rules.

```yaml
policy:
  rules:
    - name: allow-my-api-key
      match:
        expr: "request.path.startsWith('/api/') && has_valid_token"
      action: allow
```

### Tune a weight

Find the signal name in the weights table and adjust its value. Set to `0` to disable a signal entirely.

```yaml
scoring:
  weights:
    datacenter_ip: 0  # don't penalize datacenter IPs (e.g. you serve API clients)
```

### Change PoW difficulty

Higher difficulty means more CPU work for the client. Each +1 roughly doubles solve time.

```yaml
challenge:
  pow_difficulty: 5  # ~1s on a modern laptop
```

### Use Redis for the decision cache

```yaml
cache:
  backend: redis
  redis:
    addr: "redis:6379"
    db: 0
  ttl_seconds: 300
```

---

## CEL expression reference

Rules with `expr` use [CEL (Common Expression Language)](https://cel.dev). Available variables:

| Variable | Type | Example |
|----------|------|---------|
| `request.path` | string | `"/api/users"` |
| `request.method` | string | `"GET"` |
| `request.host` | string | `"example.com"` |
| `request.user_agent` | string | `"Mozilla/5.0..."` |
| `ip.address` | string | `"1.2.3.4"` |
| `ip.category` | string | `"residential"`, `"datacenter"`, `"tor"`, `"mobile"` |
| `ip.asn` | string | `"AS15169"` |
| `ja3` | string | JA3 hash or family name |
| `ja4` | string | JA4 hash |
| `score` | int | Computed risk score |
| `has_valid_token` | bool | Whether a valid pass-token is present |
| `signals` | map[string]int | Per-signal fired values (0 = not fired) |

Shorthand match keys (no `expr` needed):

| Key | Type | Compiles to |
|-----|------|-------------|
| `path` | string | `request.path == "..."` |
| `path_prefix` | string | `request.path.startsWith("...")` |
| `has_valid_token` | bool | `has_valid_token` or `!has_valid_token` |
| `ip_category` | string | `ip.category == "..."` |
| `score` | string | `score >= N` (any comparison operator) |
| `ja3_in` | list | `ja3.matches_family([...])` |
