# testdata/ — Anti-Scrapling Test Vector Corpus

Ground-truth captures and synthesized fingerprint samples for TDD of the W1 signal-detection packages.

## Directory Layout

```
testdata/
├── _tools/             Developer tools for regeneration and capture
├── clienthello/        TLS ClientHello hex captures + JA3/JA4 expected values
├── http2/              HTTP/2 frame captures + Akamai H2 fingerprints
├── headers/            HTTP/1.1 request header captures
├── fingerprint/        FingerprintReport JSON for browser/scraper profiles
└── behavior/           BehaviorBeacon JSON for real user vs bot patterns
```

---

## `_tools/`

| File | Purpose |
|---|---|
| `gen_clienthello.py` | Python script that generates `clienthello/*.hex` + `*.expected.json` from documented JA3/JA4 values |
| `capture_tls.sh` | Run `openssl s_server` on `:18443` and capture a real ClientHello from any client |
| `refresh.sh` | Top-level regeneration orchestrator. Run `bash _tools/refresh.sh` to regenerate all synthetic vectors |
| `probe.html` + `probe.js` | Vanilla JS dev tool: open in browser to run all fingerprint probes and download a `FingerprintReport` JSON |
| `verify.sh` | Validation script: checks JSON syntax, required fields, and hex file format |

---

## `clienthello/`

TLS ClientHello byte captures for 9 browser/scraper profiles.

**Provenance**: Representative reconstructions from publicly documented JA3/JA4 values. Not real captures unless noted. Cite `notes` field in each `.expected.json`.

| Profile | `browser_family` | `is_scraper_library` | Notes |
|---|---|---|---|
| `chrome131_linux` | chrome | false | Real Chrome 131 Linux TLS profile |
| `chrome131_mac` | chrome | false | Real Chrome 131 macOS (TLS identical to Linux) |
| `firefox134_linux` | firefox | false | Firefox 134 Linux; no GREASE; delegated_credentials extension |
| `safari18_mac` | safari | false | Safari 18 macOS; includes SCSV (0xFF) and PSK (41) extensions |
| `curl_cffi_chrome131` | chrome | true | curl_cffi impersonate=chrome131; JA3 matches Chrome by design |
| `curl_cffi_firefox133` | firefox | true | curl_cffi impersonate=firefox133 |
| `curl_cffi_safari18_0` | safari | true | curl_cffi impersonate=safari18_0 |
| `python_requests` | python-requests | true | Default urllib3/OpenSSL; well-known JA3 hash b32309a... |
| `curl_default` | curl | true | Raw curl 8.x CLI; only 3 request headers |

Each profile has:
- `<profile>.hex` — space-separated hex text of the TLS ClientHello record (starts `16 03`)
- `<profile>.expected.json` — `ja3`, `ja3_hash` (MD5), `ja4`, `browser_family`, `is_scraper_library`, `notes`

**W1 consumer**: `internal/signal/tls/` (W1-T1)

---

## `http2/`

HTTP/2 connection preface captures + Akamai H2 fingerprint expected values.

| Profile | Akamai H2 fingerprint | Notes |
|---|---|---|
| `chrome131` | `1:65536,3:1000,4:6291456,6:262144\|15663105\|0\|m,a,s,p` | Chrome 131 SETTINGS |
| `firefox134` | `1:65536,4:131072,5:16384\|12517377\|0\|m,a,s,p` | Firefox 134 SETTINGS |
| `curl_cffi_chrome131` | same as Chrome 131 | Impersonation matches at SETTINGS level |
| `python_requests` | N/A | urllib3 is HTTP/1.1 only |

Files ending in `.bin.placeholder` are stubs pending real Wireshark captures (W1-T2 task).

**W1 consumer**: `internal/signal/http2/` (W1-T2)

---

## `headers/`

Raw HTTP/1.1 GET request captures (header order preserved).

| Profile | Key signal |
|---|---|
| `chrome131_get` | sec-ch-ua before User-Agent; zstd in Accept-Encoding; all Sec-Fetch-* |
| `firefox134_get` | No sec-ch-ua; User-Agent before Accept |
| `safari18_get` | No sec-ch-ua; no Sec-Fetch-*; no zstd; only 6 headers |
| `curl_cffi_chrome131_get` | Google Referer hardcoded (L2.2); Sec-Fetch-Site:none contradicts Referer |
| `python_requests_get` | 5 headers only; Accept:*/*; User-Agent reveals library |
| `curl_default_get` | 3 headers only; no Accept-Encoding |

Each profile has a `<profile>.expected.json` with `header_order[]`, `ua_ch_consistency`, `anomalies[]`.

**W1 consumer**: `internal/signal/headers/` (W1-T3)

---

## `fingerprint/`

Canonical `FingerprintReport` JSON for 8 browser/scraper profiles.

Schema: matches `FingerprintReport` Go type in `internal/types/fingerprint.go` exactly (snake_case JSON tags).

| File | Expected risk score | Key signals |
|---|---|---|
| `clean_chrome_131_linux.json` | < 20 | All probes consistent; canvas/audio variance=1 |
| `clean_chrome_131_mac.json` | < 20 | macOS fonts; device_pixel_ratio=2 |
| `clean_firefox_134_linux.json` | < 20 | chrome.present=false; oscpu present; vendor="" |
| `clean_safari_18_mac.json` | < 20 | vendor="Apple Computer, Inc."; webm="" |
| `patchright_chromium_131.json` | > 60 | **console_debug_arity=0** (L3.3); service_worker.controller=false (L3.4); iframe_identity=true (L3.6) |
| `camoufox_default.json` | > 70 | **canvas.variance=3** (L4.11); **audio.variance=3** (L4.12); **impossible WebGL vendor+renderer** (L4.13); missing_os_bundled fonts (L4.14) |
| `playwright_stealth_chromium.json` | > 80 | **hardware_concurrency=4** (L4.3); **outerHeight-innerHeight=85** (L4.9); **platform/UA mismatch** (L4.4); **chrome.runtime TypeError** (L4.5); iframe_identity=true (L4.7); hairline=false (L4.17) |
| `scrapling_stealthy_fetcher.json` | > 75 | patchright signals + Google referer + resource blocking + 1920x1080 pinned viewport |

**W1 consumer**: `internal/signal/fingerprint/` (W1-T5)

---

## `behavior/`

`BehaviorBeacon` JSON samples for real-user and bot behavioral patterns.

| File | Pattern | Key signals |
|---|---|---|
| `real_user_browsing.json` | Normal user reading + clicking | 423 mouse moves; jitter_mean=4.7px; 3 clicks across 34s |
| `real_user_fast_reader.json` | Reader, minimal mouse | 234 scroll events; 1 click at 87s |
| `real_user_mobile.json` | Mobile touch (no mouse) | move_events=0; touch clicks with 13s gap |
| `bot_scrapling_stealthy.json` | Scrapling StealthyFetcher | zero mouse/scroll; page_visible=false; no CSS/font/image fetches (L5.1) |
| `bot_scrapling_turnstile_click.json` | Scrapling Turnstile solver | 1 click at 143ms (randint(100,200)); zero jitter; perfect center click (L5.3) |
| `bot_synthetic_smooth.json` | Generic Bezier mouse bot | Bezier R²=0.9998; 42ms constant intervals; zero jitter; no resource fetches |

**W1 consumer**: `internal/signal/behavior/` (W1-T6)

---

## Regeneration

```bash
# Regenerate all synthetic vectors
bash testdata/_tools/refresh.sh

# Validate all files
bash testdata/_tools/verify.sh

# Capture a real ClientHello from a browser
bash testdata/_tools/capture_tls.sh testdata/clienthello/my_new_profile.hex

# Run fingerprint probes in browser
open testdata/_tools/probe.html
```

---

## Sources

- JA3/JA4 reference values: https://tls.peet.ws/, https://github.com/salesforce/ja3, https://github.com/FoxIO-LLC/ja4
- curl_cffi impersonation profiles: https://github.com/lexiforest/curl_cffi
- Akamai H2 fingerprinting: https://www.akamai.com/blog/security/passive-os-fingerprinting
- Scrapling threat model: `docs/01-threat-model.md`
