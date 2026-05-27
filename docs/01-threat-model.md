# Anti-Scrapling: Scrapling Threat Model

This document catalogues every bypass technique used by [D4Vinci/Scrapling](https://github.com/D4Vinci/Scrapling) (at HEAD `b31dc50a063418307c6572cf01a1a9d14ccda8fc`) and its dependency stack (`curl_cffi`, `browserforge`, `patchright`, `camoufox`, `playwright-stealth`). Each row maps to a counter-detection lane in the Anti-Scrapling firewall.

## Layer 1 — Network/TLS

| # | Scrapling technique | Bypass mechanism | Library | Our counter |
|---|---|---|---|---|
| L1.1 | TLS JA3/JA4 spoof | `impersonate=` chrome110…chrome131/safari/edge/firefox | `curl_cffi` | Compute JA3/JA4 from real ClientHello; allowlist real-browser fingerprints |
| L1.2 | TLS profile randomization | Per-request `choice(impersonate_list)` | `curl_cffi` | Per-session fingerprint must be stable; rotation flagged |
| L1.3 | HTTP/2 SETTINGS spoof | Delegated to `curl_cffi` impersonate | `curl_cffi` | JA4H + Akamai H2 fingerprint detection |
| L1.4 | HTTP/3 / QUIC pivot | `http_version=CurlHttpVersion.V3ONLY` | `curl_cffi` | Detect H3-only clients; H3 fingerprint mismatch |
| L1.5 | DNS-over-HTTPS | `--dns-over-https-templates=…cloudflare-dns.com` | Chromium | Not detectable from origin (resolver-side); ignore |
| L1.6 | Proxy/SOCKS rotation | rotating proxy + SOCKS4/5 | `curl_cffi`, Playwright | IP reputation + ASN scoring + datacenter IP detection |
| L1.7 | Connection pooling | `CurlSession()` reuse | `curl_cffi` | TLS-session-resumption tracking; rapid-IP-switch detection |

## Layer 2 — HTTP semantics

| # | Scrapling technique | Bypass mechanism | Library | Our counter |
|---|---|---|---|---|
| L2.1 | Browser-like headers | `browserforge.HeaderGenerator()` | `browserforge` | Header-order JA4H + UA↔sec-ch-ua consistency; browserforge has fixed quirks |
| L2.2 | Default Google referer | `final_headers["referer"]="https://www.google.com/"` | Scrapling | Statistical anomaly: too high Google-referer ratio per IP |
| L2.3 | User-supplied header priority | user headers override generator | Scrapling | Header-order anomaly detection |
| L2.4 | sec-ch-ua/sec-fetch synthesis | browserforge generates the set | `browserforge` | Detect known browserforge value combinations; verify against Client Hints spec |
| L2.5 | Cookie persistence | persistent session + `add_cookies()` | `curl_cffi`, Playwright | Token-binding: pass-cookie must round-trip with original fingerprint |

## Layer 3 — Browser/Process

| # | Scrapling technique | Bypass mechanism | Library | Our counter |
|---|---|---|---|---|
| L3.1 | webdriver flag removed | `chromiumSwitchesPatch.ts` removes `--enable-automation`, adds `--disable-blink-features=AutomationControlled` | `patchright` | Don't rely on `navigator.webdriver` alone |
| L3.2 | `Runtime.enable` skipped | `crDevToolsPatch.ts` removes `Runtime.enable` from `Promise.all` | `patchright` | Error-stack timing probe; multiple eval contexts probe |
| L3.3 | Console API disabled | patches kill console events to hide CDP listener | `patchright` | **NEW SIGNAL**: probe `console.debug.length` / `console.debug.toString()` for tampering; missing console events trigger flag |
| L3.4 | Service worker no-op | `navigator.serviceWorker.register = async () => {}` | `patchright` | Probe registration: register a worker, expect `serviceWorker.controller` to populate; failure flags patchright |
| L3.5 | Init script via route | `route.fallback({patchrightInitScript: true})` injects on HTML document only | `patchright` | Detect non-HTML init absence (CSS/JS-only pages) |
| L3.6 | Isolated execution context | `evaluate(..., isolatedContext=true)` | `patchright` | Cross-realm object identity probe |
| L3.7 | Closed Shadow Root traversal | `DOM.describeNode` CDP-only | `patchright` | Test: create closed shadow root, expect inaccessible to JS; if accessed → flag |
| L3.8 | Browser command-line stealth flags | DEFAULT_ARGS + STEALTH_ARGS large set | Scrapling | Not directly observable, but companion signals (DoH leak, no extensions) |
| L3.9 | Real Chrome / CDP attachment | `playwright.chromium.connect_over_cdp()` | Playwright | CDP-tunnel detection: WS upgrade to /devtools/* origin patterns |

## Layer 4 — JS Fingerprint Spoofing

| # | Scrapling technique | Bypass mechanism | Library | Our counter |
|---|---|---|---|---|
| L4.1 | `navigator.webdriver=false` | JS patch | `playwright-stealth` | Trivial; not a sole signal |
| L4.2 | `navigator.languages=[…]` | JS patch, fixed values | `playwright-stealth` | UA-language consistency; OS-language consistency via timezone |
| L4.3 | `navigator.hardwareConcurrency=4` | hardcoded to 4 in stealth | `playwright-stealth` | Anomaly: too many bots report exactly 4 |
| L4.4 | `navigator.platform` spoof | JS patch with TYPO (`opts.navigator_plaftorm`) | `playwright-stealth` | Detect: spoof silently fails → platform-UA mismatch |
| L4.5 | `window.chrome.runtime/app/loadTimes/csi` mocks | Fabricated functions | `playwright-stealth` | Probe `chrome.runtime.connect()` and verify behavior; fakes throw on real port use |
| L4.6 | `navigator.plugins/mimeTypes` magic arrays | Fabricated PDF/NaCl plugins | `playwright-stealth` | Compare against canonical Chrome plugin sets per version |
| L4.7 | `iframe.contentWindow` patch | iframe.contentWindow returns iframe element | `playwright-stealth` | Cross-frame property identity probe |
| L4.8 | `media.codecs` MIME spoof | Limited codec allowlist | `playwright-stealth` | Probe rare codecs (HEVC, AV1 profiles); real browsers report full table |
| L4.9 | `window.outerWidth/Height` patch | `outerWidth=innerWidth`, `outerHeight=innerHeight+85` | `playwright-stealth` | Constant offset `85` is a signature |
| L4.10 | `Function.prototype.toString` patch | `utils.patchToString()` | `playwright-stealth` | Cross-realm `toString` probe; iframe-isolated function reflection |
| L4.11 | Canvas seed noise | `setCanvasSeed()` in camoufox JS | `camoufox` | Statistical canvas test: render same canvas multiple times; variance ≠ 0 → seeded noise |
| L4.12 | Audio seed noise | `setAudioFingerprintSeed()` | `camoufox` | Same AudioContext output should be deterministic per session; variance flags noise |
| L4.13 | WebGL vendor/renderer spoof | `setWebGLVendor`/`setWebGLRenderer` from DB | `camoufox` | Cross-check WebGL params (vendor + renderer + extensions + max texture size) against known GPU profiles |
| L4.14 | Font enumeration spoof | `setFontList()` | `camoufox` | Probe rare/OS-bundled fonts not in spoof set |
| L4.15 | Speech voices spoof | `setSpeechVoices()` | `camoufox` | Probe `speechSynthesis.getVoices()` for OS-default voices |
| L4.16 | WebRTC IP spoof | `setWebRTCIPv4()` | `camoufox` | STUN probe from JS; compare against socket-IP |
| L4.17 | Modernizr hairline patch | `hairline.js` returns 1 for id=modernizr | `playwright-stealth` | Run hairline test on non-modernizr id |
| L4.18 | uBlock Origin bundled | extension blocks fingerprint/tracker scripts | `camoufox` | Detect missing requests to our beacon endpoints |

## Layer 5 — Resource/behavior shaping

| # | Scrapling technique | Bypass mechanism | Library | Our counter |
|---|---|---|---|---|
| L5.1 | Resource type blocking | `font/image/media/beacon/object/imageset/texttrack/websocket/csp_report/stylesheet` aborted | Scrapling | Missing CSS/font/image fetches per page = bot signal |
| L5.2 | Ad/tracker domain blocking | suffix-match against AD_DOMAINS | Scrapling | Same as above |
| L5.3 | Cloudflare Turnstile auto-solver | Detect `challenges.cloudflare.com/turnstile/v` script, click at randomized coords | Scrapling | Click-coordinate entropy analysis; randint(100,200) delay is a signature |
| L5.4 | Viewport pinning | 1920x1080 fixed | Scrapling | Population of viewports that exactly match `1920x1080` with no devicePixelRatio variation = bot |
| L5.5 | Permissions allow-list | `geolocation, notifications` always permitted | Scrapling | Probe `permissions.query({name:'midi'})` etc.; spoofed `permissions` only handles `notifications` |

## Counter-Defense Architecture (summary)

The Anti-Scrapling firewall layers detections in this order:

1. **Network/TLS (cheap)**: JA3/JA4/JA4H computed from raw ClientHello + first request. Decisions in <1ms.
2. **HTTP semantics (cheap)**: header-order, UA↔Client-Hints consistency, missing-header heuristics.
3. **IP reputation (medium)**: datacenter ASN, Tor exit, known scraper IPs.
4. **JS challenge (medium)**: proof-of-work + comprehensive fingerprint collection.
5. **Behavioral (deferred)**: telemetry beacon scoring across session lifetime.
6. **Honeypots (decoy)**: hidden links/forms; access = instant ban.

Each layer can independently **allow / challenge / block**, with the policy engine combining scores.

## Residual Telltales We Will Exploit

Specific code-level weaknesses we will leverage:

1. **playwright-stealth** `navigator.platform` typo → platform spoof silently fails
2. **playwright-stealth** `hardwareConcurrency` hardcoded to `4`
3. **playwright-stealth** `outerHeight = innerHeight + 85` (constant offset)
4. **playwright-stealth** `chrome.runtime` mocked (not real port behavior)
5. **patchright** Console API disabled (probe `console.debug` arity)
6. **patchright** Service worker registration no-op
7. **camoufox** canvas/audio seeds produce statistically-anomalous noise distributions
8. **Scrapling** default Google referer (statistical anomaly per IP)
9. **Scrapling** Turnstile auto-click at `randint(100, 200)` delay (timing signature)
10. **Scrapling** browserforge sec-ch-ua quirks (`Sec-Fetch-Site: ?1` style)
