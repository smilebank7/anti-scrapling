# Adversarial E2E Tests — anti-scrapling

## How to run

### Docker Compose (recommended)

```bash
make e2e
```

or directly:

```bash
cd tests/scrapling
docker compose up --abort-on-container-exit --build
```

JUnit XML results are written to `tests/scrapling/results/junit.xml`.

### Local (no Docker)

```bash
bash tests/scrapling/run_local.sh
```

Requires Go toolchain + Python 3.11+. Starts a native `bin/antiscrapling` daemon and
runs pytest directly. Useful for debugging individual scenarios without rebuilding images.

---

## Service topology

| Service  | Port | Role |
|----------|------|------|
| upstream | 3000 | Echo server (ealen/echo-server) — the "protected" origin |
| daemon   | 8080 | Anti-scrapling proxy (main) |
| daemon   | 9090 | Prometheus metrics |
| daemon   | 9091 | Admin/SDK API (`/v1/decide`) |
| attacker | —    | Python container that runs pytest scenarios |

---

## Scenarios

### `test_l1_tls.py` — Layer 1: TLS / Network

The daemon runs plain HTTP in this setup, so TLS fingerprinting does not apply at port 8080.
Detection relies on HTTP-level signals and the policy default action (challenge everything without
a valid pass-token). A 200 from upstream is a bypass.

| Test | What it asserts |
|------|-----------------|
| `test_curl_cffi_chrome131_blocked` | `curl_cffi.requests` with `impersonate="chrome131"` (Scrapling's primary HTTP weapon) is challenged or denied |
| `test_curl_cffi_rotation_blocked` | Per-request impersonate rotation across 5 Chrome profiles is blocked at least once |
| `test_raw_python_requests_blocked` | Bare `requests` library (OpenSSL TLS stack, no impersonation) is blocked |
| `test_raw_curl_blocked` | System `curl` binary is blocked |

### `test_l2_http.py` — Layer 2: HTTP Semantics

| Test | Signal tested | Expected block |
|------|--------------|----------------|
| `test_no_referer_no_secfetch_blocked` | Missing browser-standard Sec-Fetch-* headers | CHALLENGE (302) |
| `test_browserforge_quirks_blocked` | `Sec-Fetch-Site: ?1` — known browserforge boolean quirk (`browserforge_quirk` signal, score=40) | CHALLENGE or DENY |
| `test_ua_clienthints_mismatch_blocked` | Chrome/131 UA + `sec-ch-ua` reporting Chrome/120 (version mismatch) | CHALLENGE or DENY |

### `test_decide_api.py` — SDK `/v1/decide` contract

| Test | What it asserts |
|------|-----------------|
| `test_decide_returns_valid_decision` | POST to `:9091/v1/decide` returns 200 with Verdict in {ALLOW, CHALLENGE, DENY} |
| `test_decide_known_scraper_returns_deny` | python-requests JA3 hash `f8bfd03d8fe2b66ec606d235dacb30fa` (deny-listed in `families.go`) produces Verdict=DENY |

### `test_scrapling_lib.py` — Scrapling library (optional)

Skipped automatically if `scrapling` is not installed on PyPI. The curl_cffi-based tests
in `test_l1_tls.py` are the primary truth gate (Scrapling's `Fetcher` uses curl_cffi).

| Test | What it asserts |
|------|-----------------|
| `test_scrapling_fetcher_blocked` | `Fetcher(impersonate="chrome131").get(...)` is challenged or denied |
| `test_scrapling_stealthy_fetcher_blocked` | **Skipped** — requires patchright + Chromium in container (too heavy for CI) |

---

## Acceptance criteria

**ALL enabled tests must pass.** A passing test means the corresponding attack vector
is blocked by the daemon. Any test failure is a regression in detection coverage.

---

## Workarounds

### scrapling not on PyPI

If `pip install scrapling==0.2.99` fails, the Dockerfile.attacker falls back to
`pip install scrapling` (latest). If both fail, all tests in `test_scrapling_lib.py`
are skipped via `pytest.mark.skipif`. The curl_cffi tests remain the truth gate.

### StealthyFetcher (patchright/Chromium)

`test_scrapling_stealthy_fetcher_blocked` is permanently skipped in the container because
installing Chromium in a Docker image adds ~700 MB. To run it locally:

```bash
pip install scrapling playwright
playwright install chromium
DAEMON_URL=http://localhost:8080 pytest tests/scrapling/scenarios/test_scrapling_lib.py::test_scrapling_stealthy_fetcher_blocked -v
```
