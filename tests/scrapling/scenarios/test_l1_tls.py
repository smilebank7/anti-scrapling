import subprocess

from curl_cffi import requests as cffi_requests


_TARGET_PATH = "/"

_CURL_CFFI_PROFILES_ROTATION = [
    "chrome110",
    "chrome116",
    "chrome120",
    "chrome124",
    "chrome131",
]


def _is_blocked(status_code: int) -> bool:
    return status_code in (302, 403)


def test_curl_cffi_chrome131_blocked(daemon_url: str) -> None:
    resp = cffi_requests.get(
        daemon_url + _TARGET_PATH,
        impersonate="chrome131",
        allow_redirects=False,
        timeout=10,
    )
    assert _is_blocked(resp.status_code), (
        f"curl_cffi impersonate=chrome131 was NOT blocked — "
        f"daemon returned HTTP {resp.status_code} (expected 302 or 403). "
        f"The TLS+HTTP fingerprint of Scrapling's Fetcher passed the firewall."
    )


def test_curl_cffi_rotation_blocked(daemon_url: str) -> None:
    blocked = 0
    results = {}
    for profile in _CURL_CFFI_PROFILES_ROTATION:
        resp = cffi_requests.get(
            daemon_url + _TARGET_PATH,
            impersonate=profile,
            allow_redirects=False,
            timeout=10,
        )
        results[profile] = resp.status_code
        if _is_blocked(resp.status_code):
            blocked += 1

    assert blocked >= 1, (
        f"Per-request TLS-profile rotation across {len(_CURL_CFFI_PROFILES_ROTATION)} profiles "
        f"was NOT blocked even once. Status codes: {results}"
    )


def test_raw_python_requests_blocked(daemon_url: str) -> None:
    import requests

    resp = requests.get(daemon_url + _TARGET_PATH, allow_redirects=False, timeout=10)
    assert _is_blocked(resp.status_code), (
        f"Bare Python requests (urllib3 TLS stack, no impersonation) was NOT blocked — "
        f"daemon returned HTTP {resp.status_code}."
    )


def test_raw_curl_blocked(daemon_url: str) -> None:
    result = subprocess.run(
        [
            "curl",
            "-s",
            "-o", "/dev/null",
            "-w", "%{http_code}",
            "--max-redirs", "0",
            "--connect-timeout", "5",
            daemon_url + _TARGET_PATH,
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    status = result.stdout.strip()
    assert status in ("302", "403"), (
        f"Raw system curl was NOT blocked — daemon returned HTTP {status} "
        f"(stderr: {result.stderr.strip()!r})."
    )
