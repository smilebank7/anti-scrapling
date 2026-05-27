import httpx
import pytest


_TARGET_PATH = "/"
_BLOCKED = frozenset((302, 403))


def _assert_blocked(resp: httpx.Response, scenario: str) -> None:
    assert resp.status_code in _BLOCKED, (
        f"{scenario}: daemon returned HTTP {resp.status_code} — expected 302 (challenge) "
        f"or 403 (deny). Attack vector was NOT blocked."
    )


def test_no_referer_no_secfetch_blocked(daemon_url: str) -> None:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
    }
    resp = httpx.get(daemon_url + _TARGET_PATH, headers=headers, follow_redirects=False, timeout=10)
    _assert_blocked(resp, "no-Referer/no-Sec-Fetch-* scraper fingerprint")


def test_browserforge_quirks_blocked(daemon_url: str) -> None:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Sec-Fetch-Site": "?1",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }
    resp = httpx.get(daemon_url + _TARGET_PATH, headers=headers, follow_redirects=False, timeout=10)
    _assert_blocked(resp, "browserforge quirk Sec-Fetch-Site:?1 (boolean-style value)")


def test_ua_clienthints_mismatch_blocked(daemon_url: str) -> None:
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "sec-ch-ua": '"Chromium";v="120", "Not_A Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    resp = httpx.get(daemon_url + _TARGET_PATH, headers=headers, follow_redirects=False, timeout=10)
    _assert_blocked(resp, "Chrome/131 UA with sec-ch-ua reporting Chrome/120 (version mismatch)")
