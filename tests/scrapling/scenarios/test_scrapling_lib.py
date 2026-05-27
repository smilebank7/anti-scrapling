import pytest

try:
    import scrapling as _scrapling_module
    _SCRAPLING_AVAILABLE = True
    _SCRAPLING_IMPORT_ERROR = None
except ImportError as _e:
    _SCRAPLING_AVAILABLE = False
    _SCRAPLING_IMPORT_ERROR = str(_e)

_skip_if_no_scrapling = pytest.mark.skipif(
    not _SCRAPLING_AVAILABLE,
    reason=(
        f"scrapling not installed ({_SCRAPLING_IMPORT_ERROR}). "
        "curl_cffi-based tests in test_l1_tls.py serve as the primary truth gate "
        "because Scrapling's Fetcher uses curl_cffi internally."
    ),
)

_BLOCKED = frozenset((302, 403))


@_skip_if_no_scrapling
def test_scrapling_fetcher_blocked(daemon_url: str) -> None:
    from scrapling import Fetcher

    fetcher = Fetcher(impersonate="chrome131", auto_match=False)
    resp = fetcher.get(daemon_url + "/", allow_redirects=False, timeout=10)
    status = getattr(resp, "status", None) or getattr(resp, "status_code", None)
    assert status in _BLOCKED, (
        f"Scrapling Fetcher(impersonate='chrome131') was NOT blocked — "
        f"daemon returned HTTP {status}."
    )


@pytest.mark.skip(
    reason=(
        "StealthyFetcher uses patchright + a real Chromium browser. "
        "Requires `playwright install chromium` in the container, which is too heavy for CI. "
        "Run locally: cd tests/scrapling && pip install scrapling playwright && "
        "playwright install chromium && pytest scenarios/test_scrapling_lib.py::test_scrapling_stealthy_fetcher_blocked"
    )
)
def test_scrapling_stealthy_fetcher_blocked(daemon_url: str) -> None:
    from scrapling import StealthyFetcher

    resp = StealthyFetcher.fetch(daemon_url + "/")
    status = getattr(resp, "status", None) or getattr(resp, "status_code", None)
    assert status in _BLOCKED, (
        f"StealthyFetcher was NOT blocked — daemon returned HTTP {status}."
    )
