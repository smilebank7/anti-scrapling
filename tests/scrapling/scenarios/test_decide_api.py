import httpx
import pytest


_VALID_VERDICTS = frozenset(("ALLOW", "CHALLENGE", "DENY"))

_PYTHON_REQUESTS_JA3_HASH = "f8bfd03d8fe2b66ec606d235dacb30fa"


def test_decide_returns_valid_decision(decide_url: str) -> None:
    payload = {
        "method": "GET",
        "path": "/",
        "host": "example.com",
        "remote_ip": "203.0.113.1",
        "headers": {
            "User-Agent": "Mozilla/5.0 Chrome/131.0.0.0",
            "Accept": "text/html",
        },
        "header_order": ["User-Agent", "Accept"],
    }
    resp = httpx.post(decide_url + "/v1/decide", json=payload, timeout=10)
    assert resp.status_code == 200, (
        f"/v1/decide returned HTTP {resp.status_code}; expected 200. Body: {resp.text!r}"
    )
    data = resp.json()
    assert "Verdict" in data, f"Response JSON missing 'Verdict' field: {data}"
    assert data["Verdict"] in _VALID_VERDICTS, (
        f"Verdict {data['Verdict']!r} is not one of {_VALID_VERDICTS}"
    )


def test_decide_known_scraper_returns_deny(decide_url: str) -> None:
    payload = {
        "method": "GET",
        "path": "/sensitive-data",
        "host": "target.example.com",
        "remote_ip": "203.0.113.42",
        "headers": {
            "User-Agent": "python-requests/2.31.0",
        },
        "header_order": ["User-Agent"],
        "ja3": _PYTHON_REQUESTS_JA3_HASH,
    }
    resp = httpx.post(decide_url + "/v1/decide", json=payload, timeout=10)
    assert resp.status_code == 200, (
        f"/v1/decide returned HTTP {resp.status_code}. Body: {resp.text!r}"
    )
    data = resp.json()
    assert data.get("Verdict") == "DENY", (
        f"Expected DENY for python-requests JA3 hash ({_PYTHON_REQUESTS_JA3_HASH}) "
        f"which is deny-listed in families.go, but got Verdict={data.get('Verdict')!r}. "
        f"Full response: {data}"
    )
