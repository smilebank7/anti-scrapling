from __future__ import annotations

import httpx
import pytest
import respx

from anti_scrapling import Client, Decision, DecisionRequest, Verdict

DAEMON = "http://daemon-test:9092"
DECIDE = f"{DAEMON}/v1/decide"

_ALLOW = {
    "verdict": "ALLOW", "score": 0, "signals": [], "reasons": [],
    "policy_name": "default", "timestamp": 0, "request_id": "r1",
}
_CHALLENGE = {
    "verdict": "CHALLENGE", "score": 50, "signals": [], "reasons": ["ua_mismatch"],
    "policy_name": "default", "timestamp": 0, "request_id": "r2",
}
_DENY = {
    "verdict": "DENY", "score": 100, "signals": [], "reasons": ["blocked"],
    "policy_name": "strict", "timestamp": 0, "request_id": "r3",
}


def _req() -> DecisionRequest:
    return DecisionRequest(
        method="GET", path="/data", host="example.com", remote_ip="1.2.3.4",
        headers={"user-agent": "Mozilla/5.0"}, header_order=["user-agent"],
    )


@respx.mock
async def test_decide_async_allow():
    respx.post(DECIDE).mock(return_value=httpx.Response(200, json=_ALLOW))
    d = await Client(daemon_url=DAEMON).decide_async(_req())
    assert d.verdict == Verdict.ALLOW
    assert d.score == 0
    assert d.request_id == "r1"


@respx.mock
async def test_decide_async_challenge():
    respx.post(DECIDE).mock(return_value=httpx.Response(200, json=_CHALLENGE))
    d = await Client(daemon_url=DAEMON).decide_async(_req())
    assert d.verdict == Verdict.CHALLENGE
    assert d.score == 50
    assert "ua_mismatch" in d.reasons


@respx.mock
async def test_decide_async_deny():
    respx.post(DECIDE).mock(return_value=httpx.Response(200, json=_DENY))
    d = await Client(daemon_url=DAEMON).decide_async(_req())
    assert d.verdict == Verdict.DENY
    assert d.policy_name == "strict"


@respx.mock
async def test_timeout_fail_open():
    respx.post(DECIDE).mock(side_effect=httpx.TimeoutException("timed out"))
    d = await Client(daemon_url=DAEMON, fail_open=True).decide_async(_req())
    assert d.verdict == Verdict.ALLOW


@respx.mock
async def test_timeout_fail_closed():
    respx.post(DECIDE).mock(side_effect=httpx.TimeoutException("timed out"))
    d = await Client(daemon_url=DAEMON, fail_open=False).decide_async(_req())
    assert d.verdict == Verdict.DENY


@respx.mock
async def test_http_error_fail_open():
    respx.post(DECIDE).mock(return_value=httpx.Response(502))
    d = await Client(daemon_url=DAEMON, fail_open=True).decide_async(_req())
    assert d.verdict == Verdict.ALLOW


@respx.mock
def test_decide_sync_allow():
    respx.post(DECIDE).mock(return_value=httpx.Response(200, json=_ALLOW))
    d = Client(daemon_url=DAEMON).decide(_req())
    assert d.verdict == Verdict.ALLOW


@respx.mock
def test_decide_sync_fail_open():
    respx.post(DECIDE).mock(side_effect=httpx.TimeoutException("timed out"))
    d = Client(daemon_url=DAEMON, fail_open=True).decide(_req())
    assert d.verdict == Verdict.ALLOW
