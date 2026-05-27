from __future__ import annotations

import httpx
import pytest
from fastapi import FastAPI

from anti_scrapling import AntiScraplingMiddleware, Decision, DecisionRequest, Verdict


class _MockClient:
    def __init__(self, verdict: Verdict, score: int = 0) -> None:
        self._verdict = verdict
        self._score = score

    async def decide_async(self, req: DecisionRequest) -> Decision:
        return Decision(verdict=self._verdict, score=self._score)


def _make_app(verdict: Verdict) -> FastAPI:
    app = FastAPI()
    app.add_middleware(AntiScraplingMiddleware, client=_MockClient(verdict))

    @app.get("/hello")
    def hello():
        return {"message": "hello"}

    return app


async def _get(app: FastAPI, path: str, follow_redirects: bool = True) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", follow_redirects=follow_redirects) as ac:
        return await ac.get(path)


async def test_allow_passes_through():
    resp = await _get(_make_app(Verdict.ALLOW), "/hello")
    assert resp.status_code == 200
    assert resp.json() == {"message": "hello"}


async def test_deny_returns_403():
    resp = await _get(_make_app(Verdict.DENY), "/hello")
    assert resp.status_code == 403


async def test_challenge_redirects_302():
    resp = await _get(_make_app(Verdict.CHALLENGE), "/hello", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/__as/challenge"


async def test_non_http_scope_bypasses():
    app = FastAPI()
    mock_inner = []

    async def inner(scope, receive, send):
        mock_inner.append(scope["type"])

    mw = AntiScraplingMiddleware(inner, _MockClient(Verdict.DENY))
    await mw({"type": "lifespan"}, None, None)
    assert mock_inner == ["lifespan"]


async def test_custom_challenge_url():
    app = FastAPI()
    app.add_middleware(AntiScraplingMiddleware, client=_MockClient(Verdict.CHALLENGE), challenge_url="/bot-check")

    @app.get("/data")
    def data():
        return {}

    resp = await _get(app, "/data", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/bot-check"
