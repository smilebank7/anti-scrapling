from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from flask import Flask, jsonify

from anti_scrapling import Decision, DecisionRequest, Verdict, flask_middleware
from anti_scrapling.client import Client


def _mock_client(verdict: Verdict) -> Client:
    c = MagicMock(spec=Client)
    c.decide.return_value = Decision(verdict=verdict, score=0)
    return c


def _make_app(verdict: Verdict, challenge_url: str = "/__as/challenge") -> Flask:
    app = Flask(__name__)
    client = _mock_client(verdict)

    @app.route("/hello")
    @flask_middleware(client, challenge_url=challenge_url)
    def hello():
        return jsonify({"message": "hello"})

    return app


def test_allow_returns_200():
    with _make_app(Verdict.ALLOW).test_client() as tc:
        resp = tc.get("/hello")
    assert resp.status_code == 200
    assert resp.get_json() == {"message": "hello"}


def test_deny_returns_403():
    with _make_app(Verdict.DENY).test_client() as tc:
        resp = tc.get("/hello")
    assert resp.status_code == 403


def test_challenge_redirects_302():
    with _make_app(Verdict.CHALLENGE).test_client() as tc:
        resp = tc.get("/hello", follow_redirects=False)
    assert resp.status_code == 302
    assert "/__as/challenge" in resp.location


def test_custom_challenge_url():
    with _make_app(Verdict.CHALLENGE, challenge_url="/verify").test_client() as tc:
        resp = tc.get("/hello", follow_redirects=False)
    assert resp.status_code == 302
    assert "/verify" in resp.location


def test_client_decide_called_with_request_fields():
    app = Flask(__name__)
    mock = _mock_client(Verdict.ALLOW)

    @app.route("/api")
    @flask_middleware(mock)
    def api():
        return jsonify({})

    with app.test_client() as tc:
        tc.get("/api", headers={"User-Agent": "TestAgent/1.0", "Host": "example.com"})

    mock.decide.assert_called_once()
    req: DecisionRequest = mock.decide.call_args[0][0]
    assert req.method == "GET"
    assert req.path == "/api"
    assert "user-agent" in req.headers
