from __future__ import annotations

import httpx

from .types import Decision, DecisionRequest, Signal, Verdict


class Client:
    def __init__(
        self,
        daemon_url: str = "http://localhost:9092",
        timeout: float = 0.2,
        fail_open: bool = True,
    ) -> None:
        self._url = daemon_url.rstrip("/") + "/v1/decide"
        self._timeout = timeout
        self._fail_open = fail_open

    def _payload(self, req: DecisionRequest) -> dict:
        return {
            "method": req.method,
            "path": req.path,
            "host": req.host,
            "remote_ip": req.remote_ip,
            "headers": req.headers,
            "header_order": req.header_order,
            "ja3": req.ja3,
            "ja4": req.ja4,
            "token": req.token,
        }

    def _parse(self, data: dict) -> Decision:
        signals = [
            Signal(
                name=s.get("name", ""),
                score=s.get("score", 0),
                reason=s.get("reason", ""),
                detail=s.get("detail") or {},
            )
            for s in (data.get("signals") or [])
        ]
        return Decision(
            verdict=Verdict(data.get("verdict", "ALLOW")),
            score=data.get("score", 0),
            signals=signals,
            reasons=data.get("reasons") or [],
            policy_name=data.get("policy_name", ""),
            timestamp=data.get("timestamp", 0),
            request_id=data.get("request_id", ""),
        )

    def _fallback(self) -> Decision:
        v = Verdict.ALLOW if self._fail_open else Verdict.DENY
        return Decision(verdict=v, score=0)

    async def decide_async(self, req: DecisionRequest) -> Decision:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as c:
                resp = await c.post(self._url, json=self._payload(req))
                resp.raise_for_status()
                return self._parse(resp.json())
        except Exception:
            return self._fallback()

    def decide(self, req: DecisionRequest) -> Decision:
        try:
            with httpx.Client(timeout=self._timeout) as c:
                resp = c.post(self._url, json=self._payload(req))
                resp.raise_for_status()
                return self._parse(resp.json())
        except Exception:
            return self._fallback()
