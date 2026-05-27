from __future__ import annotations

from typing import Any, Awaitable, Callable

from .client import Client
from .types import DecisionRequest, Verdict

Scope = dict[str, Any]
Receive = Callable[[], Awaitable[dict]]
Send = Callable[[dict], Awaitable[None]]


class AntiScraplingMiddleware:
    def __init__(self, app: Any, client: Client, challenge_url: str = "/__as/challenge") -> None:
        self._app = app
        self._client = client
        self._challenge_url = challenge_url

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        req = self._build_request(scope)
        decision = await self._client.decide_async(req)

        if decision.verdict == Verdict.ALLOW:
            await self._app(scope, receive, send)
        elif decision.verdict == Verdict.CHALLENGE:
            await _redirect(send, self._challenge_url)
        else:
            await _deny(send)

    @staticmethod
    def _build_request(scope: Scope) -> DecisionRequest:
        headers: dict[str, str] = {}
        header_order: list[str] = []
        for raw_name, raw_value in scope.get("headers", []):
            name = raw_name.decode("latin-1").lower()
            if name not in headers:
                headers[name] = raw_value.decode("latin-1")
                header_order.append(name)

        host = headers.get("host", "")
        client_info = scope.get("client")
        remote_ip = client_info[0] if client_info else ""

        path: str = scope.get("path", "/")
        qs = scope.get("query_string", b"")
        if qs:
            path = path + "?" + qs.decode("latin-1")

        return DecisionRequest(
            method=scope.get("method", "GET"),
            path=path,
            host=host,
            remote_ip=remote_ip,
            headers=headers,
            header_order=header_order,
        )


async def _redirect(send: Send, url: str) -> None:
    await send({"type": "http.response.start", "status": 302, "headers": [(b"location", url.encode())]})
    await send({"type": "http.response.body", "body": b""})


async def _deny(send: Send) -> None:
    await send({"type": "http.response.start", "status": 403, "headers": [(b"content-type", b"text/plain")]})
    await send({"type": "http.response.body", "body": b"Forbidden"})
