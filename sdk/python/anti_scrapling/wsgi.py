from __future__ import annotations

import functools
from typing import Callable

from .client import Client
from .types import DecisionRequest, Verdict


def flask_middleware(client: Client, challenge_url: str = "/__as/challenge") -> Callable:
    def decorator(view_fn: Callable) -> Callable:
        @functools.wraps(view_fn)
        def wrapper(*args, **kwargs):
            from flask import abort, redirect
            from flask import request as flask_req

            headers = {k.lower(): v for k, v in flask_req.headers.items()}
            header_order = [k.lower() for k in flask_req.headers.keys()]

            req = DecisionRequest(
                method=flask_req.method,
                path=flask_req.full_path.rstrip("?"),
                host=flask_req.host,
                remote_ip=flask_req.remote_addr or "",
                headers=headers,
                header_order=header_order,
            )
            decision = client.decide(req)

            if decision.verdict == Verdict.ALLOW:
                return view_fn(*args, **kwargs)
            if decision.verdict == Verdict.CHALLENGE:
                return redirect(challenge_url)
            abort(403)

        return wrapper
    return decorator
