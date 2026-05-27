from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    CHALLENGE = "CHALLENGE"
    DENY = "DENY"


@dataclass
class Signal:
    name: str
    score: int
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Decision:
    verdict: Verdict
    score: int
    signals: list[Signal] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    policy_name: str = ""
    timestamp: int = 0
    request_id: str = ""


@dataclass
class DecisionRequest:
    method: str
    path: str
    host: str
    remote_ip: str
    headers: dict[str, str] = field(default_factory=dict)
    header_order: list[str] = field(default_factory=list)
    ja3: str = ""
    ja4: str = ""
    token: str = ""
