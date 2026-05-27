import os
from urllib.parse import urlparse, urlunparse

import pytest


def _replace_port(url: str, port: int) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(netloc=f"{parsed.hostname}:{port}"))


DAEMON_URL = os.environ.get("DAEMON_URL", "http://localhost:8080")
DECIDE_URL = os.environ.get("DECIDE_URL", _replace_port(DAEMON_URL, 9091))


@pytest.fixture
def daemon_url() -> str:
    return DAEMON_URL


@pytest.fixture
def decide_url() -> str:
    return DECIDE_URL
