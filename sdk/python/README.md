# anti-scrapling Python SDK

Thin proxy to the anti-scrapling daemon's `POST /v1/decide` endpoint.  
Supports FastAPI/Starlette (ASGI) and Flask (WSGI).

## Install

```bash
pip install "anti-scrapling[fastapi]"   # FastAPI / Starlette
pip install "anti-scrapling[flask]"     # Flask
pip install "anti-scrapling"            # bare client only
```

## FastAPI / Starlette

```python
from fastapi import FastAPI
from anti_scrapling import Client, AntiScraplingMiddleware

app = FastAPI()
client = Client(daemon_url="http://localhost:9092", timeout=0.2, fail_open=True)
app.add_middleware(AntiScraplingMiddleware, client=client)

@app.get("/api/data")
def data():
    return {"ok": True}
```

Responses by verdict:

| Verdict     | HTTP action                     |
|-------------|---------------------------------|
| `ALLOW`     | request forwarded to your route |
| `CHALLENGE` | `302 → /__as/challenge`         |
| `DENY`      | `403 Forbidden`                 |

Custom challenge redirect:

```python
app.add_middleware(AntiScraplingMiddleware, client=client, challenge_url="/bot-gate")
```

## Flask

```python
from flask import Flask, jsonify
from anti_scrapling import Client, flask_middleware

app = Flask(__name__)
client = Client(daemon_url="http://localhost:9092")

@app.route("/api/data")
@flask_middleware(client)
def data():
    return jsonify({"ok": True})
```

## Client options

```python
Client(
    daemon_url="http://localhost:9092",  # daemon base URL
    timeout=0.2,                          # per-request timeout in seconds
    fail_open=True,                       # True → ALLOW on daemon error; False → DENY
)
```

Sync and async both available:

```python
decision = client.decide(req)            # sync (Flask-friendly)
decision = await client.decide_async(req) # async (ASGI-friendly)
```

## Running tests

```bash
pip install -e ".[dev]"
pytest
```
