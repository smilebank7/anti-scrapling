#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

python3 -m http.server 3000 &>/dev/null &
UP_PID=$!
trap "kill $UP_PID 2>/dev/null; pkill -f 'bin/antiscrapling' 2>/dev/null || true" EXIT

make build 2>/dev/null || true

AS_TARGET=http://localhost:3000 \
  ./bin/antiscrapling --config policies/default.yaml --admin-bind :9091 --metrics-bind :9090 &

sleep 3

cd "$ROOT/tests/scrapling"
pip install -q pytest httpx "curl-cffi>=0.7" requests 2>/dev/null || true
pip install -q "scrapling==0.2.99" 2>/dev/null || pip install -q scrapling 2>/dev/null || true

DAEMON_URL=http://localhost:8080 DECIDE_URL=http://localhost:9091 \
  python3 -m pytest -v scenarios/
