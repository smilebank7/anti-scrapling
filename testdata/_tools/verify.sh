#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDATA_DIR="$(dirname "$SCRIPT_DIR")"

cd "$TESTDATA_DIR"

echo "=== Validating fingerprint JSON files ==="
for f in fingerprint/*.json; do
    python3 -c "import json,sys; json.load(open('$f'))" && echo "OK: $f"
done

echo ""
echo "=== Validating behavior JSON files ==="
for f in behavior/*.json; do
    python3 -c "import json,sys; json.load(open('$f'))" && echo "OK: $f"
done

echo ""
echo "=== Validating clienthello expected JSON files ==="
for f in clienthello/*.expected.json; do
    python3 -c "import json,sys; d=json.load(open('$f')); assert 'ja3' in d and 'ja3_hash' in d and 'ja4' in d and 'browser_family' in d, 'missing required field'" \
        && echo "OK: $f"
done

echo ""
echo "=== Validating clienthello hex files ==="
for f in clienthello/*.hex; do
    head -1 "$f" | grep -q "^16 03" || (echo "Not a ClientHello: $f"; exit 1)
    echo "OK: $f"
done

echo ""
echo "=== Validating http2 expected JSON files ==="
for f in http2/*.expected.json; do
    python3 -c "import json,sys; json.load(open('$f'))" && echo "OK: $f"
done

echo ""
echo "=== Validating headers expected JSON files ==="
for f in headers/*.expected.json; do
    python3 -c "import json,sys; json.load(open('$f'))" && echo "OK: $f"
done

echo ""
echo "All checks passed."
