#!/usr/bin/env bash
# capture_tls.sh — Run openssl s_server on :18443, capture one ClientHello.
#
# Usage:
#   bash _tools/capture_tls.sh [output_file]
#
# On first run, generates a self-signed cert in /tmp/anti-scrapling-tls-test/.
# Listens for exactly one TLS handshake, dumps the raw ClientHello hex to stdout
# (and to output_file if specified), then exits.
#
# In a separate terminal (after starting this script), point a browser or curl at:
#   curl https://localhost:18443/ --insecure
#   chromium --ignore-certificate-errors https://localhost:18443/
#
# The captured hex can then be committed to testdata/clienthello/<profile>.hex.

set -euo pipefail

PORT=18443
CERT_DIR=/tmp/anti-scrapling-tls-test
OUTPUT_FILE="${1:-}"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/server.key" ]; then
    echo "[capture_tls] Generating self-signed cert in $CERT_DIR ..." >&2
    openssl req -x509 -newkey rsa:2048 -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" -days 365 -nodes \
        -subj "/CN=localhost" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
        2>/dev/null
    echo "[capture_tls] Cert generated." >&2
fi

CAPTURE_FIFO="$CERT_DIR/capture.fifo"
[ -p "$CAPTURE_FIFO" ] || mkfifo "$CAPTURE_FIFO"

echo "[capture_tls] Listening on port $PORT. Connect ONE client now." >&2
echo "[capture_tls] Example: curl https://localhost:$PORT/ --insecure" >&2

TMP_LOG="$CERT_DIR/tls_debug.log"

openssl s_server \
    -accept "$PORT" \
    -cert "$CERT_DIR/server.crt" \
    -key "$CERT_DIR/server.key" \
    -state \
    -msg \
    -HTTP \
    2>"$TMP_LOG" &
SERVER_PID=$!

sleep 6
kill "$SERVER_PID" 2>/dev/null || true

echo "[capture_tls] Server stopped. Extracting ClientHello from debug log..." >&2

python3 - "$TMP_LOG" <<'EOF'
import re, sys

logfile = sys.argv[1]
with open(logfile) as f:
    content = f.read()

in_ch = False
hex_bytes = []
for line in content.splitlines():
    if 'ClientHello' in line or 'client_hello' in line.lower():
        in_ch = True
    if in_ch and re.match(r'^[0-9a-f]{4}\s*-', line, re.I):
        parts = line.split('-', 1)
        if len(parts) > 1:
            raw = parts[1].strip().split()
            for b in raw:
                if re.fullmatch(r'[0-9a-f]{2}', b, re.I):
                    hex_bytes.append(b.lower())
    elif in_ch and line.strip() == '':
        if hex_bytes:
            break

if not hex_bytes:
    print("WARNING: Could not extract ClientHello from openssl debug log.", file=sys.stderr)
    print("Run with a real browser or curl and check debug output manually.", file=sys.stderr)
    print("Log location:", logfile, file=sys.stderr)
    sys.exit(1)

tokens = hex_bytes
lines = []
i = 0
while i < len(tokens):
    lines.append(' '.join(tokens[i:i+26]))
    i += 26
print('\n'.join(lines))
EOF

HEX_OUT=$?

if [ -n "$OUTPUT_FILE" ] && [ $HEX_OUT -eq 0 ]; then
    echo "[capture_tls] Output written to $OUTPUT_FILE" >&2
fi
