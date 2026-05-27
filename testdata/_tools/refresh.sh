#!/usr/bin/env bash
# refresh.sh — Regenerate testdata from canonical sources.
#
# PROVENANCE MAP
# ==============
#
# clienthello/*.hex
#   Source: gen_clienthello.py (representative reconstructions from documented
#           JA3/JA4 values at tls.peet.ws, salesforce/ja3, FoxIO-LLC/ja4).
#   To re-capture from a real browser: see _tools/capture_tls.sh.
#   To regenerate from documented values: python3 _tools/gen_clienthello.py
#
# http2/*.bin.placeholder
#   Source: Stub placeholders. Real captures require a live H2 server and
#           Wireshark capture. See W1-T2 task for production capture plan.
#   Reference values in *.expected.json come from:
#     https://www.akamai.com/blog/security/passive-os-fingerprinting
#     https://github.com/nicowillis/tls-fingerprints
#
# headers/*.txt
#   Source: Hand-crafted from browser DevTools / curl -v output.
#   Reference: browserforge header generator source code.
#
# fingerprint/*.json
#   Source: Synthesized from threat-model probes in docs/01-threat-model.md.
#   Schema: FingerprintReport Go type (internal/types/fingerprint.go).
#   To update: edit JSON directly; validate with _tools/verify.sh.
#
# behavior/*.json
#   Source: Synthesized from behavioral telemetry model in docs/01-threat-model.md.
#   Schema: BehaviorBeacon Go type (internal/types/behavior.go).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTDATA_DIR="$(dirname "$SCRIPT_DIR")"

echo "Regenerating clienthello test vectors..."
python3 "$SCRIPT_DIR/gen_clienthello.py"

echo "Validating all JSON files..."
bash "$SCRIPT_DIR/verify.sh"

echo "Done."
