#!/usr/bin/env bash
# Launch the dirty vuln playground (binds 0.0.0.0:$PORT).
set -euo pipefail
cd "$(dirname "$0")"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-${PLAYGROUND_PORT:-9080}}"
exec python3 app.py --host "$HOST" --port "$PORT"
