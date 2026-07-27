#!/usr/bin/env bash
# Launch the dirty vuln playground (binds 0.0.0.0:$PORT).
set -euo pipefail
cd "$(dirname "$0")"
export HOST="${HOST:-0.0.0.0}"
export PORT="${PORT:-${PLAYGROUND_PORT:-9080}}"
if python3 -c "import waitress" 2>/dev/null; then
  exec python3 -m waitress --host="$HOST" --port="$PORT" --threads=8 wsgi:app
fi
exec python3 app.py --host "$HOST" --port "$PORT"
