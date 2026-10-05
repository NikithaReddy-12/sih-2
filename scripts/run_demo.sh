#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BACKEND="$ROOT/backend"

if [[ ! -f "$ROOT/dist/index.html" ]]; then
  (cd "$ROOT" && npm run build)
fi

(cd "$BACKEND" && python -m uvicorn main:app --host 127.0.0.1 --port 8000) &
BACKEND_PID=$!

cleanup() {
  if kill -0 "$BACKEND_PID" 2>/dev/null; then
    kill "$BACKEND_PID" 2>/dev/null || true
    wait "$BACKEND_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

cd "$ROOT"
npm run preview -- --host 127.0.0.1 --port 5173
