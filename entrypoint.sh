#!/bin/sh
set -e

# modprobe wireguard 2>/dev/null || true

exec /app/.venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000