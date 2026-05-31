#!/bin/sh
set -e

modprobe wireguard 2>/dev/null || true

exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"
