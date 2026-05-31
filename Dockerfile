# ---------------------------------------------------------
# STAGE 1: Builder (Dependencies & venv)
# ---------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

# ---------------------------------------------------------
# STAGE 2: Runtime (Minimal, Non-Root)
# ---------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------
# Create non-root user (fixed UID/GID for volumes)
# ---------------------------------------------------------
RUN addgroup --system --gid 1000 app \
    && adduser --system --uid 1000 --ingroup app app

WORKDIR /app

RUN mkdir -p /data \
    && chown -R app:app /data

# ---------------------------------------------------------
# Copy virtualenv & source code
# ---------------------------------------------------------
COPY --from=builder /app/.venv /app/.venv
COPY --chown=app:app . /app

# ---------------------------------------------------------
# Setup entrypoint
# ---------------------------------------------------------
RUN chmod +x /app/entrypoint.sh

# USER app

CMD ["/app/entrypoint.sh"]
