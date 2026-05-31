FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app
COPY uv.lock pyproject.toml ./
RUN uv sync --frozen --no-dev

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app /app
COPY --from=builder /root/.local /root/.local
COPY . /app
WORKDIR /app
ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1
EXPOSE 8000
CMD ["sh", "-c", "uv run uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
