# wagapi — WireGuard Peer Manager for wg0

Python 3.11-only. Package manager: `uv` (Astral). Single module, no monorepo.

## Commands

```sh
uv sync                                # install dependencies
uv run pytest                          # all tests (no root needed)
uv run pytest test_api.py -xvs         # mocked API tests
uv run pytest test_models.py -xvs      # model CRUD tests
uv run pytest test_integration.py -xvs # full stack with kernel I/O stubbed
sudo .venv/bin/uvicorn main:app --reload  # dev server (root for WireGuard kernel calls)
docker compose up --build              # containerised
```

## Architecture

| File | Role |
|---|---|
| `main.py` | FastAPI app, peer-only endpoints, startup lifespan |
| `database.py` | SQLAlchemy engine, SQLite at `{WAGAPI_DATA_DIR}/wireguard_dynamic.db` |
| `models.py` | ORM: `Peer` (`dynamic_peers`) |
| `schemas.py` | Pydantic v2 request/response models |
| `wg_engine.py` | `WireGuardEngine` static class — keypair gen (cryptography) + kernel I/O (pyroute2) |

- **No Alembic / migrations** — tables created at startup via `Base.metadata.create_all()`.
- Auth: `X-API-KEY` header, verified against `WAGAPI_API_KEY` env var (default: `ProductionSecretDynamicTunnelAPIKeyCredentialToken`).
- Single interface `wg0` is assumed to already exist in the kernel. The API only manages peers on wg0.
- Subnet pool default `10.9.0.0/16`, IPs allocated consecutively from `.2` (`.1` reserved as gateway). Configured via `SUBNET_POOL` env var.
- wg0 configuration for config generation: `WG0_PUBLIC_KEY`, `WG0_ENDPOINT`, `WG0_DNS` env vars.

## Testing quirks

- All tests use `sqlite:///:memory:` — no real DB needed.
- Every test file monkeypatches kernel methods (`sync_peer_to_kernel`, `drop_peer_from_kernel`) → **no root required**.
- `test_api.py` and `test_integration.py` have independent but similar fixtures; changes may need porting to both.
- `pyproject.toml` has no `[tool.ruff]` — ruff uses defaults.

## Docker / Dokploy

- Compose: `network_mode: host`, needs `NET_ADMIN` + `SYS_MODULE` caps, `/dev/net/tun`.
- Non-root user (UID 1000). Data directory must be writeable.
- `USER app` is **commented out** in `Dockerfile` — uncomment if kernel ops are not needed.

## Deploy gotchas

- WireGuard kernel module + `iproute2` + root required for real kernel operations.
- SQLite DB lives at `{WAGAPI_DATA_DIR}/wireguard_dynamic.db` — must be persisted across restarts.
- No CI workflows or pre-commit hooks configured.
