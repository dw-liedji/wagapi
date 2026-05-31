# wagapi — WireGuard Hybrid SSOT Controller

## Commands

```sh
uv sync                          # install deps (uv.lock)
sudo .venv/bin/uvicorn main:app --reload   # dev server (needs root for kernel calls)
uv run pytest                    # all 89 tests, no root required
uv run pytest test_api.py -xvs   # mock API tests only
uv run pytest test_models.py -xvs # model CRUD tests only
uv run pytest test_integration.py -xvs # full-stack integration tests
```

## Structure

| File | Role |
|---|---|
| `main.py` | FastAPI app, full CRUD: Interfaces (GET list, GET, POST, PUT, DELETE) + Peers (GET list, GET, POST, PUT, DELETE) |
| `wg_engine.py` | WireGuard kernel I/O (pyroute2) — **all methods monkeypatched in tests** |
| `models.py` | SQLAlchemy: `Interface` / `Peer` |
| `schemas.py` | Pydantic request/response models |
| `database.py` | SQLite engine, tables from `WAGAPI_DATA_DIR` (default `data/`), created at startup |
| `test_api.py` | Mock API layer tests |
| `test_models.py` | Model persistence tests |
| `test_integration.py` | Full stack tests with kernel I/O stubbed |

## Gotchas

- **No migrations** — tables are `create_all` on startup via lifespan handler.
- **No ruff config** in pyproject.toml — uses `ruff` defaults.
- **Auth**: hardcoded `X-API-KEY` header value in `main.py:12`.
- **Reserved**: interface name `wg0` and port `51820` (static infra).
- **DB**: SQLite at `{DATA_DIR}/wireguard_dynamic.db`. Override with `WAGAPI_DATA_DIR`.
- **Tests use `random` ports** in integration tests to avoid collisions — don't hardcode port numbers.
- `pyproject.toml` has a pytest warning filter for deprecated `httpx` + `starlette.testclient` usage.
