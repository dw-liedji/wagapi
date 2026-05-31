# wagapi — WireGuard Peer Manager for wg0

REST API for managing WireGuard peers on a pre-existing `wg0` interface via the Linux kernel.

## Quick start

```sh
uv sync                               # install dependencies (uses uv.lock)
sudo .venv/bin/uvicorn main:app --reload   # dev server (requires root for WireGuard kernel calls)
```

## Test

```sh
uv run pytest                          # all tests, no root required
uv run pytest test_api.py -xvs        # mock tests only
uv run pytest test_models.py -xvs     # model CRUD tests only
uv run pytest test_integration.py -xvs  # full API stack tests
```

## API

Authentication: `X-API-KEY` header. Set via `WAGAPI_API_KEY` env var (default fallback: `ProductionSecretDynamicTunnelAPIKeyCredentialToken`).

| Method | Path | Description |
|---|---|---|
| `GET` | `/peers` | List all peers on wg0 |
| `GET` | `/peers/{id}` | Get a single peer with config |
| `POST` | `/peers` | Add a peer (auto-generates keys if omitted) |
| `PUT` | `/peers/{id}` | Update peer (device_name, allowed_ips) |
| `DELETE` | `/peers/{id}` | Remove a peer from DB and kernel |

### wg0 configuration (env vars)

| Variable | Default | Description |
|---|---|---|
| `WG0_PUBLIC_KEY` | `wg0_public_key_placeholder` | Public key used in generated peer config files |
| `WG0_ENDPOINT` | `vpn.example.com:51820` | Endpoint used in generated peer config files |
| `WG0_DNS` | `1.1.1.1` | DNS server used in generated peer config files |
| `SUBNET_POOL` | `10.9.0.0/16` | Subnet pool for peer IP allocation |

### IP allocation

Peers are assigned consecutive `/32` IPs from the `SUBNET_POOL` starting at `.2` (`.1` is reserved as gateway). View all allocations via `GET /peers`.

## Try from browser

- Swagger UI: `http://localhost:8001/docs`
- ReDoc: `http://localhost:8001/redoc`

### curl examples

All endpoints require the `X-API-KEY` header.

```sh
# ── LIST ────────────────────────────────────────────────────
curl -s http://localhost:8001/peers \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" | jq

# ── CREATE (auto key) ───────────────────────────────────────
curl -s -X POST http://localhost:8001/peers \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"device_name":"Developer-Laptop"}' | jq

# Response (201):
# {
#   "id": 1, "device_name": "Developer-Laptop",
#   "public_key": "Q4...8Q=", "private_key": "sL...cI=",
#   "allowed_ips": "10.9.0.2/32", "created_at": "2026-05-31T...",
#   "config_file": "[Interface]\nPrivateKey = sL...cI=\n..."
# }

# ── CREATE (explicit key) ───────────────────────────────────
curl -s -X POST http://localhost:8001/peers \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"public_key":"xTIBdExlFbFKB5NUhVq3PPcEb4P+Jw4O6itFnH+Dhjc="}' | jq

# ── GET ─────────────────────────────────────────────────────
curl -s http://localhost:8001/peers/1 \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" | jq

# ── UPDATE ──────────────────────────────────────────────────
curl -s -X PUT http://localhost:8001/peers/1 \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"device_name":"New-Device","allowed_ips":"10.9.0.10/32"}' | jq

# ── DELETE ──────────────────────────────────────────────────
curl -s -X DELETE http://localhost:8001/peers/1 \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" -w "\n%{http_code}\n"

# Response: 204 No Content
```

## Docker / Dokploy

Requires `NET_ADMIN`, `SYS_MODULE` capabilities and `/dev/net/tun` device access.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `WAGAPI_API_KEY` | `ProductionSecretDynamicTunnelAPIKeyCredentialToken` | API auth key (`X-API-KEY` header) |
| `WAGAPI_DATA_DIR` | `data` | Directory for SQLite database |
| `PORT` | `8001` | Uvicorn listen port |

## Notes

- **Kernel**: Requires Linux with the `wireguard` module, `iproute2`, and root for actual kernel operations. All kernel I/O is monkeypatched in tests.
- **DB**: SQLite at `{WAGAPI_DATA_DIR}/wireguard_dynamic.db`. Defaults to `./data/` if not set. Tables created at startup — no Alembic/migrations.
- **Config**: The `pyproject.toml` has no `[tool.ruff]` section — ruff uses defaults.
