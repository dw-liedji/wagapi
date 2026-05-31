# wagapi — WireGuard Hybrid SSOT Controller v4.0.0

REST API for provisioning dynamic WireGuard interfaces and peers via the Linux kernel.

## Quick start

```sh
uv sync                               # install dependencies (uses uv.lock)
sudo .venv/bin/uvicorn main:app --reload   # dev server (requires root for WireGuard kernel calls)
```

## Test

```sh
uv run pytest                          # 89 tests, no root required
uv run pytest test_api.py -xvs        # mock tests only
uv run pytest test_models.py -xvs     # model CRUD tests only
uv run pytest test_integration.py -xvs  # full API stack tests
```

## API

Authentication: `X-API-KEY` header. Set via `WAGAPI_API_KEY` env var (default fallback: `ProductionSecretDynamicTunnelAPIKeyCredentialToken`).

| Method | Path | Description |
|---|---|---|
| `GET` | `/interfaces` | List all dynamic interfaces |
| `GET` | `/interfaces/{id}` | Get a single interface |
| `POST` | `/interfaces` | Create a dynamic WireGuard interface |
| `PUT` | `/interfaces/{id}` | Update interface (endpoint, dns, listen_port, subnet_pool) |
| `DELETE` | `/interfaces/{id}` | Destroy an interface |
| `GET` | `/interfaces/{id}/peers` | List peers on an interface |
| `GET` | `/interfaces/{id}/peers/{pid}` | Get a single peer with config |
| `POST` | `/interfaces/{id}/peers` | Add a peer (auto-generates keys if omitted) |
| `PUT` | `/interfaces/{id}/peers/{pid}` | Update peer (device_name, allowed_ips) |
| `DELETE` | `/interfaces/{id}/peers/{pid}` | Remove a peer from DB and kernel |

Reserved: interface name `wg0` and port `51820` (static infra).

## Try from browser

- Swagger UI: `http://localhost:8001/docs`
- ReDoc: `http://localhost:8001/redoc`

### curl examples

All endpoints require the `X-API-KEY` header. Replace `/1` with actual IDs.

#### Interfaces

```sh
# ── LIST ────────────────────────────────────────────────────
curl -s http://localhost:8001/interfaces \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" | jq

# Response (200):
# [
#   { "id": 1, "name": "wg1", "listen_port": 51821, ... }
# ]

# ── CREATE ──────────────────────────────────────────────────
curl -s -X POST http://localhost:8001/interfaces \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"name":"wg1","listen_port":51821,"endpoint":"vpn.example.com:51821"}' | jq

# Response (201):
# {
#   "id": 1, "name": "wg1", "subnet_pool": "10.9.0.0/16",
#   "listen_port": 51821, "public_key": "6L...UQ=",
#   "endpoint": "vpn.example.com:51821", "dns": "1.1.1.1",
#   "created_at": "2026-05-31T..."
# }

# ── GET ─────────────────────────────────────────────────────
curl -s http://localhost:8001/interfaces/1 \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" | jq

# Response (200): single interface object (same shape as CREATE response)

# ── UPDATE ──────────────────────────────────────────────────
curl -s -X PUT http://localhost:8001/interfaces/1 \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"endpoint":"new.example.com:51821","dns":"8.8.8.8"}' | jq

# Response (200): updated interface object

# ── DELETE ──────────────────────────────────────────────────
curl -s -X DELETE http://localhost:8001/interfaces/1 \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" -w "\n%{http_code}\n"

# Response: 204 No Content
```

#### Peers

```sh
# ── LIST ────────────────────────────────────────────────────
curl -s http://localhost:8001/interfaces/1/peers \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" | jq

# Response (200):
# [
#   { "id": 1, "interface_id": 1, "device_name": "...", ... }
# ]

# ── CREATE (auto key) ───────────────────────────────────────
curl -s -X POST http://localhost:8001/interfaces/1/peers \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"device_name":"Developer-Laptop"}' | jq

# Response (201):
# {
#   "id": 1, "interface_id": 1, "device_name": "Developer-Laptop",
#   "public_key": "Q4...8Q=", "private_key": "sL...cI=",
#   "allowed_ips": "10.9.0.2/32", "created_at": "2026-05-31T...",
#   "config_file": "[Interface]\nPrivateKey = sL...cI=\n..."
# }

# ── CREATE (explicit key) ───────────────────────────────────
curl -s -X POST http://localhost:8001/interfaces/1/peers \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"public_key":"xTIBdExlFbFKB5NUhVq3PPcEb4P+Jw4O6itFnH+Dhjc="}' | jq

# Response (201): same shape, but private_key is null

# ── GET ─────────────────────────────────────────────────────
curl -s http://localhost:8001/interfaces/1/peers/1 \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" | jq

# Response (200): single peer object with config_file

# ── UPDATE ──────────────────────────────────────────────────
curl -s -X PUT http://localhost:8001/interfaces/1/peers/1 \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" \
  -d '{"device_name":"New-Device","allowed_ips":"10.9.0.10/32"}' | jq

# Response (200): updated peer object

# ── DELETE ──────────────────────────────────────────────────
curl -s -X DELETE http://localhost:8001/interfaces/1/peers/1 \
  -H "X-API-KEY: ProductionSecretDynamicTunnelAPIKeyCredentialToken" -w "\n%{http_code}\n"

# Response: 204 No Content
```

#### IP allocation

Interfaces created with the default `subnet_pool` (`10.9.0.0/16`) allocate consecutive `/32` IPs starting at `.2` (`.1` is reserved as gateway). View all allocations via `GET /interfaces/{id}/peers`.

## Docker / Dokploy

### Build & run

```sh
docker compose up --build
```

Requires `NET_ADMIN`, `SYS_MODULE` capabilities and `/dev/net/tun` device access.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `WAGAPI_API_KEY` | `ProductionSecretDynamicTunnelAPIKeyCredentialToken` | API auth key (`X-API-KEY` header) |
| `WAGAPI_DATA_DIR` | `data` | Directory for SQLite database |
| `PORT` | `8001` | Uvicorn listen port |

### Dokploy deployment

1. Set the container **Port** to `8001` (or match `PORT` env).
2. Add **NET_ADMIN** + **SYS_MODULE** capabilities.
3. Add `/dev/net/tun` device if WireGuard kernel ops are needed.
4. Mount a persistent volume at the path set in `WAGAPI_DATA_DIR`.
5. Set `WAGAPI_API_KEY` to a strong random value.

## Notes

- **Kernel**: Requires Linux with the `wireguard` module, `iproute2`, and root for actual kernel operations. All kernel I/O is monkeypatched in tests.
- **DB**: SQLite at `{WAGAPI_DATA_DIR}/wireguard_dynamic.db`. Defaults to `./data/` if not set. Tables created at startup — no Alembic/migrations.
- **Config**: The `pyproject.toml` has no `[tool.ruff]` section — ruff uses defaults.
