"""Integration tests that exercise the full API stack with monkeypatched kernel I/O.

Both WireGuardEngine kernel methods are stubbed out, so no root required.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
from main import app
from settings import settings
from wg_engine import WireGuardEngine

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def bypass_kernel_netlink(monkeypatch):
    monkeypatch.setattr(
        WireGuardEngine, "sync_peer_to_kernel", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        WireGuardEngine, "drop_peer_from_kernel", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        WireGuardEngine, "get_wg0_public_key", lambda: "test_wg0_public_key"
    )
    monkeypatch.setattr(
        WireGuardEngine, "ensure_wg0_interface", lambda: None
    )
    monkeypatch.setattr(
        WireGuardEngine, "sync_all_peers_to_kernel", lambda *args, **kwargs: None
    )


@pytest.fixture(scope="function")
def client():
    import database as db_mod
    import main as main_mod

    db_mod.engine = engine
    main_mod.engine = engine
    db_mod.SessionLocal = TestingSessionLocal
    main_mod.SessionLocal = TestingSessionLocal

    connection = engine.connect()
    Base.metadata.create_all(bind=connection)
    db = TestingSessionLocal(bind=connection)
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app)
    db.close()
    connection.close()
    app.dependency_overrides.clear()


class TestPeerCreate:
    def test_happy_path(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        res = client.post("/peers", json={}, headers=headers)
        assert res.status_code == 201, res.text
        data = res.json()
        assert data["public_key"]
        assert data["private_key"]
        assert data["allowed_ips"].endswith("/32")

    def test_add_explicit_key(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        pub, _ = WireGuardEngine.generate_keypair()
        res = client.post(
            "/peers",
            json={"public_key": pub},
            headers=headers,
        )
        assert res.status_code == 201, res.text
        assert res.json()["public_key"] == pub
        assert res.json()["private_key"] is None

    def test_with_device_name(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        res = client.post(
            "/peers",
            json={"device_name": "Test-Device"},
            headers=headers,
        )
        assert res.status_code == 201
        assert res.json()["device_name"] == "Test-Device"

    def test_duplicate_public_key_rejected(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        pub, _ = WireGuardEngine.generate_keypair()
        client.post("/peers", json={"public_key": pub}, headers=headers)
        res = client.post("/peers", json={"public_key": pub}, headers=headers)
        assert res.status_code == 400
        assert "collision" in res.json()["detail"]

    def test_consecutive_ip_allocation(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        p1 = client.post("/peers", json={}, headers=headers).json()
        p2 = client.post("/peers", json={}, headers=headers).json()
        assert p1["allowed_ips"] == "10.9.0.2/32"
        assert p2["allowed_ips"] == "10.9.0.3/32"

    def test_config_file_is_well_formed(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        data = client.post("/peers", json={}, headers=headers).json()
        cfg = data["config_file"]
        assert "[Interface]" in cfg
        assert "[Peer]" in cfg
        assert "PrivateKey" in cfg.split("[Interface]")[1].split("[Peer]")[0]
        assert "PublicKey" in cfg.split("[Peer]")[1]
        assert "Endpoint" in cfg
        assert "AllowedIPs = " in cfg
        assert "0.0.0.0/0" not in cfg


class TestApiResponseShape:
    def test_peer_response_shape(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        data = client.post("/peers", json={}, headers=headers).json()
        assert set(data.keys()) == {
            "id",
            "device_name",
            "public_key",
            "private_key",
            "allowed_ips",
            "created_at",
            "config_file",
        }
        assert isinstance(data["id"], int)
        assert data["allowed_ips"].endswith("/32")

    def test_list_response_shape(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        client.post("/peers", json={}, headers=headers)
        res = client.get("/peers", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert len(data) == 1
        assert set(data[0].keys()) == {
            "id",
            "device_name",
            "public_key",
            "private_key",
            "allowed_ips",
            "created_at",
            "config_file",
        }


class TestAuth:
    def test_missing_api_key(self, client):
        res = client.post("/peers", json={"device_name": "x"})
        assert res.status_code == 403

    def test_wrong_api_key(self, client):
        res = client.post(
            "/peers",
            json={"device_name": "x"},
            headers={"X-API-KEY": "wrong"},
        )
        assert res.status_code == 403

    def test_no_auth_on_get(self, client):
        res = client.get("/peers")
        assert res.status_code == 403

    def test_no_auth_on_delete(self, client):
        res = client.delete("/peers/1")
        assert res.status_code == 403


class TestListPeers:
    def test_list_empty(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        res = client.get("/peers", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_list_with_items(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        client.post("/peers", json={}, headers=headers)
        client.post("/peers", json={}, headers=headers)
        res = client.get("/peers", headers=headers)
        assert res.status_code == 200
        assert len(res.json()) == 2

    def test_list_requires_auth(self, client):
        res = client.get("/peers")
        assert res.status_code == 403


class TestGetPeer:
    def test_get_existing(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.get(f"/peers/{peer['id']}", headers=headers)
        assert res.status_code == 200
        assert res.json()["id"] == peer["id"]
        assert res.json()["config_file"]

    def test_get_nonexistent(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        res = client.get("/peers/99999", headers=headers)
        assert res.status_code == 404


class TestUpdatePeer:
    def test_update_device_name(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.put(
            f"/peers/{peer['id']}",
            json={"device_name": "Updated-Device"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["device_name"] == "Updated-Device"

    def test_update_allowed_ips(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.put(
            f"/peers/{peer['id']}",
            json={"allowed_ips": "10.9.0.100/32"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["allowed_ips"] == "10.9.0.100/32"

    def test_update_nonexistent_peer(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        res = client.put(
            "/peers/99999",
            json={"device_name": "Nope"},
            headers=headers,
        )
        assert res.status_code == 404

    def test_update_peer_duplicate_ip(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        p1 = client.post("/peers", json={}, headers=headers).json()
        p2 = client.post("/peers", json={}, headers=headers).json()
        res = client.put(
            f"/peers/{p2['id']}",
            json={"allowed_ips": p1["allowed_ips"]},
            headers=headers,
        )
        assert res.status_code == 400
        assert "already allocated" in res.json()["detail"]


class TestDeletePeer:
    def test_delete_peer(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.delete(f"/peers/{peer['id']}", headers=headers)
        assert res.status_code == 204
        get_res = client.get(f"/peers/{peer['id']}", headers=headers)
        assert get_res.status_code == 404

    def test_delete_nonexistent(self, client):
        headers = {"X-API-KEY": settings.wagapi_api_key}
        res = client.delete("/peers/99999", headers=headers)
        assert res.status_code == 404
