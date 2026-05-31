import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base, get_db
from main import app, API_SECRET_KEY
from wg_engine import WireGuardEngine

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def client():
    connection = engine.connect()
    Base.metadata.create_all(bind=connection)
    db = TestingSessionLocal(bind=connection)
    app.dependency_overrides[get_db] = lambda: db
    yield TestClient(app)
    db.close()
    connection.close()
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def bypass_kernel_io(monkeypatch):
    monkeypatch.setattr(WireGuardEngine, "sync_peer_to_kernel", lambda *a, **k: None)
    monkeypatch.setattr(
        WireGuardEngine, "drop_peer_from_kernel", lambda *a, **k: None
    )


class TestAddPeer:
    def test_add_peer_success(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.post("/peers", json={}, headers=headers)
        assert res.status_code == 201
        data = res.json()
        assert data["public_key"]
        assert data["allowed_ips"].endswith("/32")
        assert "created_at" in data

    def test_auto_generates_keys(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.post("/peers", json={}, headers=headers)
        data = res.json()
        assert data["public_key"]
        assert data["private_key"]

    def test_with_explicit_public_key(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        payload = {"public_key": "xTIBdExlFbFKB5NUhVq3PPcEb4P+Jw4O6itFnH+Dhjc="}
        res = client.post("/peers", json=payload, headers=headers)
        assert res.status_code == 201
        assert res.json()["public_key"] == payload["public_key"]
        assert res.json()["private_key"] is None

    def test_with_device_name(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        payload = {"device_name": "My-Laptop"}
        res = client.post("/peers", json=payload, headers=headers)
        assert res.status_code == 201
        assert res.json()["device_name"] == "My-Laptop"

    def test_duplicate_public_key_returns_400(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        pub_key = "xTIBdExlFbFKB5NUhVq3PPcEb4P+Jw4O6itFnH+Dhjc="
        client.post("/peers", json={"public_key": pub_key}, headers=headers)
        res = client.post("/peers", json={"public_key": pub_key}, headers=headers)
        assert res.status_code == 400
        assert "collision" in res.json()["detail"]

    def test_allocates_consecutive_ips(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        p1 = client.post("/peers", json={}, headers=headers).json()
        p2 = client.post("/peers", json={}, headers=headers).json()
        assert p1["allowed_ips"] == "10.9.0.2/32"
        assert p2["allowed_ips"] == "10.9.0.3/32"

    def test_config_file_is_well_formed(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.post("/peers", json={}, headers=headers)
        data = res.json()
        cfg = data["config_file"]
        assert "[Interface]" in cfg
        assert "[Peer]" in cfg
        assert "PrivateKey" in cfg.split("[Interface]")[1].split("[Peer]")[0]
        assert "PublicKey" in cfg.split("[Peer]")[1]
        assert "Endpoint" in cfg
        assert "AllowedIPs" in cfg


class TestListPeers:
    def test_list_empty(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/peers", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_list_with_items(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        client.post("/peers", json={}, headers=headers)
        client.post("/peers", json={}, headers=headers)
        res = client.get("/peers", headers=headers)
        assert res.status_code == 200
        assert len(res.json()) == 2


class TestGetPeer:
    def test_get_existing(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.get(f"/peers/{peer['id']}", headers=headers)
        assert res.status_code == 200
        assert res.json()["id"] == peer["id"]

    def test_get_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/peers/9999", headers=headers)
        assert res.status_code == 404


class TestUpdatePeer:
    def test_update_device_name(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.put(
            f"/peers/{peer['id']}",
            json={"device_name": "Updated-Device"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["device_name"] == "Updated-Device"

    def test_update_allowed_ips(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.put(
            f"/peers/{peer['id']}",
            json={"allowed_ips": "10.9.0.10/32"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["allowed_ips"] == "10.9.0.10/32"

    def test_update_nonexistent_peer(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.put(
            "/peers/9999",
            json={"device_name": "Nope"},
            headers=headers,
        )
        assert res.status_code == 404

    def test_update_peer_duplicate_ip(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
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
        headers = {"X-API-KEY": API_SECRET_KEY}
        peer = client.post("/peers", json={}, headers=headers).json()
        res = client.delete(f"/peers/{peer['id']}", headers=headers)
        assert res.status_code == 204
        get_res = client.get(f"/peers/{peer['id']}", headers=headers)
        assert get_res.status_code == 404

    def test_delete_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.delete("/peers/9999", headers=headers)
        assert res.status_code == 404

    def test_delete_peer_requires_auth(self, client):
        res = client.delete("/peers/1")
        assert res.status_code == 403
