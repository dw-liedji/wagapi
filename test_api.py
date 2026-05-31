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
    monkeypatch.setattr(
        WireGuardEngine, "render_entire_interface_from_db", lambda *a, **k: None
    )
    monkeypatch.setattr(WireGuardEngine, "sync_peer_to_kernel", lambda *a, **k: None)
    monkeypatch.setattr(
        WireGuardEngine, "destroy_interface_from_kernel", lambda *a, **k: None
    )
    monkeypatch.setattr(
        WireGuardEngine, "drop_peer_from_kernel", lambda *a, **k: None
    )


def test_create_interface(client):
    headers = {"X-API-KEY": API_SECRET_KEY}
    payload = {"name": "test1", "listen_port": 51999, "endpoint": "vpn.test.com:51999"}
    res = client.post("/interfaces", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["name"] == "test1"


def test_static_guard_restrictions(client):
    headers = {"X-API-KEY": API_SECRET_KEY}
    payload = {"name": "wg0", "listen_port": 51820, "endpoint": "vpn.foo.com:51820"}

    res = client.post("/interfaces", json=payload, headers=headers)
    assert res.status_code == 400
    assert "reserved" in res.json()["detail"]


def _create_iface(client, headers, port=51821, name="wg1"):
    payload = {"name": name, "listen_port": port, "endpoint": f"vpn.test.com:{port}"}
    res = client.post("/interfaces", json=payload, headers=headers)
    assert res.status_code == 201
    return res.json()


class TestAddPeer:
    def test_add_peer_success(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers)
        res = client.post(f"/interfaces/{iface['id']}/peers", json={}, headers=headers)
        assert res.status_code == 201
        data = res.json()
        assert data["interface_id"] == iface["id"]
        assert data["public_key"]
        assert data["allowed_ips"].endswith("/32")
        assert "created_at" in data

    def test_auto_generates_keys(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers)
        res = client.post(f"/interfaces/{iface['id']}/peers", json={}, headers=headers)
        data = res.json()
        assert data["public_key"]
        assert data["private_key"]

    def test_with_explicit_public_key(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers)
        payload = {"public_key": "xTIBdExlFbFKB5NUhVq3PPcEb4P+Jw4O6itFnH+Dhjc="}
        res = client.post(
            f"/interfaces/{iface['id']}/peers", json=payload, headers=headers
        )
        assert res.status_code == 201
        assert res.json()["public_key"] == payload["public_key"]
        assert res.json()["private_key"] is None

    def test_with_device_name(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers)
        payload = {"device_name": "My-Laptop"}
        res = client.post(
            f"/interfaces/{iface['id']}/peers", json=payload, headers=headers
        )
        assert res.status_code == 201
        assert res.json()["device_name"] == "My-Laptop"

    def test_nonexistent_interface_returns_404(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.post("/interfaces/9999/peers", json={}, headers=headers)
        assert res.status_code == 404

    def test_duplicate_public_key_returns_400(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51901)
        pub_key = "xTIBdExlFbFKB5NUhVq3PPcEb4P+Jw4O6itFnH+Dhjc="
        client.post(
            f"/interfaces/{iface['id']}/peers",
            json={"public_key": pub_key},
            headers=headers,
        )
        res = client.post(
            f"/interfaces/{iface['id']}/peers",
            json={"public_key": pub_key},
            headers=headers,
        )
        assert res.status_code == 400
        assert "collision" in res.json()["detail"]

    def test_allocates_consecutive_ips(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51902)
        p1 = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        p2 = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        assert p1["allowed_ips"] == "10.9.0.2/32"
        assert p2["allowed_ips"] == "10.9.0.3/32"

    def test_config_file_is_well_formed(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51903)
        res = client.post(f"/interfaces/{iface['id']}/peers", json={}, headers=headers)
        data = res.json()
        cfg = data["config_file"]
        assert "[Interface]" in cfg
        assert "[Peer]" in cfg
        assert "PrivateKey" in cfg.split("[Interface]")[1].split("[Peer]")[0]
        assert "PublicKey" in cfg.split("[Peer]")[1]
        assert "Endpoint" in cfg
        assert "AllowedIPs" in cfg


class TestListInterfaces:
    def test_list_empty(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/interfaces", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_list_with_items(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        _create_iface(client, headers, port=51821, name="list_a")
        _create_iface(client, headers, port=51822, name="list_b")
        res = client.get("/interfaces", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert len(data) == 2


class TestGetInterface:
    def test_get_existing(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51823)
        res = client.get(f"/interfaces/{iface['id']}", headers=headers)
        assert res.status_code == 200
        assert res.json()["id"] == iface["id"]

    def test_get_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/interfaces/9999", headers=headers)
        assert res.status_code == 404


class TestUpdateInterface:
    def test_update_endpoint(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51824)
        res = client.put(
            f"/interfaces/{iface['id']}",
            json={"endpoint": "new.example.com:51824"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["endpoint"] == "new.example.com:51824"

    def test_update_dns(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51825)
        res = client.put(
            f"/interfaces/{iface['id']}",
            json={"dns": "8.8.8.8"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["dns"] == "8.8.8.8"

    def test_update_to_reserved_port(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51826)
        res = client.put(
            f"/interfaces/{iface['id']}",
            json={"listen_port": 51820},
            headers=headers,
        )
        assert res.status_code == 400

    def test_update_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.put(
            "/interfaces/9999",
            json={"endpoint": "x.com:9999"},
            headers=headers,
        )
        assert res.status_code == 404

    def test_update_subnet_pool(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51827)
        res = client.put(
            f"/interfaces/{iface['id']}",
            json={"subnet_pool": "10.10.0.0/16"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["subnet_pool"] == "10.10.0.0/16"

    def test_update_port_requires_auth(self, client):
        res = client.put("/interfaces/1", json={"endpoint": "x.com:1"})
        assert res.status_code == 403


class TestListPeers:
    def test_list_empty(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51828)
        res = client.get(f"/interfaces/{iface['id']}/peers", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_list_with_items(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51829)
        client.post(f"/interfaces/{iface['id']}/peers", json={}, headers=headers)
        client.post(f"/interfaces/{iface['id']}/peers", json={}, headers=headers)
        res = client.get(f"/interfaces/{iface['id']}/peers", headers=headers)
        assert res.status_code == 200
        assert len(res.json()) == 2

    def test_list_nonexistent_interface(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/interfaces/9999/peers", headers=headers)
        assert res.status_code == 404


class TestGetPeer:
    def test_get_existing(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51830)
        peer = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        res = client.get(
            f"/interfaces/{iface['id']}/peers/{peer['id']}", headers=headers
        )
        assert res.status_code == 200
        assert res.json()["id"] == peer["id"]

    def test_get_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51831)
        res = client.get(
            f"/interfaces/{iface['id']}/peers/9999", headers=headers
        )
        assert res.status_code == 404

    def test_get_peer_wrong_interface(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface1 = _create_iface(client, headers, port=51832, name="get_a")
        iface2 = _create_iface(client, headers, port=51833, name="get_b")
        peer = client.post(
            f"/interfaces/{iface1['id']}/peers", json={}, headers=headers
        ).json()
        res = client.get(
            f"/interfaces/{iface2['id']}/peers/{peer['id']}", headers=headers
        )
        assert res.status_code == 404


class TestUpdatePeer:
    def test_update_device_name(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51834)
        peer = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        res = client.put(
            f"/interfaces/{iface['id']}/peers/{peer['id']}",
            json={"device_name": "Updated-Device"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["device_name"] == "Updated-Device"

    def test_update_allowed_ips(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51835)
        peer = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        res = client.put(
            f"/interfaces/{iface['id']}/peers/{peer['id']}",
            json={"allowed_ips": "10.9.0.10/32"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["allowed_ips"] == "10.9.0.10/32"

    def test_update_nonexistent_peer(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51836)
        res = client.put(
            f"/interfaces/{iface['id']}/peers/9999",
            json={"device_name": "Nope"},
            headers=headers,
        )
        assert res.status_code == 404

    def test_update_peer_duplicate_ip(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51837)
        p1 = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        p2 = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        res = client.put(
            f"/interfaces/{iface['id']}/peers/{p2['id']}",
            json={"allowed_ips": p1["allowed_ips"]},
            headers=headers,
        )
        assert res.status_code == 400
        assert "already allocated" in res.json()["detail"]


class TestDeletePeer:
    def test_delete_peer(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51838)
        peer = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        res = client.delete(
            f"/interfaces/{iface['id']}/peers/{peer['id']}", headers=headers
        )
        assert res.status_code == 204
        get_res = client.get(
            f"/interfaces/{iface['id']}/peers/{peer['id']}", headers=headers
        )
        assert get_res.status_code == 404

    def test_delete_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, port=51839)
        res = client.delete(
            f"/interfaces/{iface['id']}/peers/9999", headers=headers
        )
        assert res.status_code == 404

    def test_delete_peer_requires_auth(self, client):
        res = client.delete("/interfaces/1/peers/1")
        assert res.status_code == 403
