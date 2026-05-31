"""Integration tests that exercise the full API stack with monkeypatched kernel I/O.

All four WireGuardEngine kernel methods are stubbed out, so no root required.
"""

import random
import uuid

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


@pytest.fixture(autouse=True)
def bypass_kernel_netlink(monkeypatch):
    monkeypatch.setattr(
        WireGuardEngine, "render_entire_interface_from_db", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        WireGuardEngine, "sync_peer_to_kernel", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        WireGuardEngine, "drop_peer_from_kernel", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        WireGuardEngine, "destroy_interface_from_kernel", lambda *args, **kwargs: None
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


@pytest.fixture
def ifname():
    return f"itest_{uuid.uuid4().hex[:8]}"


def _create_iface(client, headers, ifname, port, subnet="10.200.0.0/16"):
    payload = {
        "name": ifname,
        "listen_port": port,
        "endpoint": f"vpn.example.com:{port}",
        "subnet_pool": subnet,
    }
    res = client.post("/interfaces", json=payload, headers=headers)
    assert res.status_code == 201, res.text
    return res.json()


class TestInterfaceCreate:
    def test_happy_path(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        port = random.randint(51001, 51999)
        data = _create_iface(client, headers, ifname, port)
        assert data["name"] == ifname
        assert data["listen_port"] == port
        assert data["public_key"]
        assert data["subnet_pool"] == "10.200.0.0/16"
        assert data["dns"] == "1.1.1.1"

    def test_reserved_name_wg0(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.post(
            "/interfaces",
            json={
                "name": "wg0",
                "listen_port": 52001,
                "endpoint": "vpn.test.com:52001",
            },
            headers=headers,
        )
        assert res.status_code == 400
        assert "reserved" in res.json()["detail"]

    def test_reserved_port_51820(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.post(
            "/interfaces",
            json={
                "name": "wg_test",
                "listen_port": 51820,
                "endpoint": "vpn.test.com:51820",
            },
            headers=headers,
        )
        assert res.status_code == 400
        assert "reserved" in res.json()["detail"]

    def test_duplicate_name_rejected(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        _create_iface(client, headers, ifname, random.randint(52001, 52999))
        res = client.post(
            "/interfaces",
            json={
                "name": ifname,
                "listen_port": random.randint(53001, 53999),
                "endpoint": f"vpn.test.com:{random.randint(53001, 53999)}",
            },
            headers=headers,
        )
        assert res.status_code == 400

    def test_duplicate_port_rejected(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        port = random.randint(54001, 54999)
        _create_iface(client, headers, ifname, port)
        name2 = f"itest_{uuid.uuid4().hex[:8]}"
        res = client.post(
            "/interfaces",
            json={
                "name": name2,
                "listen_port": port,
                "endpoint": f"vpn.test.com:{port}",
            },
            headers=headers,
        )
        assert res.status_code == 400


class TestInterfaceDelete:
    def test_delete_existing(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(client, headers, ifname, random.randint(55001, 55999))
        res = client.delete(f"/interfaces/{data['id']}", headers=headers)
        assert res.status_code == 204

    def test_delete_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.delete("/interfaces/99999", headers=headers)
        assert res.status_code == 404

    def test_delete_orphaned_kernel(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(client, headers, ifname, random.randint(56001, 56999))
        res = client.delete(f"/interfaces/{data['id']}", headers=headers)
        assert res.status_code == 204


class TestPeerCreate:
    def test_add_auto_key(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, ifname, random.randint(57001, 57999))
        res = client.post(f"/interfaces/{iface['id']}/peers", json={}, headers=headers)
        assert res.status_code == 201, res.text
        data = res.json()
        assert data["interface_id"] == iface["id"]
        assert data["public_key"]
        assert data["private_key"]

    def test_add_explicit_key(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, ifname, random.randint(58001, 58999))
        pub, _ = WireGuardEngine.generate_keypair()
        res = client.post(
            f"/interfaces/{iface['id']}/peers",
            json={"public_key": pub},
            headers=headers,
        )
        assert res.status_code == 201, res.text
        assert res.json()["public_key"] == pub
        assert res.json()["private_key"] is None

    def test_with_device_name(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, ifname, random.randint(59001, 59999))
        res = client.post(
            f"/interfaces/{iface['id']}/peers",
            json={"device_name": "Test-Device"},
            headers=headers,
        )
        assert res.status_code == 201
        assert res.json()["device_name"] == "Test-Device"

    def test_nonexistent_interface_404(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.post("/interfaces/99999/peers", json={}, headers=headers)
        assert res.status_code == 404

    def test_duplicate_public_key_rejected(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, ifname, random.randint(60001, 60999))
        pub, _ = WireGuardEngine.generate_keypair()
        client.post(
            f"/interfaces/{iface['id']}/peers",
            json={"public_key": pub},
            headers=headers,
        )
        res = client.post(
            f"/interfaces/{iface['id']}/peers",
            json={"public_key": pub},
            headers=headers,
        )
        assert res.status_code == 400
        assert "collision" in res.json()["detail"]

    def test_consecutive_ip_allocation(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, ifname, random.randint(61001, 61999))
        p1 = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        p2 = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        assert p1["allowed_ips"] == "10.200.0.2/32"
        assert p2["allowed_ips"] == "10.200.0.3/32"

    def test_config_file_is_well_formed(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, ifname, random.randint(62001, 62999))
        data = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        cfg = data["config_file"]
        assert "[Interface]" in cfg
        assert "[Peer]" in cfg
        assert "PrivateKey" in cfg.split("[Interface]")[1].split("[Peer]")[0]
        assert "PublicKey" in cfg.split("[Peer]")[1]
        assert "Endpoint" in cfg
        assert "0.0.0.0/0" in cfg


class TestApiResponseShape:
    def test_interface_response_shape(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(client, headers, ifname, random.randint(63001, 63999))
        assert set(data.keys()) == {
            "id",
            "name",
            "subnet_pool",
            "listen_port",
            "public_key",
            "endpoint",
            "dns",
            "created_at",
        }
        assert isinstance(data["id"], int)
        assert isinstance(data["created_at"], str)

    def test_peer_response_shape(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(client, headers, ifname, random.randint(64001, 64999))
        data = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        assert set(data.keys()) == {
            "id",
            "interface_id",
            "device_name",
            "public_key",
            "private_key",
            "allowed_ips",
            "created_at",
            "config_file",
        }
        assert isinstance(data["id"], int)
        assert data["allowed_ips"].endswith("/32")


class TestAuth:
    def test_missing_api_key(self, client):
        res = client.post(
            "/interfaces", json={"name": "x", "listen_port": 67001, "endpoint": "x"}
        )
        assert res.status_code == 403

    def test_wrong_api_key(self, client):
        res = client.post(
            "/interfaces",
            json={"name": "x", "listen_port": 67002, "endpoint": "x"},
            headers={"X-API-KEY": "wrong"},
        )
        assert res.status_code == 403

    def test_no_auth_on_peer_create(self, client):
        res = client.post("/interfaces/1/peers", json={})
        assert res.status_code == 403

    def test_no_auth_on_delete(self, client):
        res = client.delete("/interfaces/1")
        assert res.status_code == 403


class TestListInterfaces:
    def test_list_empty(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/interfaces", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_list_with_items(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        _create_iface(
            client, headers, f"{ifname}_a", random.randint(65001, 65099)
        )
        _create_iface(
            client, headers, f"{ifname}_b", random.randint(65101, 65199)
        )
        res = client.get("/interfaces", headers=headers)
        assert res.status_code == 200
        assert len(res.json()) == 2

    def test_list_requires_auth(self, client):
        res = client.get("/interfaces")
        assert res.status_code == 403


class TestGetInterface:
    def test_get_existing(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(
            client, headers, ifname, random.randint(65201, 65299)
        )
        res = client.get(f"/interfaces/{data['id']}", headers=headers)
        assert res.status_code == 200
        assert res.json()["id"] == data["id"]

    def test_get_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/interfaces/99999", headers=headers)
        assert res.status_code == 404


class TestUpdateInterface:
    def test_update_endpoint(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(
            client, headers, ifname, random.randint(65301, 65399)
        )
        new_endpoint = f"new.{ifname}.com:{data['listen_port']}"
        res = client.put(
            f"/interfaces/{data['id']}",
            json={"endpoint": new_endpoint},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["endpoint"] == new_endpoint

    def test_update_dns(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(
            client, headers, ifname, random.randint(65401, 65499)
        )
        res = client.put(
            f"/interfaces/{data['id']}",
            json={"dns": "8.8.8.8"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["dns"] == "8.8.8.8"

    def test_update_to_reserved_port(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(
            client, headers, ifname, random.randint(65501, 65599)
        )
        res = client.put(
            f"/interfaces/{data['id']}",
            json={"listen_port": 51820},
            headers=headers,
        )
        assert res.status_code == 400

    def test_update_nonexistent(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.put(
            "/interfaces/99999",
            json={"endpoint": "x.com:9999"},
            headers=headers,
        )
        assert res.status_code == 404


class TestListPeers:
    def test_list_empty(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(
            client, headers, ifname, random.randint(65601, 65699)
        )
        res = client.get(f"/interfaces/{data['id']}/peers", headers=headers)
        assert res.status_code == 200
        assert res.json() == []

    def test_list_with_items(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        data = _create_iface(
            client, headers, ifname, random.randint(65701, 65799)
        )
        client.post(f"/interfaces/{data['id']}/peers", json={}, headers=headers)
        client.post(f"/interfaces/{data['id']}/peers", json={}, headers=headers)
        res = client.get(f"/interfaces/{data['id']}/peers", headers=headers)
        assert res.status_code == 200
        assert len(res.json()) == 2

    def test_list_nonexistent_interface(self, client):
        headers = {"X-API-KEY": API_SECRET_KEY}
        res = client.get("/interfaces/99999/peers", headers=headers)
        assert res.status_code == 404


class TestGetPeer:
    def test_get_existing(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(65801, 65899)
        )
        peer = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        res = client.get(
            f"/interfaces/{iface['id']}/peers/{peer['id']}", headers=headers
        )
        assert res.status_code == 200
        assert res.json()["id"] == peer["id"]
        assert res.json()["config_file"]

    def test_get_nonexistent(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(65901, 65999)
        )
        res = client.get(
            f"/interfaces/{iface['id']}/peers/99999", headers=headers
        )
        assert res.status_code == 404


class TestUpdatePeer:
    def test_update_device_name(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(66001, 66099)
        )
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

    def test_update_allowed_ips(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(66101, 66199)
        )
        peer = client.post(
            f"/interfaces/{iface['id']}/peers", json={}, headers=headers
        ).json()
        res = client.put(
            f"/interfaces/{iface['id']}/peers/{peer['id']}",
            json={"allowed_ips": "10.200.0.100/32"},
            headers=headers,
        )
        assert res.status_code == 200
        assert res.json()["allowed_ips"] == "10.200.0.100/32"

    def test_update_nonexistent_peer(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(66201, 66299)
        )
        res = client.put(
            f"/interfaces/{iface['id']}/peers/99999",
            json={"device_name": "Nope"},
            headers=headers,
        )
        assert res.status_code == 404

    def test_update_peer_duplicate_ip(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(66301, 66399)
        )
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
    def test_delete_peer(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(66401, 66499)
        )
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

    def test_delete_nonexistent(self, client, ifname):
        headers = {"X-API-KEY": API_SECRET_KEY}
        iface = _create_iface(
            client, headers, ifname, random.randint(66501, 66599)
        )
        res = client.delete(
            f"/interfaces/{iface['id']}/peers/99999", headers=headers
        )
        assert res.status_code == 404
