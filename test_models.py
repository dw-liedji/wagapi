import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Interface, Peer
from wg_engine import WireGuardEngine

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(autouse=True)
def db_session():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.rollback()
    db.close()
    Base.metadata.drop_all(bind=engine)


def make_interface(**kwargs) -> Interface:
    priv, pub = WireGuardEngine.generate_keypair()
    fields = {
        "name": "wg1",
        "listen_port": 51821,
        "endpoint": "vpn.test.com:51821",
        "private_key": priv,
        "public_key": pub,
        **kwargs,
    }
    return Interface(**fields)


class TestInterfaceCreate:
    def test_minimal_fields(self, db_session):
        iface = make_interface()
        db_session.add(iface)
        db_session.commit()
        assert iface.id is not None
        assert iface.name == "wg1"
        assert iface.listen_port == 51821
        assert iface.subnet_pool == "10.9.0.0/16"
        assert iface.dns == "1.1.1.1"

    def test_default_dns(self, db_session):
        iface = make_interface()
        db_session.add(iface)
        db_session.commit()
        assert iface.dns == "1.1.1.1"

    def test_default_subnet_pool(self, db_session):
        iface = make_interface()
        db_session.add(iface)
        db_session.commit()
        assert iface.subnet_pool == "10.9.0.0/16"

    def test_created_at_is_set_on_add(self, db_session):
        iface = make_interface()
        db_session.add(iface)
        db_session.commit()
        assert iface.created_at is not None


class TestInterfaceUniqueConstraints:
    def test_duplicate_name_raises(self, db_session):
        iface1 = make_interface(name="dup", listen_port=52001)
        iface2 = make_interface(name="dup", listen_port=52002)
        db_session.add(iface1)
        db_session.commit()
        db_session.add(iface2)
        with pytest.raises(Exception):
            db_session.commit()
        db_session.rollback()

    def test_duplicate_port_raises(self, db_session):
        iface1 = make_interface(name="port1", listen_port=53001)
        iface2 = make_interface(name="port2", listen_port=53001)
        db_session.add(iface1)
        db_session.commit()
        db_session.add(iface2)
        with pytest.raises(Exception):
            db_session.commit()
        db_session.rollback()


class TestInterfaceRead:
    def test_query_by_name(self, db_session):
        iface = make_interface(name="findme", listen_port=54001)
        db_session.add(iface)
        db_session.commit()
        found = db_session.query(Interface).filter(Interface.name == "findme").first()
        assert found is not None
        assert found.id == iface.id

    def test_query_by_port(self, db_session):
        iface = make_interface(name="byport", listen_port=54002)
        db_session.add(iface)
        db_session.commit()
        found = (
            db_session.query(Interface).filter(Interface.listen_port == 54002).first()
        )
        assert found is not None

    def test_not_found_returns_none(self, db_session):
        found = (
            db_session.query(Interface).filter(Interface.name == "nonexistent").first()
        )
        assert found is None


class TestInterfaceUpdate:
    def test_update_endpoint(self, db_session):
        iface = make_interface()
        db_session.add(iface)
        db_session.commit()
        iface.endpoint = "updated.test.com:51821"
        db_session.commit()
        db_session.refresh(iface)
        assert iface.endpoint == "updated.test.com:51821"

    def test_update_dns(self, db_session):
        iface = make_interface()
        db_session.add(iface)
        db_session.commit()
        iface.dns = "8.8.8.8"
        db_session.commit()
        db_session.refresh(iface)
        assert iface.dns == "8.8.8.8"


class TestInterfaceDelete:
    def test_delete_removes_row(self, db_session):
        iface = make_interface(name="delete_me", listen_port=55001)
        db_session.add(iface)
        db_session.commit()
        iface_id = iface.id
        db_session.delete(iface)
        db_session.commit()
        found = db_session.get(Interface, iface_id)
        assert found is None

    def test_cascade_deletes_peers(self, db_session):
        iface = make_interface(name="cascade_test", listen_port=55002)
        db_session.add(iface)
        db_session.commit()
        peer = Peer(
            interface_id=iface.id,
            public_key="test_pub_key_cascade",
            allowed_ips="10.9.0.2/32",
        )
        db_session.add(peer)
        db_session.commit()
        db_session.delete(iface)
        db_session.commit()
        found = (
            db_session.query(Peer)
            .filter(Peer.public_key == "test_pub_key_cascade")
            .first()
        )
        assert found is None


class TestPeerRelationship:
    def test_add_peers_to_interface(self, db_session):
        iface = make_interface(name="rel_test", listen_port=56001)
        db_session.add(iface)
        db_session.commit()
        peer1 = Peer(
            interface_id=iface.id,
            public_key="peer_pub_1",
            allowed_ips="10.9.0.2/32",
        )
        peer2 = Peer(
            interface_id=iface.id,
            public_key="peer_pub_2",
            allowed_ips="10.9.0.3/32",
        )
        db_session.add_all([peer1, peer2])
        db_session.commit()
        db_session.refresh(iface)
        assert len(iface.peers) == 2

    def test_peer_belongs_to_interface(self, db_session):
        iface = make_interface(name="parent_test", listen_port=57001)
        db_session.add(iface)
        db_session.commit()
        peer = Peer(
            interface_id=iface.id,
            public_key="peer_parent",
            allowed_ips="10.9.0.4/32",
        )
        db_session.add(peer)
        db_session.commit()
        assert peer.interface_rel.id == iface.id
