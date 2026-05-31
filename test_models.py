import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models import Peer

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


class TestPeerCreate:
    def test_minimal_fields(self, db_session):
        peer = Peer(public_key="test_pub_key_minimal", allowed_ips="10.9.0.2/32")
        db_session.add(peer)
        db_session.commit()
        assert peer.id is not None
        assert peer.device_name is None

    def test_with_device_name(self, db_session):
        peer = Peer(
            device_name="My-Laptop",
            public_key="test_pub_key_device",
            allowed_ips="10.9.0.3/32",
        )
        db_session.add(peer)
        db_session.commit()
        assert peer.device_name == "My-Laptop"

    def test_created_at_is_set(self, db_session):
        peer = Peer(public_key="test_pub_key_time", allowed_ips="10.9.0.4/32")
        db_session.add(peer)
        db_session.commit()
        assert peer.created_at is not None


class TestPeerUniqueConstraints:
    def test_duplicate_public_key_raises(self, db_session):
        peer1 = Peer(public_key="dup_key", allowed_ips="10.9.0.5/32")
        peer2 = Peer(public_key="dup_key", allowed_ips="10.9.0.6/32")
        db_session.add(peer1)
        db_session.commit()
        db_session.add(peer2)
        with pytest.raises(Exception):
            db_session.commit()
        db_session.rollback()

    def test_duplicate_allowed_ips_raises(self, db_session):
        peer1 = Peer(public_key="key1", allowed_ips="10.9.0.7/32")
        peer2 = Peer(public_key="key2", allowed_ips="10.9.0.7/32")
        db_session.add(peer1)
        db_session.commit()
        db_session.add(peer2)
        with pytest.raises(Exception):
            db_session.commit()
        db_session.rollback()


class TestPeerRead:
    def test_query_by_public_key(self, db_session):
        peer = Peer(public_key="find_key", allowed_ips="10.9.0.8/32")
        db_session.add(peer)
        db_session.commit()
        found = db_session.query(Peer).filter(Peer.public_key == "find_key").first()
        assert found is not None
        assert found.id == peer.id

    def test_not_found_returns_none(self, db_session):
        found = db_session.query(Peer).filter(Peer.public_key == "nonexistent").first()
        assert found is None


class TestPeerUpdate:
    def test_update_device_name(self, db_session):
        peer = Peer(public_key="update_key", allowed_ips="10.9.0.9/32")
        db_session.add(peer)
        db_session.commit()
        peer.device_name = "New-Name"
        db_session.commit()
        db_session.refresh(peer)
        assert peer.device_name == "New-Name"

    def test_update_allowed_ips(self, db_session):
        peer = Peer(public_key="update_ip_key", allowed_ips="10.9.0.10/32")
        db_session.add(peer)
        db_session.commit()
        peer.allowed_ips = "10.9.0.100/32"
        db_session.commit()
        db_session.refresh(peer)
        assert peer.allowed_ips == "10.9.0.100/32"


class TestPeerDelete:
    def test_delete_removes_row(self, db_session):
        peer = Peer(public_key="delete_key", allowed_ips="10.9.0.11/32")
        db_session.add(peer)
        db_session.commit()
        peer_id = peer.id
        db_session.delete(peer)
        db_session.commit()
        found = db_session.get(Peer, peer_id)
        assert found is None
