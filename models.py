from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from database import Base


class Interface(Base):
    __tablename__ = "dynamic_interfaces"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    subnet_pool = Column(String, nullable=False, default="10.9.0.0/16")
    listen_port = Column(Integer, unique=True, nullable=False)
    private_key = Column(String, nullable=False)
    public_key = Column(String, nullable=False)
    dns = Column(String, default="1.1.1.1")
    endpoint = Column(String, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    peers = relationship(
        "Peer", back_populates="interface_rel", cascade="all, delete-orphan"
    )


class Peer(Base):
    __tablename__ = "dynamic_peers"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    interface_id = Column(Integer, ForeignKey("dynamic_interfaces.id"), nullable=False)
    device_name = Column(String, nullable=True)
    public_key = Column(String, unique=True, nullable=False, index=True)
    allowed_ips = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    interface_rel = relationship("Interface", back_populates="peers")
