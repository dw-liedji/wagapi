from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime, timezone
from database import Base


class Peer(Base):
    __tablename__ = "dynamic_peers"

    id = Column(Integer, primary_key=True, autoincrement=True, index=True)
    device_name = Column(String, nullable=True)
    public_key = Column(String, unique=True, nullable=False, index=True)
    private_key = Column(String, nullable=True)
    allowed_ips = Column(String, unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
