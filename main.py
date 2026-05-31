import ipaddress
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, status, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from sqlalchemy.orm import Session

import models
import schemas
from database import engine, SessionLocal, get_db
from wg_engine import WireGuardEngine

API_SECRET_KEY = os.environ.get(
    "WAGAPI_API_KEY", "ProductionSecretDynamicTunnelAPIKeyCredentialToken"
)
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)

WG0_ENDPOINT = os.environ.get("WG0_ENDPOINT", "vpn.example.com:51820")
WG0_DNS = os.environ.get("WG0_DNS", "1.1.1.1")
SUBNET_POOL = os.environ.get("SUBNET_POOL", "10.9.0.0/16")


def require_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API Key."
        )


def allocate_next_ip(db: Session) -> str:
    network = ipaddress.ip_network(SUBNET_POOL)
    used_ips = {p.allowed_ips.split("/")[0] for p in db.query(models.Peer).all()}

    for ip in network.hosts():
        ip_str = str(ip)
        if ip_str.endswith(".1"):
            continue
        if ip_str not in used_ips:
            return f"{ip_str}/32"
    raise HTTPException(status_code=500, detail="Subnet address pool exhausted.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="WireGuard Hybrid SSOT Controller", version="4.0.0", lifespan=lifespan
)


@app.post(
    "/peers",
    response_model=schemas.PeerResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def add_peer(payload: schemas.PeerCreate, db: Session = Depends(get_db)):
    try:
        assigned_cidr = allocate_next_ip(db)
        private_key, public_key = None, payload.public_key
        if not public_key:
            private_key, public_key = WireGuardEngine.generate_keypair()

        if db.query(models.Peer).filter(models.Peer.public_key == public_key).first():
            raise HTTPException(
                status_code=400, detail="Public Key duplicate collision encountered."
            )

        db_peer = models.Peer(
            device_name=payload.device_name,
            public_key=public_key,
            private_key=private_key,
            allowed_ips=assigned_cidr,
        )
        db.add(db_peer)
        db.commit()
        db.refresh(db_peer)

        try:
            WireGuardEngine.sync_peer_to_kernel("wg0", public_key, assigned_cidr)
        except Exception as e:
            db.delete(db_peer)
            db.commit()
            raise HTTPException(
                status_code=500, detail=f"Kernel failed loading runtime rule: {str(e)}"
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Peer creation failed: {type(e).__name__}: {str(e)}"
        )

    return schemas.PeerResponse(
        id=db_peer.id,
        device_name=db_peer.device_name,
        public_key=db_peer.public_key,
        private_key=db_peer.private_key,
        allowed_ips=db_peer.allowed_ips,
        created_at=db_peer.created_at,
        config_file=_build_peer_config(db_peer),
    )


def _build_peer_config(peer: models.Peer) -> str:
    private_key = peer.private_key
    return (
        f"[Interface]\nPrivateKey = {private_key}\nAddress = {peer.allowed_ips}\n"
        f"DNS = {WG0_DNS}\n\n"
        f"[Peer]\nPublicKey = {WireGuardEngine.get_wg0_public_key()}\n"
        f"Endpoint = {WG0_ENDPOINT}\nAllowedIPs = {SUBNET_POOL}\n"
    )


def _peer_to_response(peer: models.Peer) -> schemas.PeerResponse:
    return schemas.PeerResponse(
        id=peer.id,
        device_name=peer.device_name,
        public_key=peer.public_key,
        private_key=peer.private_key,
        allowed_ips=peer.allowed_ips,
        created_at=peer.created_at,
        config_file=_build_peer_config(peer),
    )


@app.get(
    "/peers",
    response_model=list[schemas.PeerResponse],
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def list_peers(db: Session = Depends(get_db)):
    return [_peer_to_response(p) for p in db.query(models.Peer).all()]


@app.get(
    "/peers/{peer_id}",
    response_model=schemas.PeerResponse,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def get_peer(peer_id: int, db: Session = Depends(get_db)):
    peer = db.query(models.Peer).filter(models.Peer.id == peer_id).first()
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found.")
    return _peer_to_response(peer)


@app.put(
    "/peers/{peer_id}",
    response_model=schemas.PeerResponse,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def update_peer(
    peer_id: int,
    payload: schemas.PeerUpdate,
    db: Session = Depends(get_db),
):
    peer = db.query(models.Peer).filter(models.Peer.id == peer_id).first()
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found.")

    update_data = payload.model_dump(exclude_unset=True)

    if "allowed_ips" in update_data:
        conflict = (
            db.query(models.Peer)
            .filter(
                models.Peer.allowed_ips == update_data["allowed_ips"],
                models.Peer.id != peer_id,
            )
            .first()
        )
        if conflict:
            raise HTTPException(
                status_code=400,
                detail="IP address already allocated to another peer.",
            )

    for field, value in update_data.items():
        setattr(peer, field, value)
    db.commit()
    db.refresh(peer)

    if "allowed_ips" in update_data:
        try:
            WireGuardEngine.sync_peer_to_kernel(
                "wg0", peer.public_key, peer.allowed_ips
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Kernel failed loading runtime rule: {str(e)}",
            )

    return _peer_to_response(peer)


@app.delete(
    "/peers/{peer_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def delete_peer(peer_id: int, db: Session = Depends(get_db)):
    peer = db.query(models.Peer).filter(models.Peer.id == peer_id).first()
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found.")

    try:
        WireGuardEngine.drop_peer_from_kernel("wg0", peer.public_key)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Kernel peer removal failed: {type(e).__name__}: {str(e)}",
        )
    db.delete(peer)
    db.commit()
    return
