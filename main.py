import asyncio
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


def require_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API Key."
        )


def allocate_next_ip(interface: models.Interface) -> str:
    network = ipaddress.ip_network(interface.subnet_pool)
    used_ips = {p.allowed_ips.split("/")[0] for p in interface.peers}

    for ip in network.hosts():
        ip_str = str(ip)
        if ip_str.endswith(".1") and ip_str.startswith(
            str(network.network_address).rsplit(".", 2)[0]
        ):
            continue
        if ip_str not in used_ips:
            return f"{ip_str}/32"
    raise HTTPException(status_code=500, detail="Subnet address pool exhausted.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    models.Base.metadata.create_all(bind=engine)
    print("🔄 Boot: Restoring memory-based dynamic interfaces...")
    db = SessionLocal()
    try:
        dynamic_interfaces = db.query(models.Interface).all()
        for interface in dynamic_interfaces:
            await asyncio.to_thread(
                WireGuardEngine.render_entire_interface_from_db, interface
            )
            print(f"📡 Interface [{interface.name}] rendered inside RAM successfully.")
    finally:
        db.close()
    yield


app = FastAPI(
    title="WireGuard Hybrid SSOT Controller", version="4.0.0", lifespan=lifespan
)

# --- ENDPOINTS ---


@app.post(
    "/interfaces",
    response_model=schemas.InterfaceResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Interfaces"],
    dependencies=[Depends(require_api_key)],
)
def provision_dynamic_interface(
    payload: schemas.InterfaceCreate, db: Session = Depends(get_db)
):
    if payload.name == "wg0":
        raise HTTPException(
            status_code=400,
            detail="Interface name 'wg0' is reserved for system static infrastructure.",
        )
    if payload.listen_port == 51820:
        raise HTTPException(
            status_code=400,
            detail="Port 51820 is reserved by the static host listener interface.",
        )

    if (
        db.query(models.Interface)
        .filter(
            (models.Interface.name == payload.name)
            | (models.Interface.listen_port == payload.listen_port)
        )
        .first()
    ):
        raise HTTPException(
            status_code=400, detail="Interface name or network port collision detected."
        )

    priv, pub = WireGuardEngine.generate_keypair()
    new_interface = models.Interface(
        name=payload.name,
        subnet_pool=payload.subnet_pool,
        listen_port=payload.listen_port,
        endpoint=payload.endpoint,
        dns=payload.dns,
        private_key=priv,
        public_key=pub,
    )
    db.add(new_interface)
    db.commit()
    db.refresh(new_interface)

    try:
        WireGuardEngine.render_entire_interface_from_db(new_interface)
    except Exception as e:
        db.delete(new_interface)
        db.commit()
        raise HTTPException(
            status_code=500, detail=f"Kernel netlink instantiation failure: {str(e)}"
        )

    return new_interface


@app.get(
    "/interfaces",
    response_model=list[schemas.InterfaceResponse],
    tags=["Interfaces"],
    dependencies=[Depends(require_api_key)],
)
def list_interfaces(db: Session = Depends(get_db)):
    return db.query(models.Interface).all()


@app.get(
    "/interfaces/{interface_id}",
    response_model=schemas.InterfaceResponse,
    tags=["Interfaces"],
    dependencies=[Depends(require_api_key)],
)
def get_interface(interface_id: int, db: Session = Depends(get_db)):
    interface = (
        db.query(models.Interface)
        .filter(models.Interface.id == interface_id)
        .first()
    )
    if not interface:
        raise HTTPException(status_code=404, detail="Interface not found.")
    return interface


@app.put(
    "/interfaces/{interface_id}",
    response_model=schemas.InterfaceResponse,
    tags=["Interfaces"],
    dependencies=[Depends(require_api_key)],
)
def update_interface(
    interface_id: int,
    payload: schemas.InterfaceUpdate,
    db: Session = Depends(get_db),
):
    interface = (
        db.query(models.Interface)
        .filter(models.Interface.id == interface_id)
        .first()
    )
    if not interface:
        raise HTTPException(status_code=404, detail="Interface not found.")

    update_data = payload.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "listen_port":
            if value == 51820:
                raise HTTPException(
                    status_code=400,
                    detail="Port 51820 is reserved by the static host listener interface.",
                )
            conflict = (
                db.query(models.Interface)
                .filter(
                    models.Interface.listen_port == value,
                    models.Interface.id != interface_id,
                )
                .first()
            )
            if conflict:
                raise HTTPException(
                    status_code=400,
                    detail="Interface name or network port collision detected.",
                )
        setattr(interface, field, value)
    db.commit()
    db.refresh(interface)

    re_render = "listen_port" in update_data
    if re_render:
        try:
            WireGuardEngine.render_entire_interface_from_db(interface)
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Kernel netlink instantiation failure: {str(e)}",
            )

    return interface


@app.delete(
    "/interfaces/{interface_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Interfaces"],
    dependencies=[Depends(require_api_key)],
)
def drop_dynamic_interface(interface_id: int, db: Session = Depends(get_db)):
    interface = (
        db.query(models.Interface).filter(models.Interface.id == interface_id).first()
    )
    if not interface:
        raise HTTPException(status_code=404, detail="Interface not found.")

    WireGuardEngine.destroy_interface_from_kernel(interface.name)
    db.delete(interface)
    db.commit()
    return


@app.post(
    "/interfaces/{interface_id}/peers",
    response_model=schemas.PeerResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def add_peer_to_dynamic_interface(
    interface_id: int, payload: schemas.PeerCreate, db: Session = Depends(get_db)
):
    try:
        interface = (
            db.query(models.Interface).filter(models.Interface.id == interface_id).first()
        )
        if not interface:
            raise HTTPException(status_code=404, detail="Interface not found.")

        assigned_cidr = allocate_next_ip(interface)
        private_key, public_key = None, payload.public_key
        if not public_key:
            private_key, public_key = WireGuardEngine.generate_keypair()

        if db.query(models.Peer).filter(models.Peer.public_key == public_key).first():
            raise HTTPException(
                status_code=400, detail="Public Key duplicate collision encountered."
            )

        db_peer = models.Peer(
            interface_id=interface.id,
            device_name=payload.device_name,
            public_key=public_key,
            allowed_ips=assigned_cidr,
        )
        db.add(db_peer)
        db.commit()
        db.refresh(db_peer)

        try:
            WireGuardEngine.sync_peer_to_kernel(interface.name, public_key, assigned_cidr)
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

    config_string = (
        f"[Interface]\nPrivateKey = {private_key or 'CLIENT_PRIVATE_KEY'}\nAddress = {assigned_cidr}\nDNS = {interface.dns}\n\n"
        f"[Peer]\nPublicKey = {interface.public_key}\nEndpoint = {interface.endpoint}\nAllowedIPs = 0.0.0.0/0\n"
    )
    return schemas.PeerResponse(
        id=db_peer.id,
        interface_id=db_peer.interface_id,
        device_name=db_peer.device_name,
        public_key=db_peer.public_key,
        private_key=private_key,
        allowed_ips=db_peer.allowed_ips,
        created_at=db_peer.created_at,
        config_file=config_string,
    )


def _build_peer_config(
    interface: models.Interface, peer: models.Peer
) -> str:
    return (
        f"[Interface]\nPrivateKey = CLIENT_PRIVATE_KEY\nAddress = {peer.allowed_ips}\n"
        f"DNS = {interface.dns}\n\n"
        f"[Peer]\nPublicKey = {interface.public_key}\n"
        f"Endpoint = {interface.endpoint}\nAllowedIPs = 0.0.0.0/0\n"
    )


def _peer_to_response(
    peer: models.Peer, config_file: str,
) -> schemas.PeerResponse:
    return schemas.PeerResponse(
        id=peer.id,
        interface_id=peer.interface_id,
        device_name=peer.device_name,
        public_key=peer.public_key,
        private_key=None,
        allowed_ips=peer.allowed_ips,
        created_at=peer.created_at,
        config_file=config_file,
    )


@app.get(
    "/interfaces/{interface_id}/peers",
    response_model=list[schemas.PeerResponse],
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def list_peers(interface_id: int, db: Session = Depends(get_db)):
    interface = (
        db.query(models.Interface)
        .filter(models.Interface.id == interface_id)
        .first()
    )
    if not interface:
        raise HTTPException(status_code=404, detail="Interface not found.")
    return [
        _peer_to_response(p, _build_peer_config(interface, p))
        for p in interface.peers
    ]


@app.get(
    "/interfaces/{interface_id}/peers/{peer_id}",
    response_model=schemas.PeerResponse,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def get_peer(
    interface_id: int, peer_id: int, db: Session = Depends(get_db)
):
    peer = (
        db.query(models.Peer)
        .filter(
            models.Peer.id == peer_id,
            models.Peer.interface_id == interface_id,
        )
        .first()
    )
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found.")
    return _peer_to_response(
        peer, _build_peer_config(peer.interface_rel, peer)
    )


@app.put(
    "/interfaces/{interface_id}/peers/{peer_id}",
    response_model=schemas.PeerResponse,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def update_peer(
    interface_id: int,
    peer_id: int,
    payload: schemas.PeerUpdate,
    db: Session = Depends(get_db),
):
    peer = (
        db.query(models.Peer)
        .filter(
            models.Peer.id == peer_id,
            models.Peer.interface_id == interface_id,
        )
        .first()
    )
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
        interface = peer.interface_rel
        try:
            WireGuardEngine.sync_peer_to_kernel(
                interface.name, peer.public_key, peer.allowed_ips
            )
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail=f"Kernel failed loading runtime rule: {str(e)}",
            )

    return _peer_to_response(
        peer, _build_peer_config(peer.interface_rel, peer)
    )


@app.delete(
    "/interfaces/{interface_id}/peers/{peer_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["Peers"],
    dependencies=[Depends(require_api_key)],
)
def delete_peer(
    interface_id: int, peer_id: int, db: Session = Depends(get_db)
):
    peer = (
        db.query(models.Peer)
        .filter(
            models.Peer.id == peer_id,
            models.Peer.interface_id == interface_id,
        )
        .first()
    )
    if not peer:
        raise HTTPException(status_code=404, detail="Peer not found.")

    interface = peer.interface_rel
    try:
        WireGuardEngine.drop_peer_from_kernel(interface.name, peer.public_key)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Kernel peer removal failed: {type(e).__name__}: {str(e)}",
        )
    db.delete(peer)
    db.commit()
    return
