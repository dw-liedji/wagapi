import base64
from pyroute2 import IPRoute, WireGuard
from cryptography.hazmat.primitives.asymmetric import x25519
from models import Interface as InterfaceModel


class WireGuardEngine:
    @staticmethod
    def generate_keypair() -> tuple[str, str]:
        priv_key = x25519.X25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        return (
            base64.b64encode(priv_key.private_bytes_raw()).decode("utf-8"),
            base64.b64encode(pub_key.public_bytes_raw()).decode("utf-8"),
        )

    @staticmethod
    def _ensure_interface(interface_name: str) -> None:
        with IPRoute() as ipr:
            if not ipr.link_lookup(ifname=interface_name):
                ipr.link("add", ifname=interface_name, kind="wireguard")

    @staticmethod
    def sync_peer_to_kernel(
        interface_name: str, public_key: str, allowed_ips: str
    ) -> None:
        wg = WireGuard()
        wg.set(
            interface_name,
            peer={
                "public_key": public_key,
                "allowed_ips": [allowed_ips],
                "persistent_keepalive": 25,
            },
        )

    @staticmethod
    def drop_peer_from_kernel(interface_name: str, public_key: str) -> None:
        wg = WireGuard()
        wg.set(interface_name, peer={"public_key": public_key, "remove": True})

    @staticmethod
    def render_entire_interface_from_db(interface: InterfaceModel) -> None:
        WireGuardEngine._ensure_interface(interface.name)

        wg = WireGuard()
        wg.set(
            interface.name,
            private_key=interface.private_key,
            listen_port=interface.listen_port,
        )

        for peer in interface.peers:
            wg.set(
                interface.name,
                peer={
                    "public_key": peer.public_key,
                    "allowed_ips": [peer.allowed_ips],
                    "persistent_keepalive": 25,
                },
            )

        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=interface.name)
            if idx:
                ipr.link("set", index=idx[0], state="up")

    @staticmethod
    def destroy_interface_from_kernel(interface_name: str) -> None:
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=interface_name)
            if idx:
                ipr.link("delete", index=idx[0])
