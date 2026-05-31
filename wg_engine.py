import base64
from pyroute2 import WireGuard
from cryptography.hazmat.primitives.asymmetric import x25519


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
    def sync_peer_to_kernel(interface_name: str, public_key: str, allowed_ips: str) -> None:
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
