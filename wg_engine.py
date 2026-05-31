import base64
import os
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
    def get_wg0_public_key() -> str:
        try:
            with WireGuard() as wg:
                info = wg.info("wg0")
                if info:
                    for name, value in info[0].get("attrs", []):
                        if name == "WGDEVICE_A_PUBLIC_KEY":
                            return base64.b64encode(value).decode()
        except Exception:
            pass
        return os.environ.get("WG0_PUBLIC_KEY", "wg0_public_key_placeholder")

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
