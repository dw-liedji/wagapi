import base64
from pyroute2 import WireGuard, IPRoute
from cryptography.hazmat.primitives.asymmetric import x25519

from settings import settings


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
        return settings.wg0_public_key

    @staticmethod
    def ensure_wg0_interface() -> None:
        try:
            with IPRoute() as ipr:
                if "wg0" not in (x.get_attr("IFLA_IFNAME") for x in ipr.link_lookup(ifname="wg0")):
                    ipr.link("add", ifname="wg0", kind="wireguard")
                idx = ipr.link_lookup(ifname="wg0")[0]
                ipr.link("set", index=idx, state="up")
            with WireGuard() as wg:
                kwargs = {"listen_port": settings.wg0_listen_port}
                if settings.wg0_private_key:
                    kwargs["private_key"] = base64.b64decode(settings.wg0_private_key)
                wg.set("wg0", **kwargs)
        except Exception:
            pass

    @staticmethod
    def sync_all_peers_to_kernel(interface_name: str, peers: list[tuple[str, str]]) -> None:
        for public_key, allowed_ips in peers:
            WireGuardEngine.sync_peer_to_kernel(interface_name, public_key, allowed_ips)

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
