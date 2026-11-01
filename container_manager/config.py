import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

PRIVATE_PEER_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def private_peer(address) -> bool:
    return any(address in network for network in PRIVATE_PEER_NETWORKS)


@dataclass(frozen=True)
class Config:
    mode: str
    database: str
    bind: str
    ca: str
    cert: str
    key: str
    controller_cn: str = "pp-ubuntu-controller"
    node_address: str = "10.200.73.2:9443"
    relay_address: str = "10.200.73.1:9444"
    node_identity: str = "gamma-agent"
    relay_identity: str = "alpha-relay"
    gamma_ip: str = "10.200.73.2"
    public_ip: str = ""
    wireguard_ip: str = ""
    image_fingerprint: str = ""
    domain_suffix: str = "hosting.i3alumba.ru"
    reserved_ports: list[int] = field(default_factory=list)
    # Operator-certified upstream ingress ownership; empty means do not publish.
    public_port_ranges: dict[str, list[list[int]]] = field(
        default_factory=lambda: {"tcp": [], "udp": []}
    )
    host_addresses: list[str] = field(default_factory=list)
    inspection_sudo: bool = False
    pool_cpu: int = 4
    pool_memory_gb: int = 16

    def domain_allowed(self, domain: str) -> bool:
        suffix = "." + self.domain_suffix
        return (
            domain.endswith(suffix)
            and re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", domain[: -len(suffix)]
            )
            is not None
        )

    @classmethod
    def load(cls, path: str):
        config = cls(**json.loads(Path(path).read_text()))
        if config.mode not in {"controller", "node", "relay"}:
            raise ValueError("invalid mode")
        if (
            not isinstance(config.domain_suffix, str)
            or len(config.domain_suffix) > 189
            or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
                config.domain_suffix,
            )
            or type(config.pool_cpu) is not int
            or type(config.pool_memory_gb) is not int
            or not 1 <= config.pool_cpu <= 1024
            or not 1 <= config.pool_memory_gb <= 4096
        ):
            raise ValueError("invalid budget/domains")
        if config.mode != "controller":
            ip = ipaddress.ip_address(config.wireguard_ip)
            if (
                not private_peer(ip)
                or ip.is_unspecified
                or ip.is_loopback
                or ip.is_multicast
                or ip.is_link_local
                or str(ip) != config.bind.rsplit(":", 1)[0]
            ):
                raise ValueError("private agent must bind configured WireGuard IP")
            if (
                not config.host_addresses
                or config.wireguard_ip not in config.host_addresses
            ):
                raise ValueError(
                    "all host public/WireGuard addresses must be configured"
                )
        if (
            not isinstance(config.public_port_ranges, dict)
            or set(config.public_port_ranges) != {"tcp", "udp"}
            or any(
                not isinstance(ranges, list)
                or len(ranges) > 32
                or any(
                    not isinstance(bounds, list)
                    or len(bounds) != 2
                    or any(type(port) is not int for port in bounds)
                    or not 1024 <= bounds[0] <= bounds[1] <= 65535
                    for bounds in ranges
                )
                for ranges in config.public_port_ranges.values()
            )
        ):
            raise ValueError("invalid upstream public port ranges")
        for address in config.host_addresses:
            ipaddress.ip_address(address)
        if any(
            type(port) is not int or not 1 <= port <= 65535
            for port in config.reserved_ports
        ):
            raise ValueError("invalid reserved ports")
        if config.mode == "node" and (
            config.gamma_ip != "10.200.73.2"
            or config.gamma_ip != config.wireguard_ip
            or not re.fullmatch(r"[0-9a-f]{64}", config.image_fingerprint)
        ):
            raise ValueError("node requires fixed image fingerprint and gamma address")
        if config.mode == "relay":
            public_ip = ipaddress.ip_address(config.public_ip)
            gamma_ip = ipaddress.ip_address(config.gamma_ip)
            if (
                public_ip.is_unspecified
                or public_ip.is_multicast
                or config.public_ip not in config.host_addresses
            ):
                raise ValueError("relay must bind a fixed owned public address")
            if (
                not private_peer(gamma_ip)
                or gamma_ip.is_unspecified
                or gamma_ip.is_multicast
                or gamma_ip.is_loopback
                or gamma_ip.is_link_local
            ):
                raise ValueError("relay target must be private gamma WireGuard address")
        return config
