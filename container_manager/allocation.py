"""Daemon-authoritative, write-ahead pinning in the shared default network."""

import ipaddress
import re
import threading
import time
from urllib.parse import urlencode

from .errors import Failure

NETWORK = "ppub0"
PROJECT = "pp-ubuntu"
NIC = {
    "type": "nic",
    "network": NETWORK,
    "name": "eth0",
    "ipv6.address": "none",
    "security.ipv4_filtering": "true",
    "security.ipv6_filtering": "true",
    "security.mac_filtering": "true",
    "security.port_isolation": "true",
}
SUBNET = ipaddress.ip_network("10.211.0.0/24")
MAX_PROJECTS = 256
MAX_LEASE_SCOPES = 16
LEASE_DOMAIN_TIMEOUT = 2.0


class Allocation:
    def __init__(self, node):
        self.node = node
        # All pins in this node process share one allocation lock. External root
        # writers must be serialized by the operator, not guessed around.
        self.lock = threading.RLock()

    def snapshot(self, resource, binding=None):
        from .incus import owned_name

        node = self.node
        node.require(resource)
        profile = node.verify_profile()
        name = owned_name(resource)
        instance = node.query(f"/1.0/instances/{name}?project={PROJECT}")
        network = node.query(f"/1.0/networks/{NETWORK}?project=default")
        projects, leases = self.lease_domain()
        claims = node.query("/1.0/instances?all-projects=true&recursion=1")
        if (
            instance.get("name") != name
            or instance.get("project") != PROJECT
            or instance.get("type") != "container"
            or instance.get("expanded_devices", {}).get("root")
            != profile["devices"]["root"]
            or any(
                instance.get("expanded_config", {}).get(key) != value
                for key, value in {
                    "security.privileged": "false",
                    "security.nesting": "false",
                    "security.idmap.isolated": "true",
                }.items()
            )
            or network.get("managed") is not True
            or network.get("type") != "bridge"
            or network.get("config", {}).get("ipv4.address") != "10.211.0.1/24"
            or network.get("config", {}).get("ipv6.address") != "none"
            or instance.get("status", "").lower() not in {"running", "stopped"}
        ):
            raise Failure("address_binding_mismatch", 409)
        mac = instance["expanded_config"]["volatile.eth0.hwaddr"]
        if (
            not isinstance(mac, str)
            or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac)
            or int(mac[:2], 16) & 1
            or mac == "00:00:00:00:00:00"
        ):
            raise Failure("address_binding_mismatch", 409)
        expanded = instance["expanded_devices"]["eth0"]
        local = instance["devices"].get("eth0")
        if binding:
            address = binding["address"]
            expected = {**NIC, "ipv4.address": address}
            if (
                binding["instance_id"] != resource
                or binding["network"] != NETWORK
                or binding["nic"] != "eth0"
                or binding["version"] != 1
                or binding["mac"] != mac
                or expanded != expected
                or local != expected
            ):
                raise Failure("address_binding_mismatch", 409)
        else:
            if (
                instance["status"].lower() != "running"
                or expanded != NIC
                or local not in (None, NIC)
            ):
                raise Failure("address_pin_requires_running_dynamic_guest", 409)
            matches = [
                lease
                for project, lease in leases
                if project == PROJECT and lease["hwaddr"] == mac
            ]
            if len(matches) != 1 or matches[0].get("type") != "dynamic":
                raise Failure("address_lease_ambiguous", 409)
            address = matches[0]["address"]
        ip = ipaddress.ip_address(address)
        if (
            str(ip) != address
            or ip not in SUBNET
            or ip
            in {
                SUBNET.network_address,
                SUBNET.broadcast_address,
                ipaddress.ip_address("10.211.0.1"),
            }
        ):
            raise Failure("address_binding_mismatch", 409)
        for project, lease in leases:
            if lease["address"] == address or lease["hwaddr"] == mac:
                if (
                    project != PROJECT
                    or lease.get("address") != address
                    or lease.get("hwaddr") != mac
                    or lease.get("type") not in {"dynamic", "static"}
                ):
                    raise Failure("address_lease_ambiguous", 409)
        if len([lease for _, lease in leases if lease["address"] == address]) > 1:
            raise Failure("address_lease_ambiguous", 409)
        own_claims = 0
        for claim in claims:
            claim_project = claim.get("project")
            if not isinstance(claim_project, str) or claim_project not in projects:
                raise Failure("address_claim_ambiguous", 409)
            for device_name, device in claim["expanded_devices"].items():
                if device.get("type") != "nic":
                    continue
                shared_network = device.get("network") == NETWORK and (
                    claim_project == "default" or projects[claim_project] == "false"
                )
                # A direct host-bridge parent is not a project-isolated network.
                if not shared_network and device.get("parent") != NETWORK:
                    continue
                claim_mac = claim.get("expanded_config", {}).get(
                    f"volatile.{device_name}.hwaddr"
                )
                if (
                    not isinstance(claim_mac, str)
                    or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", claim_mac)
                    or (
                        device.get("ipv4.address") not in (None, "none")
                        and not self.valid_claim_address(device["ipv4.address"])
                    )
                ):
                    raise Failure("address_claim_ambiguous", 409)
                own = (
                    claim.get("name") == name
                    and claim.get("project") == PROJECT
                    and device_name == "eth0"
                )
                if own:
                    own_claims += 1
                    if device != expanded or claim_mac != mac:
                        raise Failure("address_claim_ambiguous", 409)
                elif (
                    device.get("ipv4.address") == address
                    or claim_mac == mac
                    or device.get("hwaddr") == mac
                ):
                    raise Failure("address_claim_ambiguous", 409)
        if own_claims != 1:
            raise Failure("address_claim_ambiguous", 409)
        return {
            "instance_id": resource,
            "nic": "eth0",
            "network": NETWORK,
            "mac": mac,
            "address": address,
            "version": 1,
        }, instance["status"].lower()

    def lease_domain(self) -> tuple[dict[str, str], list[tuple[str, dict]]]:
        """Inspect the entire shared allocation domain, never a partial union."""
        deadline = time.monotonic() + LEASE_DOMAIN_TIMEOUT

        def remaining():
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise Failure("address_lease_domain_timeout")
            return min(5, budget)

        def query(uri):
            result = self.node.query(uri, timeout=remaining())
            remaining()  # A late successful reply is not an in-budget snapshot.
            return result

        inventory = query("/1.0/projects?recursion=1")
        if not isinstance(inventory, list) or len(inventory) > MAX_PROJECTS:
            raise Failure("address_lease_domain_unavailable")
        projects: dict[str, str] = {}
        for project in inventory:
            remaining()
            if not isinstance(project, dict):
                raise Failure("address_lease_domain_unavailable")
            name, config = project.get("name"), project.get("config")
            if (
                not isinstance(name, str)
                or not name
                or name.strip() != name
                or not name.isprintable()
                or name in projects
                or not isinstance(config, dict)
                or config.get("features.networks") not in ("true", "false")
            ):
                raise Failure("address_lease_domain_unavailable")
            projects[name] = config["features.networks"]
        if "default" not in projects or projects.get(PROJECT) != "false":
            raise Failure("address_lease_domain_unavailable")
        scopes = sorted(
            name
            for name, isolated in projects.items()
            if name == "default" or isolated == "false"
        )
        if len(scopes) > MAX_LEASE_SCOPES:
            raise Failure("address_lease_domain_unavailable")
        leases: list[tuple[str, dict]] = []
        for project in scopes:
            entries = query(
                f"/1.0/networks/{NETWORK}/leases?" + urlencode({"project": project})
            )
            if not isinstance(entries, list):
                raise Failure("address_lease_domain_unavailable")
            for lease in entries:
                remaining()
                if not isinstance(lease, dict):
                    raise Failure("address_lease_domain_unavailable")
                address, mac, kind = (
                    lease.get("address"),
                    lease.get("hwaddr"),
                    lease.get("type"),
                )
                try:
                    ip = ipaddress.IPv4Address(address)
                except (ValueError, TypeError):
                    raise Failure("address_lease_domain_unavailable") from None
                if (
                    not isinstance(address, str)
                    or str(ip) != address
                    or not isinstance(mac, str)
                ):
                    raise Failure("address_lease_domain_unavailable")
                if kind == "gateway":
                    valid = address == "10.211.0.1" and mac == ""
                else:
                    valid = (
                        kind in ("dynamic", "static")
                        and ip in SUBNET
                        and address not in ("10.211.0.0", "10.211.0.1", "10.211.0.255")
                        and re.fullmatch(
                            r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac, re.IGNORECASE
                        )
                        and not int(mac[:2], 16) & 1
                        and mac.lower() != "00:00:00:00:00:00"
                    )
                if not valid:
                    raise Failure("address_lease_domain_unavailable")
                leases.append((project, {**lease, "hwaddr": mac.lower()}))
        remaining()
        return projects, leases

    @staticmethod
    def valid_claim_address(value):
        try:
            return str(ipaddress.IPv4Address(value)) == value
        except (ValueError, TypeError):
            return False

    def validate(self, resource, binding):
        with self.lock:
            try:
                return self.snapshot(resource, binding)
            except (KeyError, TypeError, ValueError, AttributeError):
                raise Failure("address_binding_unavailable") from None

    def pin(self, resource):
        from .incus import owned_name

        with self.lock:
            old = self.node.store.address_binding(resource)
            if old:
                if old["state"] != "ready":
                    raise Failure("address_requires_reconciliation", 409)
                self.validate(resource, old)
                return old
            try:
                binding, _ = self.snapshot(resource)
                # Commit before the first host mutation; errors keep the unique IP.
                self.node.store.save_address(binding, "pending")
                try:
                    current = self.node.query(
                        f"/1.0/instances/{owned_name(resource)}?project={PROJECT}"
                    )
                    if current["devices"].get("eth0") is not None:
                        raise Failure("local_nic_requires_reconciliation", 409)
                    self.node.command(
                        [
                            "config",
                            "device",
                            "override",
                            owned_name(resource),
                            "eth0",
                            "ipv4.address=" + binding["address"],
                        ]
                    )
                    self.validate(resource, binding)
                    self.node.store.save_address(binding, "ready")
                except BaseException:
                    self.node.store.save_address(binding, "error")
                    raise
                return {**binding, "state": "ready"}
            except (KeyError, TypeError, ValueError, AttributeError):
                raise Failure("address_binding_unavailable") from None
