"""Owned CPU/RAM edits and opt-in shared physical GPU devices, never host policy edits."""

import json
import re

from .errors import Failure
from .models import GPU_PATTERN, canonical_id


def gpu_device(pci: str) -> str:
    if not isinstance(pci, str) or not re.fullmatch(GPU_PATTERN, pci):
        raise Failure("invalid_gpu", 422)
    return "gpu-" + pci.replace(":", "-").replace(".", "-")


def validate_limits(cpu, memory_bytes, gpu_ids):
    if (
        type(cpu) is not int
        or not 1 <= cpu <= 2**32 - 1
        or type(memory_bytes) is not int
        or not 1 <= memory_bytes <= 2**64 - 1
        or memory_bytes % 1_000_000
        or not isinstance(gpu_ids, list)
        or len(gpu_ids) > 64
        or any(
            not isinstance(p, str) or not re.fullmatch(GPU_PATTERN, p) for p in gpu_ids
        )
        or len(set(gpu_ids)) != len(gpu_ids)
    ):
        raise Failure("invalid_limits", 422)


class ResourceControl:
    def __init__(self, node):
        self.node = node

    def info(self):
        value = self.node.query("/1.0/resources")
        try:
            cpu, memory = value["cpu"]["total"], value["memory"]["total"]
            if (
                type(cpu) is not int
                or not 1 <= cpu <= 2**32 - 1
                or type(memory) is not int
                or not 1 <= memory <= 2**64 - 1
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError):
            raise Failure("host_resources_unavailable") from None
        gpus = []
        allowed = self.node.config.gpu_allowed_pci
        if allowed:
            project = self.node.query("/1.0/projects/pp-ubuntu")
            policy = project.get("config", {}) if isinstance(project, dict) else {}
            # Opt-in project policy belongs to the operator; never modify it here.
            if (
                policy.get("restricted") == "true"
                and policy.get("restricted.devices.gpu") == "allow"
            ):
                cards = value.get("gpu", {}).get("cards", [])
                if not isinstance(cards, list) or len(cards) > 256:
                    raise Failure("gpu_inventory_unavailable")
                seen = set()
                for card in cards:
                    if not isinstance(card, dict):
                        raise Failure("gpu_inventory_unavailable")
                    pci = card.get("pci_address")
                    if pci not in allowed:
                        continue
                    if pci in seen:
                        raise Failure("gpu_inventory_unavailable")
                    seen.add(pci)
                    name = " ".join(
                        str(card.get(k, "")) for k in ("vendor", "product")
                    ).strip()
                    name = "".join(c for c in name if c.isprintable())[:128] or pci
                    gpus.append({"id": pci, "name": name})
        return {
            "cpu": cpu,
            "memory_bytes": memory,
            "gpus": sorted(gpus, key=lambda g: g["id"]),
        }

    def validate(self, cpu, memory_bytes, gpu_ids):
        validate_limits(cpu, memory_bytes, gpu_ids)
        info = self.info()
        if cpu > info["cpu"] or memory_bytes > info["memory_bytes"]:
            raise Failure("physical_capacity_exceeded", 422)
        if set(gpu_ids) - {g["id"] for g in info["gpus"]}:
            raise Failure("gpu_not_allowed", 422)
        return info

    def add_gpu(self, name, pci):
        self.node.command(
            [
                "config",
                "device",
                "add",
                name,
                gpu_device(pci),
                "gpu",
                "gputype=physical",
                "pci=" + pci,
            ]
        )

    def read(self, resource, spec):
        from .incus import owned_name, POOL

        node = self.node
        profile = node.verify_profile()
        instance = node.query(
            f"/1.0/instances/{owned_name(resource)}?project=pp-ubuntu"
        )
        if not isinstance(instance, dict):
            raise Failure("resource_state_mismatch", 409)
        config = instance.get("expanded_config", {})
        devices = instance.get("expanded_devices", {})
        local = instance.get("devices", {})
        state = str(instance.get("status", "")).lower()
        if (
            instance.get("name") != owned_name(resource)
            or instance.get("project") != "pp-ubuntu"
            or instance.get("type") != "container"
            or instance.get("profiles") != ["default"]
            or instance.get("ephemeral") is not False
            or state not in {"running", "stopped"}
            or devices.get("root") != profile["devices"]["root"]
            or local.get("home")
            != {
                "type": "disk",
                "pool": POOL,
                "source": owned_name(resource) + "-home",
                "path": "/home",
            }
            or any(
                config.get(k) != v
                for k, v in {
                    "security.privileged": "false",
                    "security.nesting": "false",
                    "security.idmap.isolated": "true",
                    "limits.cpu": str(spec["cpu"]),
                    "limits.memory": str(spec["memory_bytes"]),
                }.items()
            )
        ):
            raise Failure("resource_state_mismatch", 409)
        nic = dict(profile["devices"]["eth0"])
        pin = node.store.address_binding(resource)
        if pin:
            if pin["state"] != "ready":
                raise Failure("address_requires_reconciliation", 409)
            nic["ipv4.address"] = pin["address"]
        if (
            devices.get("eth0") != nic
            or ("eth0" in local and (not pin or local["eth0"] != nic))
            or devices.get("home") != local.get("home")
        ):
            raise Failure("resource_device_mismatch", 409)
        expected = {
            gpu_device(p): {"type": "gpu", "gputype": "physical", "pci": p}
            for p in spec.get("gpu_ids", [])
        }
        actual = {
            name: device
            for name, device in local.items()
            if name.startswith("gpu-") or device.get("type") == "gpu"
        }
        if actual != expected or any(
            devices.get(name) != device for name, device in expected.items()
        ):
            raise Failure("gpu_ownership_mismatch", 409)
        # Preserve only known disks/NICs and owned proxy devices, never absorb drift.
        ports = {}
        for row in node.store.ownership():
            spec = json.loads(row["spec"])
            if (
                spec.get("instance_id") == resource
                and spec.get("protocol") == "udp"
                and row["state"] == "ready"
            ):
                ports["port-" + row["id"]] = {
                    "type": "proxy",
                    "listen": f"udp:{node.config.gamma_ip}:{spec['public_port']}",
                    "connect": f"udp:127.0.0.1:{spec['target_port']}",
                    "bind": "host",
                }
        if any(devices.get(name) != device for name, device in ports.items()):
            raise Failure("resource_device_mismatch", 409)
        if set(devices) - {"root", "home", "eth0", *expected, *ports}:
            raise Failure("resource_device_mismatch", 409)
        return state

    def update(
        self,
        resource,
        cpu,
        memory_bytes,
        gpu_ids,
        allow_restart,
        operation_id,
        expected_cpu,
        expected_memory_bytes,
        expected_gpu_ids,
    ):
        from .incus import owned_name

        canonical_id(resource)
        canonical_id(operation_id)
        validate_limits(cpu, memory_bytes, gpu_ids)
        if type(allow_restart) is not bool:
            raise Failure("invalid_restart", 422)
        node = self.node
        with node.instance_lock(resource):
            node.require(resource)
            old = json.loads(
                next(r["spec"] for r in node.store.ownership() if r["id"] == resource)
            )
            if (old.get("cpu"), old.get("memory_bytes"), old.get("gpu_ids", [])) != (
                expected_cpu,
                expected_memory_bytes,
                expected_gpu_ids,
            ):
                raise Failure("resources_conflict", 409)
            desired = {**old, "cpu": cpu, "memory_bytes": memory_bytes}
            if gpu_ids or "gpu_ids" in old:
                desired["gpu_ids"] = sorted(gpu_ids)
            state = self.read(resource, old)
            self.validate(cpu, memory_bytes, gpu_ids)
            if old == desired:
                return state
            restart = state == "running" and (
                old.get("gpu_ids", []) != sorted(gpu_ids)
                or memory_bytes < old["memory_bytes"]
            )
            if restart and not allow_restart:
                raise Failure("restart_required", 409)
            node.store.begin_resource_intent(resource, operation_id, desired)
            try:
                if restart:
                    node.power(resource, False)
                    if self.read(resource, old) != "stopped":
                        raise Failure("resource_state_mismatch", 409)
                node.command(
                    [
                        "config",
                        "set",
                        owned_name(resource),
                        f"limits.cpu={cpu}",
                        f"limits.memory={memory_bytes}",
                    ]
                )
                for pci in sorted(set(old.get("gpu_ids", [])) - set(gpu_ids)):
                    node.command(
                        [
                            "config",
                            "device",
                            "remove",
                            owned_name(resource),
                            gpu_device(pci),
                        ]
                    )
                for pci in sorted(set(gpu_ids) - set(old.get("gpu_ids", []))):
                    self.add_gpu(owned_name(resource), pci)
                # Never acknowledge a successful write without authoritative readback.
                self.read(resource, desired)
                if restart:
                    node.power(resource, True)
                actual = self.read(resource, desired)
                if actual != state:
                    raise Failure("resource_state_mismatch", 409)
                node.store.commit_resource_spec(resource, old, desired, operation_id)
                return actual
            except BaseException:
                node.store.resource_intent_error(resource)
                for row in node.store.native_records():
                    spec = json.loads(row["spec"])
                    if spec["instance_id"] == resource:
                        if spec["id"] in node.native.bindings:
                            node.native.pause(spec)
                        node.store.native_state(spec, "error")
                raise
