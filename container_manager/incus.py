import json
import subprocess
import threading

from .errors import Failure
from .models import Port, canonical_id, validate_port
from .inspection import listener_ready
from .allocation import Allocation
from .native_tcp import NativeTCP

PROJECT = "pp-ubuntu"
POOL = "pp-ubuntu-ssd"
BRIDGE = "ppub0"
BOOTSTRAP = """set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends openssh-server ca-certificates
install -d -m 0755 /run/sshd /etc/ssh/sshd_config.d
printf '%s\\n' 'PermitRootLogin yes' 'PasswordAuthentication yes' 'KbdInteractiveAuthentication no' 'PermitEmptyPasswords no' 'UsePAM yes' > /etc/ssh/sshd_config.d/00-pp-ubuntu.conf
ssh-keygen -A
/usr/sbin/sshd -t
/usr/sbin/sshd -T | grep -qx 'permitrootlogin yes'
/usr/sbin/sshd -T | grep -qx 'passwordauthentication yes'
systemctl enable --now ssh
"""


def owned_name(resource: str) -> str:
    return "pp-ubuntu-" + canonical_id(resource)


class Incus:
    def __init__(
        self, config, store, inspector, runner=subprocess.run, ready=listener_ready
    ):
        self.config, self.store, self.inspector, self.runner = (
            config,
            store,
            inspector,
            runner,
        )
        self.lock = threading.Lock()
        self.instance_locks: dict[str, threading.RLock] = {}
        self.ready = ready
        self.allocation = Allocation(self)
        self.native = NativeTCP(self)
        for row in store.ownership():
            if row["state"] == "creating":
                store.own(row["id"], json.loads(row["spec"]), "error")

    def query(self, uri):
        try:
            result = self.runner(
                ["incus", "query", uri],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=True,
            )
            value = json.loads(result.stdout)
            return value.get("metadata", value) if isinstance(value, dict) else value
        except (OSError, subprocess.SubprocessError, ValueError, TypeError):
            raise Failure("incus_query_unavailable") from None

    def native_record(self, spec):
        record = next(
            (r for r in self.store.native_records() if r["id"] == spec["id"]), None
        )
        if (
            not record
            or json.loads(record["spec"]) != spec
            or record["transport"] != "native_tcp_v1"
            or record["address_version"] != 1
        ):
            raise Failure("proxy_requires_reconciliation", 409)
        return record

    def recover(self):
        records = {r["id"]: r for r in self.store.native_records()}
        for row in self.store.ownership():
            spec = json.loads(row["spec"])
            if spec.get("protocol") != "tcp":
                continue
            record = records.get(row["id"])
            if not record or record["state"] not in {"active", "paused"}:
                if record:
                    self.store.native_state(spec, "error")
                else:
                    self.store.own(row["id"], spec, "error")
                continue
            with self.instance_lock(spec["instance_id"]):
                try:
                    pin = self.store.address_binding(spec["instance_id"])
                    if not pin or pin["state"] != "ready":
                        raise Failure("address_requires_reconciliation", 409)
                    _, status = self.allocation.validate(spec["instance_id"], pin)
                    self.inspector.check("tcp", spec["public_port"])
                    active = status == "running" and record["state"] == "active"
                    self.native.bind(spec, active)
                    self.store.native_state(spec, "active" if active else "paused")
                except Failure:
                    if spec["id"] in self.native.bindings:
                        self.native.pause(spec)
                    self.store.native_state(spec, "error")

    def pause_native_validation(self, binding, generation: int, state: str):
        # Match both identity and generation under the same instance lock as
        # stop/start. Never acquire that lock while holding clients_lock.
        spec = binding.spec
        with self.instance_lock(spec["instance_id"]):
            with binding.clients_lock:
                if (
                    self.native.bindings.get(spec["id"]) is not binding
                    or binding.generation != generation
                ):
                    return
            self.native.pause(spec)
            self.store.native_state(spec, state)

    def close(self):
        self.native.close()

    def instance_lock(self, resource: str):
        canonical_id(resource)
        with self.lock:
            return self.instance_locks.setdefault(resource, threading.RLock())

    def command(self, args: list[str], stdin: bytes | None = None):
        try:
            result = self.runner(
                ["incus", "--project", PROJECT, *args],
                input=stdin,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=180,
                check=False,
            )
            if result.returncode:
                # Never expose command output (including potentially exec input).
                if b"address already in use" in (result.stderr or b"").lower():
                    raise Failure("host_listener_conflict", 409)
                raise Failure("incus_operation_failed")
        except (OSError, subprocess.SubprocessError):
            raise Failure("incus_unavailable") from None

    def verify_profile(self):
        """Read only the fixed operator profile; never overwrite NIC/root policy."""
        try:
            result = self.runner(
                [
                    "incus",
                    "query",
                    "/1.0/profiles/default?project=pp-ubuntu",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=True,
            )
            profile = json.loads(result.stdout)
            profile = profile.get("metadata", profile)
            devices = profile["devices"]
            root, nic = devices["root"], devices["eth0"]
            if (
                root.get("type") != "disk"
                or root.get("pool") != POOL
                or root.get("path") != "/"
            ):
                raise Failure("operator_profile_mismatch")
            expected = {
                "type": "nic",
                "network": BRIDGE,
                "security.ipv4_filtering": "true",
                "security.ipv6_filtering": "true",
                "security.mac_filtering": "true",
                "security.port_isolation": "true",
                "ipv6.address": "none",
            }
            if any(nic.get(key) != value for key, value in expected.items()):
                raise Failure("operator_profile_mismatch")
            if set(devices) != {"root", "eth0"}:
                raise Failure("operator_profile_mismatch")
            return profile
        except (
            OSError,
            subprocess.SubprocessError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
        ):
            raise Failure("operator_profile_unavailable") from None

    def instance_status(self, resource: str) -> str:
        with self.instance_lock(resource):
            self.require(resource)
            try:
                result = self.runner(
                    [
                        "incus",
                        "--project",
                        PROJECT,
                        "list",
                        owned_name(resource),
                        "--format=json",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    check=True,
                )
                entries = json.loads(result.stdout)
                matches = [
                    entry
                    for entry in entries
                    if entry.get("name") == owned_name(resource)
                ]
                if len(matches) != 1:
                    return "error"
                state = matches[0].get("status", "").lower()
                return state if state in {"running", "stopped"} else "error"
            except (
                OSError,
                subprocess.SubprocessError,
                ValueError,
                TypeError,
                AttributeError,
            ):
                raise Failure("incus_status_unavailable") from None

    def port_status(self, spec: dict) -> str:
        with self.instance_lock(spec["instance_id"]):
            canonical_id(spec["id"])
            row = next(
                (r for r in self.store.ownership() if r["id"] == spec["id"]), None
            )
            if row is None:
                return "missing"
            if json.loads(row["spec"]) != spec:
                raise Failure("ownership_conflict", 409)
            if spec["protocol"] == "tcp":
                try:
                    record = self.native_record(spec)
                    pin = self.store.address_binding(spec["instance_id"])
                    if not pin or pin["state"] != "ready":
                        raise Failure("address_requires_reconciliation", 409)
                    _, status = self.allocation.validate(spec["instance_id"], pin)
                    if status == "stopped" and record["state"] == "active":
                        self.native.pause(spec)
                        self.store.native_state(spec, "paused")
                        record["state"] = "paused"
                    if record["state"] not in {
                        "active",
                        "paused",
                    } or not self.native.ready(spec, record["state"] == "active"):
                        raise Failure("native_tcp_not_ready")
                    return "ready"
                except Failure:
                    if spec["id"] in self.native.bindings:
                        self.native.pause(spec)
                    if any(r["id"] == spec["id"] for r in self.store.native_records()):
                        self.store.native_state(spec, "error")
                    else:
                        self.store.own(spec["id"], spec, "error")
                    return "error"
            # A stopped guest legitimately has no proxy process until next start.
            if (
                row["state"] == "ready"
                and self.instance_status(spec["instance_id"]) == "stopped"
            ):
                return "ready"
            if row["state"] != "ready" or not self.ready(
                spec["protocol"], spec["public_port"], self.config.gamma_ip
            ):
                self.store.own(spec["id"], spec, "error")
                return "error"
            return "ready"

    def require(self, resource: str):
        owned_name(resource)
        row = next((r for r in self.store.ownership() if r["id"] == resource), None)
        if not row or row["state"] != "ready":
            raise Failure("instance_requires_reconciliation", 409)

    def create(self, resource: str, cpu: int, memory_bytes: int, password: str):
        name = owned_name(resource)
        if (
            type(cpu) is not int
            or not 1 <= cpu <= 4
            or type(memory_bytes) is not int
            or not 1 <= memory_bytes <= 16_000_000_000
        ):
            raise Failure("invalid_limits", 422)
        # Validate transient password on BOTH sides of the private trust boundary.
        from .models import Password

        Password(root_password=password)
        spec = {"id": resource, "cpu": cpu, "memory_bytes": memory_bytes}
        with self.instance_lock(resource):
            old = next((r for r in self.store.ownership() if r["id"] == resource), None)
            if old:
                if old["state"] == "ready" and json.loads(old["spec"]) == spec:
                    return
                raise Failure("instance_requires_reconciliation", 409)
            self.verify_profile()
            self.store.own(resource, spec, "creating")
            try:
                self.command(
                    [
                        "init",
                        self.config.image_fingerprint,
                        name,
                        "--profile",
                        "default",
                        "-c",
                        f"limits.cpu={cpu}",
                        "-c",
                        f"limits.memory={memory_bytes}",
                        "-c",
                        "security.privileged=false",
                        "-c",
                        "security.nesting=false",
                        "-c",
                        "security.idmap.isolated=true",
                    ]
                )
                self.command(
                    [
                        "storage",
                        "volume",
                        "create",
                        POOL,
                        name + "-home",
                        "--type=filesystem",
                    ]
                )
                self.command(
                    [
                        "config",
                        "device",
                        "add",
                        name,
                        "home",
                        "disk",
                        f"pool={POOL}",
                        f"source={name}-home",
                        "path=/home",
                    ]
                )
                self.command(["start", name])
                self.command(
                    [
                        "exec",
                        name,
                        "--mode=non-interactive",
                        "--",
                        "/bin/sh",
                        "-c",
                        BOOTSTRAP,
                    ]
                )
                self.password(resource, password, creating=True)
                self.store.own(resource, spec, "ready")
            except BaseException:
                self.store.own(resource, spec, "error")
                # Never delete a partial guest or persistent volumes to roll back.
                raise

    def password(self, resource: str, password: str, creating=False):
        from .models import Password

        Password(root_password=password)
        with self.instance_lock(resource):
            if not creating:
                self.require(resource)
            self.command(
                [
                    "exec",
                    owned_name(resource),
                    "--mode=non-interactive",
                    "--",
                    "/usr/sbin/chpasswd",
                ],
                stdin=("root:" + password + "\n").encode(),
            )

    def power(self, resource: str, start: bool):
        with self.instance_lock(resource):
            self.require(resource)
            specs = [
                json.loads(r["spec"])
                for r in self.store.native_records()
                if json.loads(r["spec"])["instance_id"] == resource
            ]
            if start:
                owned_tcp = [
                    row
                    for row in self.store.ownership()
                    if (owned := json.loads(row["spec"])).get("protocol") == "tcp"
                    and owned.get("instance_id") == resource
                ]
                if {row["id"] for row in owned_tcp} != {spec["id"] for spec in specs}:
                    raise Failure("proxy_requires_reconciliation", 409)
                for row in owned_tcp:
                    spec = json.loads(row["spec"])
                    record = self.native_record(spec)
                    pin = self.store.address_binding(resource)
                    if (
                        row["state"] != "ready"
                        or record["state"] != "paused"
                        or not pin
                        or pin["state"] != "ready"
                        or pin["version"] != record["address_version"]
                        or not self.native.ready(spec, False)
                    ):
                        raise Failure("proxy_requires_reconciliation", 409)
            if not start:
                for spec in specs:
                    record = self.native_record(spec)
                    if spec["id"] in self.native.bindings:
                        self.native.pause(spec)
                    self.store.native_state(
                        spec,
                        (
                            "paused"
                            if record["state"] in {"active", "paused"}
                            else "error"
                        ),
                    )
            try:
                if start:
                    for spec in specs:
                        record = self.native_record(spec)
                        if record["state"] != "paused" or not self.native.ready(
                            spec, False
                        ):
                            raise Failure("proxy_requires_reconciliation", 409)
                        self.allocation.pin(resource)
                # No force flag; a failed stop leaves closed streams and error leases.
                self.command(["start" if start else "stop", owned_name(resource)])
                if start:
                    for spec in specs:
                        if self.native_record(spec)["state"] != "paused":
                            raise Failure("proxy_requires_reconciliation", 409)
                        pin = self.allocation.pin(resource)
                        self.allocation.validate(resource, pin)
                        self.native.resume(spec)
                        self.store.native_state(spec, "active")
            except BaseException:
                for spec in specs:
                    if spec["id"] in self.native.bindings:
                        self.native.pause(spec)
                    self.store.native_state(spec, "error")
                raise

    def publish(self, spec: dict):
        canonical_id(spec["id"])
        canonical_id(spec["instance_id"])
        port = Port(**{k: spec[k] for k in ("protocol", "public_port", "target_port")})
        validate_port(port, set(self.config.reserved_ports))
        with self.instance_lock(spec["instance_id"]):
            self.require(spec["instance_id"])
            old = next(
                (r for r in self.store.ownership() if r["id"] == spec["id"]), None
            )
            if old:
                if (
                    old["state"] == "ready"
                    and json.loads(old["spec"]) == spec
                    and self.port_status(spec) == "ready"
                ):
                    return
                raise Failure("proxy_requires_reconciliation", 409)
            self.inspector.check(port.protocol, port.public_port)
            if port.protocol == "tcp":
                pin = self.allocation.pin(spec["instance_id"])
                _, status = self.allocation.validate(spec["instance_id"], pin)
                self.store.native_state(spec, "creating")
                try:
                    self.native.bind(spec, status == "running")
                    if not self.native.ready(spec, status == "running"):
                        raise Failure("native_tcp_not_ready")
                    self.store.native_state(
                        spec, "active" if status == "running" else "paused"
                    )
                except BaseException:
                    if spec["id"] in self.native.bindings:
                        self.native.pause(spec)
                    self.store.native_state(spec, "error")
                    raise
                return
            self.store.own(spec["id"], spec, "creating")
            try:
                self.command(
                    [
                        "config",
                        "device",
                        "add",
                        owned_name(spec["instance_id"]),
                        "port-" + spec["id"],
                        "proxy",
                        f"listen={port.protocol}:{self.config.gamma_ip}:{port.public_port}",
                        f"connect={port.protocol}:127.0.0.1:{port.target_port}",
                        "bind=host",
                    ]
                )
                # Confirm kernel binding too; no UDP send/TCP handshake is treated
                # as proof that an application inside the guest is reachable.
                if not self.ready(
                    port.protocol, port.public_port, self.config.gamma_ip
                ):
                    raise Failure("proxy_not_ready")
                self.store.own(spec["id"], spec, "ready")
            except BaseException:
                self.store.own(spec["id"], spec, "error")
                raise

    def remove(self, spec: dict):
        canonical_id(spec["id"])
        canonical_id(spec["instance_id"])
        with self.instance_lock(spec["instance_id"]):
            old = next(
                (r for r in self.store.ownership() if r["id"] == spec["id"]), None
            )
            if old is None:
                return
            if json.loads(old["spec"]) != spec:
                raise Failure("ownership_conflict", 409)
            # Only ready proxies can be automatically removed. Ambiguous failures
            # need operator reconciliation, not an assumption that nothing exists.
            if old["state"] != "ready":
                raise Failure("proxy_requires_reconciliation", 409)
            if spec["protocol"] == "tcp":
                record = self.native_record(spec)
                if record["state"] not in {"active", "paused"}:
                    raise Failure("proxy_requires_reconciliation", 409)
                try:
                    self.native.remove(spec)
                    self.store.remove_native(spec)
                except BaseException:
                    self.store.native_state(spec, "error")
                    raise
                return
            self.command(
                [
                    "config",
                    "device",
                    "remove",
                    owned_name(spec["instance_id"]),
                    "port-" + spec["id"],
                ]
            )
            self.store.disown(spec["id"])
