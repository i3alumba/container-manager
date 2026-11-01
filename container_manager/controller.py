import logging
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import sqlite3
import threading
from uuid import uuid4

from .errors import Failure
from .models import Check, Create, Port, canonical_id, validate_port
from .store import now

log = logging.getLogger("container_manager.audit")


@dataclass(frozen=True)
class CreateWork:
    resource: str
    key: str
    actor: str
    request: Create
    specs: list[dict]


class Controller:
    def __init__(self, config, store, node, relay):
        self.config, self.store, self.node, self.relay = config, store, node, relay
        # One controller process is supported. SQLite uniqueness/admission also
        # protects independent connections; the lock serializes instance edits.
        self.lock = threading.RLock()
        self.create_workers = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="create"
        )
        self.reconcile_lock = threading.Lock()
        store.recover_controller()

    def schedule_reconcile(self) -> bool:
        """Never delay HTTP startup/inventory on private agent deadlines."""
        if not self.reconcile_lock.acquire(blocking=False):
            return False

        def run():
            try:
                self.reconcile()
            except Exception:
                # No untrusted peer/error descriptions or request secrets in logs.
                log.error("reconciliation_failed")
            finally:
                self.reconcile_lock.release()

        try:
            threading.Thread(target=run, name="reconcile", daemon=True).start()
        except BaseException:
            self.reconcile_lock.release()
            raise
        return True

    def reconcile(self):
        """Read-only cross-daemon reconciliation, never release an uncertain port."""
        with self.lock:
            for instance in self.store.instances():
                resource = instance["id"]
                if instance["status"] in {"running", "stopped"}:
                    try:
                        actual = self.node.instance_status(resource)
                        if actual not in {"running", "stopped"}:
                            raise Failure("invalid_agent_state")
                        self.store.status(resource, actual)
                    except Failure:
                        self.store.status(
                            resource, "error", "node_requires_reconciliation"
                        )
                for port in instance["ports"]:
                    if port["status"] != "active":
                        continue
                    spec = {
                        k: port[k]
                        for k in ("id", "protocol", "public_port", "target_port")
                    }
                    spec["instance_id"] = resource
                    try:
                        if (
                            self.relay.port_status(spec) != "active"
                            or self.node.port_status(spec) != "ready"
                        ):
                            raise Failure("mapping_requires_reconciliation")
                    except Failure:
                        with self.store.transaction() as db:
                            db.execute(
                                "UPDATE ports SET status='error' WHERE id=?",
                                (port["id"],),
                            )

    def public_route_allowed(self, port: Check) -> bool:
        return any(
            low <= port.public_port <= high
            for low, high in self.config.public_port_ranges.get(port.protocol, [])
        )

    def check(self, port: Check) -> dict:
        policy_reserved = False
        try:
            validate_port(port, set(self.config.reserved_ports))
        except Failure:
            policy_reserved = True
        with self.store.transaction() as db:
            reserved = (
                db.execute(
                    "SELECT 1 FROM ports WHERE protocol=? AND public_port=?",
                    (port.protocol, port.public_port),
                ).fetchone()
                is not None
            )
        spec = port.model_dump()
        checks = {
            "registry": {
                "status": "conflict" if reserved or policy_reserved else "free",
                "reason": (
                    "reserved_port"
                    if policy_reserved
                    else "reserved" if reserved else "free"
                ),
            }
        }
        if not self.public_route_allowed(port):
            for host in ("alpha", "gamma"):
                checks[host] = {
                    "status": "unknown",
                    "reason": "external_ingress_not_configured",
                }
            return {
                "available": False,
                "reason": "external_ingress_not_configured",
                "checks": checks,
            }
        for host, backend in (("alpha", self.relay), ("gamma", self.node)):
            try:
                answer = backend.inspect(spec)
                available = answer.get("available")
                status = (
                    "free"
                    if available is True
                    else "conflict" if available is False else "unknown"
                )
                checks[host] = {
                    "status": status,
                    "reason": (
                        "free"
                        if status == "free"
                        else (
                            "host_port_conflict"
                            if status == "conflict"
                            else "inspection_unavailable"
                        )
                    ),
                }
            except Failure as error:
                checks[host] = {
                    "status": "conflict" if error.status == 409 else "unknown",
                    "reason": (
                        "host_port_conflict"
                        if error.status == 409
                        else "inspection_unavailable"
                    ),
                }
        available = all(c["status"] == "free" for c in checks.values())
        return {
            "available": available,
            "reason": "free" if available else "conflict_or_unknown",
            "checks": checks,
        }

    def operate(
        self, key: str | None, action: str, resource: str, actor: str, callback
    ):
        if key is None:
            key = str(uuid4())
        canonical_id(key)
        with self.lock:
            previous = self.store.begin_operation(key, action, resource, actor)
            if previous is not None:
                return self.store.instance(previous)
            try:
                result = callback()
                resource = result["id"]
                self.store.finish_operation(key, "done", resource)
                log.info(
                    "actor=%r action=%s resource=%s result=success",
                    actor,
                    action,
                    resource,
                )
                return result
            except Exception:
                self.store.finish_operation(key, "error", resource)
                log.info(
                    "actor=%r action=%s resource=%s result=error",
                    actor,
                    action,
                    resource,
                )
                raise

    def reserve_row(self, db, resource: str, port: Port) -> dict:
        validate_port(port, set(self.config.reserved_ports))
        if not self.public_route_allowed(port):
            raise Failure("external_ingress_not_configured", 503)
        spec = {"id": str(uuid4()), "instance_id": resource, **port.model_dump()}
        try:
            db.execute(
                "INSERT INTO ports(id,instance_id,protocol,public_port,target_port,status) VALUES(?,?,?,?,?,'reserved')",
                tuple(
                    spec[k]
                    for k in (
                        "id",
                        "instance_id",
                        "protocol",
                        "public_port",
                        "target_port",
                    )
                ),
            )
        except sqlite3.IntegrityError:
            raise Failure("port_reserved", 409) from None
        return spec

    def activate(self, spec: dict):
        # Both advisory inspectors run again for every actual port operation.
        # Registry row is already committed; reserve holds alpha socket before gamma.
        for backend in (self.relay, self.node):
            if backend.inspect(spec).get("available") is not True:
                raise Failure("host_port_conflict", 409)
        self.relay.reserve(spec)
        self.node.publish(spec)
        self.relay.activate(spec)
        with self.store.transaction() as db:
            db.execute("UPDATE ports SET status='active' WHERE id=?", (spec["id"],))

    def compensate(self, specs: list[dict]):
        for spec in reversed(specs):
            safe = True
            # Alpha first: stop exposure before removing gamma owned device.
            for backend in (self.relay, self.node):
                try:
                    backend.remove(spec)
                except Exception:
                    safe = False
            with self.store.transaction() as db:
                if safe:
                    db.execute("DELETE FROM ports WHERE id=?", (spec["id"],))
                else:
                    db.execute(
                        "UPDATE ports SET status='error' WHERE id=?", (spec["id"],)
                    )

    def prepare_create(
        self, request: Create, actor: str, key=None
    ) -> tuple[dict, CreateWork | None]:
        if not self.config.domain_allowed(request.domain):
            raise Failure("domain_not_allowed", 422)
        key = key or str(uuid4())
        canonical_id(key)
        with self.lock:
            previous = self.store.begin_operation(key, "create", "", actor)
            if previous is not None:
                return self.store.instance(previous), None
            resource = str(uuid4())
            try:
                with self.store.transaction() as db:
                    cpu, memory = db.execute(
                        "SELECT COALESCE(SUM(cpu),0),COALESCE(SUM(memory_gb),0) FROM instances"
                    ).fetchone()
                    if (
                        cpu + request.cpu > self.config.pool_cpu
                        or memory + float(request.memory_gb)
                        > self.config.pool_memory_gb
                    ):
                        raise Failure("aggregate_budget_exceeded", 409)
                    timestamp = now()
                    try:
                        db.execute(
                            "INSERT INTO instances VALUES(?,?,?,?,?,'creating',?,?,NULL)",
                            (
                                resource,
                                request.name,
                                request.domain,
                                request.cpu,
                                float(request.memory_gb),
                                timestamp,
                                timestamp,
                            ),
                        )
                    except sqlite3.IntegrityError:
                        raise Failure("name_in_use", 409) from None
                    specs = [self.reserve_row(db, resource, p) for p in request.ports]
                    db.execute(
                        "UPDATE operations SET resource=? WHERE id=?", (resource, key)
                    )
                work = CreateWork(resource, key, actor, request, specs)
                return self.store.instance(resource), work
            except Exception:
                self.store.finish_operation(key, "error", "")
                log.info(
                    "actor=%r action=create resource=%s result=error", actor, resource
                )
                raise

    def complete_create(self, work: CreateWork):
        try:
            for spec in work.specs:
                for backend in (self.relay, self.node):
                    if backend.inspect(spec).get("available") is not True:
                        raise Failure("host_port_conflict", 409)
            self.node.create(
                work.resource,
                work.request.cpu,
                int(work.request.memory_gb * 1_000_000_000),
                work.request.root_password.get_secret_value(),
            )
            for spec in work.specs:
                self.activate(spec)
            self.store.status(work.resource, "running")
            self.store.finish_operation(work.key, "done", work.resource)
            log.info(
                "actor=%r action=create resource=%s result=success",
                work.actor,
                work.resource,
            )
        except Exception:
            self.compensate(work.specs)
            self.store.status(work.resource, "error", "create_failed")
            self.store.finish_operation(work.key, "error", work.resource)
            log.info(
                "actor=%r action=create resource=%s result=error",
                work.actor,
                work.resource,
            )
            raise

    def enqueue_create(self, work: CreateWork):
        # Admission has already bounded queued jobs by the configured CPU budget.
        # Not an ASGI BackgroundTask: a middleware/response lifetime must not hold
        # the HTTP request open until apt/SSH bootstrap finishes.
        try:
            self.create_workers.submit(self.run_create, work)
        except RuntimeError:
            self.store.status(work.resource, "error", "create_interrupted")
            self.store.finish_operation(work.key, "error", work.resource)
            raise Failure("create_unavailable") from None

    def run_create(self, work: CreateWork):
        """Background errors are durable/audited, never unhandled payload tracebacks."""
        try:
            self.complete_create(work)
        except Exception:
            # complete_create has durably recorded the sanitized error and retained
            # uncertain ownership. Nothing secret is logged by an ASGI traceback.
            return

    def create(self, request: Create, actor: str, key=None):
        """Synchronous integration seam; HTTP uses prepare_create + run_create."""
        instance, work = self.prepare_create(request, actor, key)
        if work is not None:
            self.complete_create(work)
            return self.store.instance(work.resource)
        return instance

    def add_port(self, resource: str, port: Port, actor: str, key=None):
        canonical_id(resource)

        def add():
            instance = self.store.instance(resource)
            if instance["status"] != "running":
                raise Failure("instance_not_running", 409)
            if len(instance["ports"]) >= 64:
                raise Failure("port_limit", 409)
            with self.store.transaction() as db:
                spec = self.reserve_row(db, resource, port)
            try:
                self.activate(spec)
            except Exception:
                self.compensate([spec])
                raise
            return self.store.instance(resource)

        return self.operate(key, "add_port", resource, actor, add)

    def remove_port(self, resource: str, port_id: str, actor: str, key=None):
        canonical_id(resource)
        canonical_id(port_id)

        def remove():
            instance = self.store.instance(resource)
            found = next((p for p in instance["ports"] if p["id"] == port_id), None)
            if instance["status"] == "creating":
                raise Failure("instance_creating", 409)
            if not found:
                raise Failure("port_not_found", 404)
            spec = {
                k: found[k] for k in ("id", "protocol", "public_port", "target_port")
            }
            spec["instance_id"] = resource
            try:
                self.relay.remove(spec)
                self.node.remove(spec)
            except Exception:
                with self.store.transaction() as db:
                    db.execute("UPDATE ports SET status='error' WHERE id=?", (port_id,))
                raise
            with self.store.transaction() as db:
                db.execute("DELETE FROM ports WHERE id=?", (port_id,))
            return self.store.instance(resource)

        return self.operate(key, "remove_port:" + port_id, resource, actor, remove)

    def power(self, resource: str, start: bool, actor: str, key=None):
        canonical_id(resource)

        def power():
            instance = self.store.instance(resource)
            desired = "running" if start else "stopped"
            if instance["status"] == "creating":
                raise Failure("instance_creating", 409)
            if instance["status"] == "error":
                raise Failure("instance_requires_reconciliation", 409)
            if instance["status"] != desired:
                try:
                    self.node.power(resource, start)
                    self.store.status(resource, desired)
                except Exception:
                    self.store.status(
                        resource, "error", "power_requires_reconciliation"
                    )
                    raise
            return self.store.instance(resource)

        return self.operate(key, "start" if start else "stop", resource, actor, power)

    def password(self, resource: str, password: str, actor: str, key=None):
        canonical_id(resource)

        def change():
            if self.store.instance(resource)["status"] != "running":
                raise Failure("instance_not_running", 409)
            self.node.password(resource, password)
            return self.store.instance(resource)

        self.operate(key, "password", resource, actor, change)
        return {"changed": True}
