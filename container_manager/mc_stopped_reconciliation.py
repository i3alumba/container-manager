"""Offline/operator-only fences for the stopped MC incident; not an RPC API."""

from contextlib import closing

import hashlib
import json
import os
import sqlite3
import stat
import time
from pathlib import Path
from uuid import UUID, uuid4

from .errors import Failure
from .mc_startup_repair import RESOURCE, SPECS

SPEC = SPECS[0]
PURPOSE = "mc-stopped-3002-v1"


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def snapshot(db):
    """Portable logical snapshot of every user table, including schema and history.

    Caller supplies a consistent read-only SQLite connection or an open transaction.
    Never log/export this value: prepare() emits only its digest.
    """
    result = {}
    for name, sql in db.execute(
        "SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ):
        quoted = '"' + name.replace('"', '""') + '"'
        cursor = db.execute("SELECT * FROM " + quoted)
        columns = [column[0] for column in cursor.description]
        rows = [list(row) for row in cursor]
        result[name] = {
            "schema": sql,
            "columns": columns,
            "rows": sorted(rows, key=lambda row: json.dumps(row, sort_keys=True)),
        }
    # Triggers/indexes are part of the fence too.
    result["_schema"] = [
        list(row)
        for row in db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        )
    ]
    return result


def read_snapshot(path):
    with closing(
        sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.execute("BEGIN")
        return snapshot(db)


def source_fingerprint():
    root = Path(__file__).parent
    return digest(
        {
            str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*.py"))
        }
    )


def config_fingerprint(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def prepare(
    selected_snapshot, config_sha256, source_sha256, expires, *, purpose=PURPOSE
):
    """Pure offline API. Hash the selected consistent snapshot, not a live Store."""
    return {
        "purpose": purpose,
        "resource": RESOURCE,
        "database_sha256": digest(selected_snapshot),
        "config_sha256": config_sha256,
        "source_sha256": source_sha256,
        "expires": expires,
        "nonce": str(uuid4()),
    }


def claim(path, config_path, database, *, purpose=PURPOSE, receipt_directory=None):
    """Consume before Store/Incus construction; even incomplete claims cannot replay."""
    if os.geteuid() != 0:
        raise Failure("reconciliation_requires_root")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != 0
            or stat.S_IMODE(meta.st_mode) != 0o600
        ):
            raise Failure("invalid_reconciliation_manifest")
        with os.fdopen(fd, "r", closefd=False) as stream:
            manifest = json.load(stream)
    finally:
        os.close(fd)
    validate_manifest(
        manifest,
        read_snapshot(database),
        config_fingerprint(config_path),
        source_fingerprint(),
        purpose=purpose,
    )
    if purpose != PURPOSE and receipt_directory is None:
        raise Failure("reconciliation_receipt_directory_required")
    receipt_root = (
        Path(receipt_directory)
        if receipt_directory is not None
        else Path(database).resolve().parent
    )
    if receipt_root.is_symlink():
        raise Failure("invalid_reconciliation_directory")
    receipt = receipt_root / (".mc-consumed-" + manifest["nonce"])
    # Operator must retain this protected directory and receipt permanently.
    parent = receipt.parent.stat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o077:
        raise Failure("invalid_reconciliation_directory")
    fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(json.dumps({"manifest_sha256": digest(manifest)}).encode())
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return manifest


def validate_manifest(
    manifest,
    selected_snapshot,
    config_sha256,
    source_sha256,
    *,
    purpose=PURPOSE,
    now=None,
):
    try:
        valid = (
            set(manifest)
            == {
                "purpose",
                "resource",
                "database_sha256",
                "config_sha256",
                "source_sha256",
                "expires",
                "nonce",
            }
            and manifest["purpose"] == purpose
            and manifest["resource"] == RESOURCE
            and str(UUID(manifest["nonce"])) == manifest["nonce"]
            and type(manifest["expires"]) in (int, float)
            and 0 < manifest["expires"] - (time.time() if now is None else now) <= 900
            and manifest["database_sha256"] == digest(selected_snapshot)
            and manifest["config_sha256"] == config_sha256
            and manifest["source_sha256"] == source_sha256
        )
    except (ValueError, TypeError, KeyError):
        valid = False
    if not valid:
        raise Failure("reconciliation_fence_mismatch")
    if purpose == PURPOSE:
        node_snapshot_scope(selected_snapshot)
    elif purpose == "mc-controller-stopped-v1":
        controller_snapshot_scope(selected_snapshot)
    else:
        raise Failure("reconciliation_scope_mismatch")


PORT_SPECS = (
    {
        "id": "cbbee3d4-d034-4bba-96a9-a6e548ccfa9b",
        "instance_id": RESOURCE,
        "protocol": "tcp",
        "public_port": 3001,
        "target_port": 22,
    },
    SPEC,
    SPECS[1],
    {
        "id": "02f5e44b-6dec-42c8-b5af-29e128048d32",
        "instance_id": RESOURCE,
        "protocol": "udp",
        "public_port": 3003,
        "target_port": 3003,
    },
)


def rows(selected, table):
    entry = selected[table]
    return [dict(zip(entry["columns"], row, strict=True)) for row in entry["rows"]]


def no_pending(selected):
    if any(
        row["state"] not in {"done", "error"} for row in rows(selected, "operations")
    ) or rows(selected, "resource_changes_v1"):
        raise Failure("reconciliation_scope_mismatch")


def node_snapshot_scope(selected):
    """Reject even freshly approved hashes of an inventory outside this incident."""
    try:
        no_pending(selected)
        owned = {row["id"]: row for row in rows(selected, "ownership")}
        native = {row["id"]: row for row in rows(selected, "native_tcp_v1")}
        guests = [
            row
            for row in owned.values()
            if "protocol" not in json.loads(row["spec"]) and row["state"] != "deleted"
        ]
        guest = owned[RESOURCE]
        if len(guests) != 1 or guests[0]["id"] != RESOURCE or guest["state"] != "ready":
            raise Failure("reconciliation_scope_mismatch")
        mappings = {
            key: row
            for key, row in owned.items()
            if "protocol" in json.loads(row["spec"])
        }
        if set(mappings) != {spec["id"] for spec in PORT_SPECS} or set(native) != {
            spec["id"] for spec in PORT_SPECS if spec["protocol"] == "tcp"
        }:
            raise Failure("reconciliation_scope_mismatch")
        for spec in PORT_SPECS:
            row = mappings[spec["id"]]
            if json.loads(row["spec"]) != spec or row["state"] != (
                "error" if spec == SPEC else "ready"
            ):
                raise Failure("reconciliation_scope_mismatch")
            if spec["protocol"] == "tcp":
                record = native[spec["id"]]
                if (
                    json.loads(record["spec"]) != spec
                    or record["public_port"] != spec["public_port"]
                    or record["transport"] != "native_tcp_v1"
                    or type(record["address_version"]) is not int
                    or record["address_version"] != 1
                    or record["state"] != ("error" if spec == SPEC else "paused")
                ):
                    raise Failure("reconciliation_scope_mismatch")
        pins = rows(selected, "address_bindings_v1")
        if len(pins) != 1:
            raise Failure("reconciliation_scope_mismatch")
        pin = pins[0]
        if type(pin["version"]) is not int or any(
            pin.get(k) != v
            for k, v in {
                "instance_id": RESOURCE,
                "address": "10.211.0.2",
                "network": "ppub0",
                "nic": "eth0",
                "state": "ready",
                "version": 1,
            }.items()
        ):
            raise Failure("reconciliation_scope_mismatch")
        for row in rows(selected, "node_resource_changes_v1"):
            if (
                row["instance_id"] != RESOURCE
                or row["state"] != "done"
                or str(UUID(row["operation_id"])) != row["operation_id"]
                or json.loads(row["desired"]) != json.loads(guest["spec"])
            ):
                raise Failure("reconciliation_scope_mismatch")
        return pin
    except (KeyError, ValueError, TypeError):
        raise Failure("reconciliation_scope_mismatch") from None


def controller_snapshot_scope(selected):
    try:
        no_pending(selected)
        guests = rows(selected, "instances")
        live = [row for row in guests if row["status"] != "deleted"]
        guest = next(row for row in live if row["id"] == RESOURCE)
        if (
            len(live) != 1
            or guest["status"] != "error"
            or guest["error"] != "power_requires_reconciliation"
            or rows(selected, "node_resource_changes_v1")
        ):
            raise Failure("reconciliation_scope_mismatch")
        ports = [
            row for row in rows(selected, "ports") if row["instance_id"] == RESOURCE
        ]
        if {row["id"] for row in ports} != {spec["id"] for spec in PORT_SPECS}:
            raise Failure("reconciliation_scope_mismatch")
        for spec in PORT_SPECS:
            row = next(row for row in ports if row["id"] == spec["id"])
            if any(row[key] != value for key, value in spec.items()) or row[
                "status"
            ] != ("error" if spec == SPEC else "active"):
                raise Failure("reconciliation_scope_mismatch")
    except (KeyError, ValueError, TypeError, StopIteration):
        raise Failure("reconciliation_scope_mismatch") from None


def check_scope(node):
    pin = node_snapshot_scope(read_snapshot(node.store.path))
    if SPEC["id"] in node.native.bindings:
        raise Failure("reconciliation_scope_mismatch")
    return pin


def reconcile(node, manifest):
    with node.instance_lock(RESOURCE), node.allocation.lock:
        if digest(read_snapshot(node.store.path)) != manifest["database_sha256"]:
            raise Failure("reconciliation_fence_mismatch")
        if not 0 < manifest["expires"] - time.time() <= 900:
            raise Failure("reconciliation_fence_mismatch")
        pin = check_scope(node)
        guest = next(r for r in node.store.ownership() if r["id"] == RESOURCE)
        if node.resource_control.read(RESOURCE, json.loads(guest["spec"])) != "stopped":
            raise Failure("reconciliation_scope_mismatch")
        _, status = node.allocation.validate(RESOURCE, pin)
        if status != "stopped":
            raise Failure("reconciliation_scope_mismatch")
        node.inspector.check("tcp", SPEC["public_port"])
        try:
            node.native.bind(SPEC, False)
            if not node.native.ready(SPEC, False):
                raise Failure("native_tcp_not_ready")
            _, status = node.allocation.validate(RESOURCE, pin)
            if status != "stopped" or node.store.address_binding(RESOURCE) != pin:
                raise Failure("reconciliation_scope_mismatch")
            with node.store.transaction() as db:
                if (
                    manifest["expires"] <= time.time()
                    or digest(snapshot(db)) != manifest["database_sha256"]
                ):
                    raise Failure("reconciliation_fence_mismatch")
                db.execute(
                    "UPDATE native_tcp_v1 SET state='paused' WHERE id=?", (SPEC["id"],)
                )
                db.execute(
                    "UPDATE ownership SET state='ready' WHERE id=?", (SPEC["id"],)
                )
                after = snapshot(db)
                for table in ("ownership", "native_tcp_v1"):
                    columns = [
                        r[1] for r in db.execute('PRAGMA table_info("' + table + '")')
                    ]
                    for row in after[table]["rows"]:
                        if row[columns.index("id")] == SPEC["id"]:
                            wanted = "ready" if table == "ownership" else "paused"
                            if row[columns.index("state")] != wanted:
                                raise Failure("reconciliation_unexpected_write")
                            row[columns.index("state")] = "error"
                    after[table]["rows"].sort(
                        key=lambda row: json.dumps(row, sort_keys=True)
                    )
                if digest(after) != manifest["database_sha256"]:
                    raise Failure("reconciliation_unexpected_write")
        except BaseException:
            try:
                if SPEC["id"] in node.native.bindings:
                    node.native.pause(SPEC)
            except BaseException:
                pass  # Preserve the original failure; listener was bound inactive.
            raise
