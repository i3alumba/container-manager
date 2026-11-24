"""Operator-only, incident-scoped startup repair; never exposed through RPC."""

import json
import stat
import time
from pathlib import Path

from .errors import Failure

RESOURCE = "bf8316f7-04dd-43be-8e0b-ea46a4d7c478"
SPECS = (
    {
        "id": "90d7bcfd-8dc9-4bd7-8f9c-6ddf203835e2",
        "instance_id": RESOURCE,
        "protocol": "tcp",
        "public_port": 3002,
        "target_port": 8000,
    },
    {
        "id": "0058c7f1-581f-43f8-9bdd-f7dcc836772f",
        "instance_id": RESOURCE,
        "protocol": "tcp",
        "public_port": 3004,
        "target_port": 3004,
    },
)


def load_pin(path):
    p = Path(path)
    metadata = p.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        raise Failure("invalid_repair_manifest")
    try:
        pin = json.loads(p.read_text())
    except (ValueError, OSError):
        raise Failure("invalid_repair_manifest") from None
    return pin


def check_scope(node, expected_pin):
    if (
        not isinstance(expected_pin, dict)
        or expected_pin.get("instance_id") != RESOURCE
        or expected_pin.get("address") != "10.211.0.2"
        or expected_pin.get("network") != "ppub0"
        or expected_pin.get("nic") != "eth0"
        or expected_pin.get("state") != "ready"
        or type(expected_pin.get("version")) is not int
        or expected_pin["version"] != 1
        or node.store.address_binding(RESOURCE) != expected_pin
    ):
        raise Failure("repair_scope_mismatch")
    ownership = {r["id"]: r for r in node.store.ownership()}
    records = {r["id"]: r for r in node.store.native_records()}
    guest = ownership.get(RESOURCE)
    if not guest or guest["state"] != "ready":
        raise Failure("repair_scope_mismatch")
    with node.store.transaction() as db:
        if db.execute(
            "SELECT 1 FROM node_resource_changes_v1 WHERE instance_id=?", (RESOURCE,)
        ).fetchone():
            raise Failure("repair_scope_mismatch")
    for spec in SPECS:
        owned, record = ownership.get(spec["id"]), records.get(spec["id"])
        try:
            valid = (
                owned
                and record
                and owned["state"] == record["state"] == "error"
                and json.loads(owned["spec"]) == json.loads(record["spec"]) == spec
                and record["transport"] == "native_tcp_v1"
                and record["address_version"] == 1
            )
        except (ValueError, TypeError, KeyError):
            valid = False
        if not valid or spec["id"] in node.native.bindings:
            raise Failure("repair_scope_mismatch")


def restore_binding(node, spec, wanted_state, deadline=None, require_running=False):
    while True:
        pin = node.store.address_binding(spec["instance_id"])
        if not pin or pin["state"] != "ready":
            raise Failure("address_requires_reconciliation", 409)
        _, status = node.allocation.validate(spec["instance_id"], pin)
        if require_running and status != "running":
            raise Failure("repair_scope_mismatch")
        node.inspector.check("tcp", spec["public_port"])
        active = status == "running" and wanted_state == "active"
        try:
            node.native.bind(spec, active)
        except Failure as error:
            if (
                error.code != "native_tcp_address_in_use"
                or deadline is None
                or time.monotonic() >= deadline
                or spec["id"] in node.native.bindings
            ):
                raise
            time.sleep(0.5)
            continue
        if not node.native.ready(spec, active):
            raise Failure("native_tcp_not_ready")
        node.store.native_state(spec, "active" if active else "paused")
        return


def repair(node, expected_pin, deadline):
    with node.instance_lock(RESOURCE), node.allocation.lock:
        check_scope(node, expected_pin)
        _, status = node.allocation.validate(RESOURCE, expected_pin)
        if status != "running":
            raise Failure("repair_scope_mismatch")
        try:
            for spec in SPECS:
                if node.store.address_binding(RESOURCE) != expected_pin:
                    raise Failure("repair_scope_mismatch")
                restore_binding(node, spec, "active", deadline, require_running=True)
        except Failure:
            for spec in SPECS:
                if spec["id"] in node.native.bindings:
                    node.native.pause(spec)
                node.store.native_state(spec, "error")
            raise
