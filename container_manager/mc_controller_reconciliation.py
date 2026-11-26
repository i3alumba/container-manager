"""Source-only operator CAS. Controller fencing/backups are external prerequisites."""

from .errors import Failure
from .mc_startup_repair import RESOURCE
from .mc_stopped_reconciliation import SPEC, claim, digest, snapshot

PURPOSE = "mc-controller-stopped-v1"


def reconcile_inventory(
    store,
    manifest_path,
    config_path,
    *,
    controller_fenced,
    backup_verified,
    paused_node_verified,
    receipt_directory=None,
):
    """Consume a separate offline manifest, then update only two inventory rows.

    Explicit assertions describe operator obligations, not automatic host checks.
    No operation history, timestamps, or reachability fields are rewritten.
    """
    if not (
        controller_fenced is True
        and backup_verified is True
        and paused_node_verified is True
    ):
        raise Failure("reconciliation_prerequisites_missing")
    manifest = claim(
        manifest_path,
        config_path,
        store.path,
        purpose=PURPOSE,
        receipt_directory=receipt_directory,
    )
    with store.transaction() as db:
        if digest(snapshot(db)) != manifest["database_sha256"]:
            raise Failure("reconciliation_fence_mismatch")
        guest = db.execute("SELECT * FROM instances WHERE id=?", (RESOURCE,)).fetchone()
        port = db.execute("SELECT * FROM ports WHERE id=?", (SPEC["id"],)).fetchone()
        pending = db.execute(
            "SELECT 1 FROM operations WHERE state NOT IN ('done','error')"
        ).fetchone()
        resources = db.execute("SELECT 1 FROM resource_changes_v1").fetchone()
        if (
            not guest
            or guest["status"] != "error"
            or guest["error"] != "power_requires_reconciliation"
            or not port
            or port["status"] != "error"
            or any(port[k] != SPEC[k] for k in SPEC)
            or pending
            or resources
        ):
            raise Failure("reconciliation_scope_mismatch")
        before = snapshot(db)
        db.execute(
            "UPDATE instances SET status='stopped',error=NULL WHERE id=?", (RESOURCE,)
        )
        db.execute("UPDATE ports SET status='active' WHERE id=?", (SPEC["id"],))
        # Verify trigger side effects as well; any unexpected write rolls back.
        after = snapshot(db)
        for table, changes in (
            ("instances", {"status": "stopped", "error": None}),
            ("ports", {"status": "active"}),
        ):
            columns = [r[1] for r in db.execute('PRAGMA table_info("' + table + '")')]
            expected_id = RESOURCE if table == "instances" else SPEC["id"]
            for row in before[table]["rows"]:
                if row[columns.index("id")] == expected_id:
                    for key, value in changes.items():
                        row[columns.index(key)] = value
            import json

            before[table]["rows"].sort(key=lambda row: json.dumps(row, sort_keys=True))
        if after != before:
            raise Failure("reconciliation_unexpected_write")
