import json
import time

import pytest

from container_manager.mc_controller_reconciliation import PURPOSE, reconcile_inventory
from container_manager.mc_startup_repair import RESOURCE
from container_manager.mc_stopped_reconciliation import (
    PORT_SPECS,
    SPEC,
    config_fingerprint,
    prepare,
    read_snapshot,
    source_fingerprint,
)
from container_manager.store import Store


@pytest.mark.parametrize("trigger", [False, True])
@pytest.mark.parametrize(
    "fault",
    [
        None,
        "running",
        "wrong_error",
        "pending",
        "spec",
        "missing",
        "extra",
        "extra_guest",
        "resource",
    ],
)
def test_controller_cas_preserves_history_and_rolls_back_triggers(
    tmp_path, trigger, fault, root_operator_metadata, monkeypatch
):
    app_directory = tmp_path / "app-owned"
    app_directory.mkdir(mode=0o770)
    app_directory.chmod(0o770)
    import os
    from pathlib import Path

    root_stat = Path.stat

    def app_stat(path, **kwargs):
        metadata = root_stat(path, **kwargs)
        if path == app_directory:
            fields = list(metadata)
            fields[4] = fields[5] = 10001
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(Path, "stat", app_stat)
    assert app_directory.stat().st_uid == app_directory.stat().st_gid == 10001
    assert app_directory.stat().st_mode & 0o777 == 0o770
    receipt_directory = tmp_path / "operator-receipts"
    receipt_directory.mkdir(mode=0o700)
    store = Store(str(app_directory / "controller.sqlite"))
    with store.transaction() as db:
        db.execute(
            "INSERT INTO instances VALUES(?, 'mc','example.invalid',1,1,'error','created','unchanged','power_requires_reconciliation')",
            (RESOURCE,),
        )
        for spec in PORT_SPECS:
            db.execute(
                "INSERT INTO ports VALUES(?,?,?,?,?,?,?)",
                (
                    spec["id"],
                    RESOURCE,
                    spec["protocol"],
                    spec["public_port"],
                    spec["target_port"],
                    "error" if spec == SPEC else "active",
                    "not_checked",
                ),
            )
        db.execute(
            "INSERT INTO operations VALUES('old','power',?,'error','operator')",
            (RESOURCE,),
        )
        if trigger:
            db.execute(
                "CREATE TRIGGER poison AFTER UPDATE ON instances BEGIN UPDATE operations SET state='done'; END"
            )
    with store.transaction() as db:
        if fault == "running":
            db.execute("UPDATE instances SET status='running'")
        elif fault == "wrong_error":
            db.execute("UPDATE instances SET error='node_requires_reconciliation'")
        elif fault == "pending":
            db.execute("UPDATE operations SET state='pending'")
        elif fault == "missing":
            db.execute("DELETE FROM ports WHERE public_port=3001")
        elif fault == "extra":
            db.execute(
                "INSERT INTO ports VALUES('extra',?,'tcp',3999,22,'active','not_checked')",
                (RESOURCE,),
            )
        elif fault == "extra_guest":
            db.execute(
                "INSERT INTO instances VALUES('extra','extra','example.invalid',1,1,'stopped','created','unchanged',NULL)"
            )
        elif fault == "resource":
            db.execute(
                "INSERT INTO resource_changes_v1 VALUES(?,1,1,'[]','pending')",
                (RESOURCE,),
            )
        elif fault == "spec":
            db.execute("UPDATE ports SET target_port=3002")
    config = tmp_path / "config.json"
    config.write_text("{}")
    before = read_snapshot(store.path)
    manifest = prepare(
        before,
        config_fingerprint(config),
        source_fingerprint(),
        time.time() + 300,
        purpose=PURPOSE,
    )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    if trigger or fault:
        with pytest.raises(Exception):
            reconcile_inventory(
                store,
                path,
                config,
                controller_fenced=True,
                backup_verified=True,
                paused_node_verified=True,
                receipt_directory=receipt_directory,
            )
        assert read_snapshot(store.path) == before
    else:
        from container_manager.errors import Failure

        with pytest.raises(Failure, match="reconciliation_receipt_directory_required"):
            reconcile_inventory(
                store,
                path,
                config,
                controller_fenced=True,
                backup_verified=True,
                paused_node_verified=True,
            )
        assert read_snapshot(store.path) == before
        reconcile_inventory(
            store,
            path,
            config,
            controller_fenced=True,
            backup_verified=True,
            paused_node_verified=True,
            receipt_directory=receipt_directory,
        )
        after = read_snapshot(store.path)
        for table in before:
            if table not in {"instances", "ports"}:
                assert after[table] == before[table]
        with store.transaction() as db:
            assert tuple(
                db.execute("SELECT status,error,updated_at FROM instances").fetchone()
            ) == ("stopped", None, "unchanged")
            assert db.execute("SELECT status FROM ports").fetchone()[0] == "active"
