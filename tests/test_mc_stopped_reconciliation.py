import copy
import json
import time
from unittest.mock import Mock

import pytest

from container_manager.errors import Failure
from container_manager.incus import Incus
from container_manager.mc_startup_repair import RESOURCE, SPECS
from container_manager.mc_stopped_reconciliation import (
    PORT_SPECS,
    SPEC,
    claim,
    config_fingerprint,
    digest,
    prepare,
    read_snapshot,
    reconcile,
    source_fingerprint,
    validate_manifest,
)
from container_manager.store import Store


@pytest.fixture
def incident(config, tmp_path):
    store = Store(str(tmp_path / "node.sqlite"))
    store.save_address(
        dict(
            instance_id=RESOURCE,
            nic="eth0",
            network="ppub0",
            mac="00:16:3e:00:00:01",
            address="10.211.0.2",
            version=1,
        ),
        "ready",
    )
    store.own(RESOURCE, {"id": RESOURCE}, "ready")
    for spec in PORT_SPECS:
        if spec["protocol"] == "tcp":
            store.native_state(spec, "error" if spec == SPEC else "paused")
        else:
            store.own(spec["id"], spec, "ready")
    node = Incus(config, store, Mock())
    node.allocation.validate = Mock(return_value=({}, "stopped"))
    node.resource_control.read = Mock(return_value="stopped")
    node.native.bind = Mock()
    node.native.ready = Mock(return_value=True)
    manifest = prepare(read_snapshot(store.path), "config", "source", time.time() + 300)
    yield node, manifest
    node.close()


def test_stopped_only_restores_3002(incident):
    node, manifest = incident
    before = read_snapshot(node.store.path)
    reconcile(node, manifest)
    node.native.bind.assert_called_once_with(SPEC, False)
    assert node.native_record(SPEC)["state"] == "paused"
    after = read_snapshot(node.store.path)
    for table in before:
        if table not in {"ownership", "native_tcp_v1"}:
            assert before[table] == after[table]


@pytest.mark.parametrize(
    "drift", ["running", "binding", "pin", "spec", "history", "unrelated"]
)
def test_scope_drift_fails(incident, drift):
    node, manifest = incident
    if drift == "running":
        node.allocation.validate.return_value = ({}, "running")
    elif drift == "binding":
        node.native.bindings[SPEC["id"]] = Mock()
    else:
        with node.store.transaction() as db:
            if drift == "pin":
                db.execute("UPDATE address_bindings_v1 SET address='10.211.0.3'")
            elif drift == "spec":
                db.execute("UPDATE native_tcp_v1 SET spec='{}'")
            elif drift == "history":
                db.execute(
                    "INSERT INTO node_resource_changes_v1 VALUES(?,?,?,'error')",
                    (RESOURCE, "operation", "{}"),
                )
            else:
                db.execute(
                    "INSERT INTO operations VALUES('x','power','x','done','operator')"
                )
    with pytest.raises(Failure):
        reconcile(node, manifest)
    node.native.bind.assert_not_called()
    node.native.bindings.clear()


@pytest.mark.parametrize(
    "field",
    [
        "expires",
        "nonce",
        "database_sha256",
        "config_sha256",
        "source_sha256",
        "purpose",
    ],
)
def test_manifest_fences(incident, field):
    node, manifest = incident
    manifest[field] = 0 if field == "expires" else "wrong"
    with pytest.raises(Failure):
        validate_manifest(manifest, read_snapshot(node.store.path), "config", "source")


@pytest.mark.parametrize("stage", ["bind", "ready", "allocation", "persist"])
def test_failure_retains_error_and_reservation(incident, stage):
    node, manifest = incident
    if stage == "bind":
        node.native.bind.side_effect = Failure("native_tcp_address_in_use")
    elif stage == "ready":
        node.native.ready.return_value = False
    elif stage == "allocation":
        node.allocation.validate.side_effect = [
            ({}, "stopped"),
            Failure("incus_query_unavailable"),
        ]
    else:
        with node.store.transaction() as db:
            db.execute(
                "CREATE TRIGGER deny_pause BEFORE UPDATE ON native_tcp_v1 BEGIN SELECT RAISE(ABORT,'denied'); END"
            )
        manifest["database_sha256"] = digest(read_snapshot(node.store.path))
    before = read_snapshot(node.store.path)
    with pytest.raises(Exception):
        reconcile(node, manifest)
    assert read_snapshot(node.store.path) == before
    assert node.native_record(SPEC)["state"] == "error"
    assert node.native.bind.call_count <= 1


def test_claim_is_durable_and_cannot_replay(incident, tmp_path, root_operator_metadata):
    node, _ = incident
    config = tmp_path / "config.json"
    config.write_text("{}")
    manifest = prepare(
        read_snapshot(node.store.path),
        config_fingerprint(config),
        source_fingerprint(),
        time.time() + 300,
    )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    assert claim(path, config, node.store.path) == manifest
    receipt = tmp_path / (".mc-consumed-" + manifest["nonce"])
    assert receipt.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        claim(path, config, node.store.path)
    moved = tmp_path / "other" / "manifest.json"
    moved.parent.mkdir()
    moved.write_text(path.read_text())
    moved.chmod(0o600)
    with pytest.raises(FileExistsError):
        claim(moved, config, node.store.path)


def test_snapshot_is_portable(incident):
    node, manifest = incident
    selected = json.loads(json.dumps(read_snapshot(node.store.path)))
    assert digest(selected) == manifest["database_sha256"]
    assert (
        prepare(copy.deepcopy(selected), "config", "source", time.time() + 300)[
            "database_sha256"
        ]
        == manifest["database_sha256"]
    )


@pytest.mark.parametrize("fault", ["mode", "symlink", "fsync"])
def test_claim_failure_never_allows_mutation_or_replay(
    incident, tmp_path, root_operator_metadata, monkeypatch, fault
):
    import os

    node, _ = incident
    config = tmp_path / "config.json"
    config.write_text("{}")
    manifest = prepare(
        read_snapshot(node.store.path),
        config_fingerprint(config),
        source_fingerprint(),
        time.time() + 300,
    )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    if fault == "mode":
        path.chmod(0o640)
    elif fault == "symlink":
        link = tmp_path / "link.json"
        link.symlink_to(path)
        path = link
    else:
        monkeypatch.setattr(os, "fsync", Mock(side_effect=OSError("injected")))
    before = read_snapshot(node.store.path)
    with pytest.raises((Failure, OSError)):
        claim(path, config, node.store.path)
    assert read_snapshot(node.store.path) == before
    node.native.bind.assert_not_called()
    if fault == "fsync":
        with pytest.raises(FileExistsError):
            claim(path, config, node.store.path)


def test_cli_rejects_reconciliation_in_controller_mode(monkeypatch):
    import sys
    from types import SimpleNamespace
    from container_manager import cli

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "container-manager",
            "--config",
            "unused",
            "--reconcile-mc-stopped-once",
            "unused",
        ],
    )
    monkeypatch.setattr(
        cli.Config, "load", lambda path: SimpleNamespace(mode="controller")
    )
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2


def test_cli_repair_flags_conflict(monkeypatch):
    import sys
    from container_manager import cli

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "container-manager",
            "--config",
            "unused",
            "--reconcile-mc-stopped-once",
            "unused",
            "--repair-mc-native-once",
            "unused",
        ],
    )
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2


@pytest.mark.parametrize(
    "fault",
    [
        "missing3001",
        "extra",
        "raw_port",
        "transport",
        "addrversion",
        "native_extra",
        "native_missing",
        "spec",
        "healthy_state",
        "udp",
        "pending",
        "resource",
    ],
)
def test_fresh_manifest_bad_scope_rejected_before_constructors(
    incident, tmp_path, root_operator_metadata, monkeypatch, fault, capsys
):
    import sys
    from types import SimpleNamespace
    from container_manager import cli

    node, _ = incident
    with node.store.transaction() as db:
        if fault == "missing3001":
            db.execute("DELETE FROM ownership WHERE id=?", (PORT_SPECS[0]["id"],))
            db.execute("DELETE FROM native_tcp_v1 WHERE id=?", (PORT_SPECS[0]["id"],))
        elif fault == "extra":
            extra = dict(PORT_SPECS[0], id="extra", public_port=3999)
            db.execute(
                "INSERT INTO ownership VALUES(?,?,'ready')",
                (extra["id"], json.dumps(extra)),
            )
        elif fault == "raw_port":
            db.execute(
                "UPDATE native_tcp_v1 SET public_port=3999 WHERE id=?", (SPEC["id"],)
            )
        elif fault in {"transport", "addrversion"}:
            db.execute("PRAGMA ignore_check_constraints=ON")
            if fault == "transport":
                db.execute("UPDATE native_tcp_v1 SET transport='unexpected'")
            else:
                db.execute("UPDATE native_tcp_v1 SET address_version=2")
        elif fault == "native_extra":
            extra = dict(PORT_SPECS[0], id="extra", public_port=3999)
            db.execute(
                "INSERT INTO native_tcp_v1 VALUES(?,?,3999,'native_tcp_v1',1,'paused')",
                (extra["id"], json.dumps(extra)),
            )
        elif fault == "native_missing":
            db.execute("DELETE FROM native_tcp_v1 WHERE public_port=3004")
        elif fault == "spec":
            changed = dict(PORT_SPECS[0], target_port=23)
            db.execute(
                "UPDATE ownership SET spec=? WHERE id=?",
                (json.dumps(changed), changed["id"]),
            )
        elif fault == "healthy_state":
            db.execute("UPDATE native_tcp_v1 SET state='active' WHERE public_port=3004")
        elif fault == "udp":
            db.execute("DELETE FROM ownership WHERE id=?", (PORT_SPECS[3]["id"],))
        elif fault == "pending":
            db.execute(
                "INSERT INTO operations VALUES('pending','power',?,'pending','operator')",
                (RESOURCE,),
            )
        else:
            db.execute(
                "INSERT INTO node_resource_changes_v1 VALUES(?,'pending','{}','pending')",
                (RESOURCE,),
            )
    config = tmp_path / "config.json"
    config.write_text("{}")
    before = read_snapshot(node.store.path)
    manifest = prepare(
        before, config_fingerprint(config), source_fingerprint(), time.time() + 300
    )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "container-manager",
            "--config",
            str(config),
            "--reconcile-mc-stopped-once",
            str(path),
        ],
    )
    monkeypatch.setattr(
        cli.Config,
        "load",
        lambda _: SimpleNamespace(mode="node", database=node.store.path),
    )
    store_constructor, node_constructor = Mock(), Mock()
    monkeypatch.setattr(cli, "Store", store_constructor)
    monkeypatch.setattr(cli, "Incus", node_constructor)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 1
    store_constructor.assert_not_called()
    node_constructor.assert_not_called()
    assert read_snapshot(node.store.path) == before
    assert not list(tmp_path.glob(".mc-consumed-*"))


@pytest.mark.parametrize("stage", ["claim", "recover", "bind", "persist", "cleanup"])
def test_new_cli_failure_boundary_never_leaks_exception(
    incident, tmp_path, root_operator_metadata, monkeypatch, capsys, caplog, stage
):
    import sys
    from types import SimpleNamespace
    from container_manager import cli, mc_stopped_reconciliation as repair

    node, manifest = incident
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "container-manager",
            "--config",
            "unused",
            "--reconcile-mc-stopped-once",
            "unused",
        ],
    )
    monkeypatch.setattr(
        cli.Config,
        "load",
        lambda _: SimpleNamespace(
            mode="node",
            database=node.store.path,
            host_addresses=[],
            inspection_sudo=False,
        ),
    )
    monkeypatch.setattr(repair, "claim", Mock(return_value=manifest))
    monkeypatch.setattr(cli, "Store", Mock(return_value=node.store))
    monkeypatch.setattr(cli, "Incus", Mock(return_value=node))
    monkeypatch.setattr(node, "recover", Mock())
    error = RuntimeError("SENSITIVE-MARKER-private-payload")
    if stage == "claim":
        repair.claim.side_effect = error
    elif stage == "recover":
        node.recover.side_effect = error
    elif stage == "bind":
        node.native.bind.side_effect = error
    elif stage == "persist":
        real_transaction = node.store.transaction
        from contextlib import contextmanager

        @contextmanager
        def failing_transaction():
            with real_transaction() as db:
                yield db
                raise error

        monkeypatch.setattr(node.store, "transaction", failing_transaction)
    else:
        monkeypatch.setattr(repair, "reconcile", Mock(side_effect=error))
        monkeypatch.setattr(node, "close", Mock(side_effect=error))
    with pytest.raises(SystemExit) as exit_error:
        cli.main()
    assert exit_error.value.code == 1
    output = capsys.readouterr()
    combined = output.out + output.err + caplog.text
    assert "SENSITIVE-MARKER" not in combined
    assert "Traceback" not in combined
    assert "mc_stopped_reconciliation_failed" in combined


def test_read_snapshot_closes_connection(incident, monkeypatch):
    from container_manager import mc_stopped_reconciliation as repair

    node, _ = incident
    real_connect = repair.sqlite3.connect
    connection = real_connect(node.store.path)
    monkeypatch.setattr(repair.sqlite3, "connect", lambda *a, **kw: connection)
    repair.read_snapshot(node.store.path)
    with pytest.raises(repair.sqlite3.ProgrammingError, match="closed"):
        connection.execute("SELECT 1")


@pytest.mark.parametrize("directory_kind", ["unprotected", "symlink"])
def test_receipt_directory_rejects_unprotected_and_symlink(
    incident, tmp_path, root_operator_metadata, directory_kind
):
    node, _ = incident
    config = tmp_path / "config.json"
    config.write_text("{}")
    manifest = prepare(
        read_snapshot(node.store.path),
        config_fingerprint(config),
        source_fingerprint(),
        time.time() + 300,
    )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    receipt_root = tmp_path / "receipts"
    receipt_root.mkdir(mode=0o700)
    if directory_kind == "unprotected":
        receipt_root.chmod(0o770)
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(receipt_root, target_is_directory=True)
        receipt_root = alias
    with pytest.raises(Failure, match="invalid_reconciliation_directory"):
        claim(path, config, node.store.path, receipt_directory=receipt_root)
    assert not list(receipt_root.glob(".mc-consumed-*"))
