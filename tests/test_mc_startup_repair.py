import copy
import time
from unittest.mock import Mock

import pytest

from container_manager.errors import Failure
from container_manager.incus import Incus
from container_manager.mc_startup_repair import RESOURCE, SPECS, repair, restore_binding
from container_manager.store import Store


@pytest.fixture
def incident(config, tmp_path):
    store = Store(str(tmp_path / "incident.sqlite"))
    pin = dict(
        instance_id=RESOURCE,
        nic="eth0",
        network="ppub0",
        mac="00:16:3e:00:00:01",
        address="10.211.0.2",
        version=1,
        state="ready",
    )
    store.save_address(pin, "ready")
    store.own(RESOURCE, {"id": RESOURCE}, "ready")
    for spec in SPECS:
        store.native_state(spec, "error")
    node = Incus(config, store, Mock())
    node.allocation.validate = Mock(return_value=({}, "running"))
    node.native.bind = Mock()
    node.native.ready = Mock(return_value=True)
    yield node, pin
    node.close()


def test_repair_verifies_listener_before_persisting_ready(incident):
    node, pin = incident

    def ready(spec, active):
        assert active is True
        assert node.native_record(spec)["state"] == "error"
        return True

    node.native.ready.side_effect = ready
    repair(node, pin, time.monotonic())
    assert all(node.native_record(s)["state"] == "active" for s in SPECS)
    assert node.native.bind.call_count == 2
    with node.store.transaction() as db:
        assert db.execute("SELECT count(*) FROM operations").fetchone()[0] == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("address", "10.211.0.3"),
        ("version", True),
        ("state", "error"),
        ("mac", "different"),
    ],
)
def test_repair_rejects_pin_drift(incident, field, value):
    node, pin = incident
    expected = {**pin, field: value}
    with pytest.raises(Failure):
        repair(node, expected, time.monotonic())
    node.native.bind.assert_not_called()


@pytest.mark.parametrize("state", ["deleting", "deleted", "error"])
def test_repair_rejects_guest_ownership_state(incident, state):
    node, pin = incident
    node.store.own(RESOURCE, {"id": RESOURCE}, state)
    with pytest.raises(Failure):
        repair(node, pin, time.monotonic())
    node.native.bind.assert_not_called()


@pytest.mark.parametrize("mutation", ["spec", "state", "malformed", "resource_intent"])
def test_repair_exact_scope_only(incident, mutation):
    node, pin = incident
    with node.store.transaction() as db:
        if mutation == "resource_intent":
            db.execute(
                "INSERT INTO node_resource_changes_v1 VALUES (?,?,?,?)",
                (RESOURCE, "op", "{}", "error"),
            )
        elif mutation == "state":
            db.execute(
                "UPDATE native_tcp_v1 SET state='active' WHERE id=?", (SPECS[0]["id"],)
            )
        else:
            db.execute(
                "UPDATE ownership SET spec=? WHERE id=?",
                ("null" if mutation == "malformed" else "{}", SPECS[0]["id"]),
            )
    with pytest.raises(Failure):
        repair(node, pin, time.monotonic())
    node.native.bind.assert_not_called()


@pytest.mark.parametrize("stage", ["validate", "inspect", "bind", "ready"])
def test_failure_retains_error_and_reservations(incident, stage):
    node, pin = incident
    if stage == "ready":
        node.native.ready.return_value = False
    else:
        target = {
            "validate": node.allocation.validate,
            "inspect": node.inspector.check,
            "bind": node.native.bind,
        }[stage]
        target.side_effect = Failure("native_tcp_bind_failed")
    with pytest.raises(Failure):
        repair(node, pin, time.monotonic())
    assert all(node.native_record(s)["state"] == "error" for s in SPECS)
    assert node.store.address_binding(RESOURCE) == pin


def test_retry_only_address_in_use_with_fresh_checks(incident, monkeypatch):
    node, pin = incident
    node.native.bind.side_effect = [Failure("native_tcp_address_in_use"), None]
    monkeypatch.setattr(
        "container_manager.mc_startup_repair.time.sleep", lambda _: None
    )
    restore_binding(node, SPECS[0], "active", time.monotonic() + 1)
    assert node.allocation.validate.call_count == 2
    assert node.inspector.check.call_count == 2


def test_expired_retry_deadline_fails_closed(incident):
    node, pin = incident
    node.native.bind.side_effect = Failure("native_tcp_address_in_use")
    with pytest.raises(Failure):
        repair(node, pin, time.monotonic() - 1)
    assert node.native.bind.call_count == 1
    assert node.native_record(SPECS[0])["state"] == "error"


def test_repair_does_not_bind_stopped_guest(incident):
    node, pin = incident
    node.allocation.validate.return_value = ({}, "stopped")
    with pytest.raises(Failure):
        repair(node, pin, time.monotonic())
    node.native.bind.assert_not_called()


def test_repair_preserves_failed_journal_and_healthy_mapping(incident):
    node, pin = incident
    healthy = {
        **SPECS[0],
        "id": "cbbee3d4-d034-4bba-96a9-a6e548ccfa9b",
        "public_port": 3001,
        "target_port": 22,
    }
    node.store.native_state(healthy, "active")
    with node.store.transaction() as db:
        for i in range(4):
            db.execute(
                "INSERT INTO operations VALUES (?,?,?,?,?)",
                (str(i), "start", RESOURCE, "error", "operator"),
            )
        before = [tuple(r) for r in db.execute("SELECT * FROM operations ORDER BY id")]
    # Normal recovery ignores errored repair targets and restores healthy entries.
    node.recover()
    assert node.native.bind.call_args_list[0].args == (healthy, True)
    repair(node, pin, time.monotonic())
    assert node.native_record(healthy)["state"] == "active"
    assert node.native.bind.call_count == 3
    with node.store.transaction() as db:
        assert [
            tuple(r) for r in db.execute("SELECT * FROM operations ORDER BY id")
        ] == before


def test_retry_does_not_run_with_residual_listener(incident):
    node, pin = incident

    def bind(spec, active):
        node.native.bindings[spec["id"]] = Mock()
        raise Failure("native_tcp_address_in_use")

    node.native.bind.side_effect = bind
    with pytest.raises(Failure):
        restore_binding(node, SPECS[0], "active", time.monotonic() + 1)
    assert node.native.bind.call_count == 1
    node.native.bindings.clear()


def test_startup_failure_log_is_sanitized(incident, caplog):
    node, pin = incident
    healthy = {
        **SPECS[0],
        "id": "cbbee3d4-d034-4bba-96a9-a6e548ccfa9b",
        "public_port": 3001,
        "target_port": 22,
    }
    node.store.native_state(healthy, "active")
    node.allocation.validate.side_effect = Failure("untrusted\nprivate payload")
    node.recover()
    assert "code=recovery_failure" in caplog.text
    assert "private payload" not in caplog.text
    assert node.native_record(healthy)["state"] == "error"


def test_partial_repair_failure_closes_forwarding_and_retains_history(incident):
    node, pin = incident
    with node.store.transaction() as db:
        db.execute(
            "INSERT INTO operations VALUES (?,?,?,?,?)",
            ("failed", "start", RESOURCE, "error", "operator"),
        )

    def bind(spec, active):
        if spec == SPECS[1]:
            raise Failure("native_tcp_bind_failed")
        node.native.bindings[spec["id"]] = Mock()

    node.native.bind.side_effect = bind
    node.native.pause = Mock()
    with pytest.raises(Failure):
        repair(node, pin, time.monotonic())
    node.native.pause.assert_called_once_with(SPECS[0])
    assert all(node.native_record(s)["state"] == "error" for s in SPECS)
    with node.store.transaction() as db:
        assert tuple(
            db.execute(
                "SELECT action,state FROM operations WHERE id='failed'"
            ).fetchone()
        ) == ("start", "error")
    node.native.bindings.clear()


@pytest.fixture
def startup_cli(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from container_manager import cli
    from container_manager import mc_startup_repair as module

    config = SimpleNamespace(
        mode="node",
        database=str(tmp_path / "node.sqlite"),
        host_addresses=[],
        inspection_sudo=False,
    )
    backend, host = Mock(), Mock()
    monkeypatch.setattr(
        "sys.argv",
        [
            "container-manager",
            "--config",
            "unused",
            "--repair-mc-native-once",
            "pin.json",
        ],
    )
    monkeypatch.setattr(cli.Config, "load", lambda _: config)
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.os, "umask", lambda _: None)
    monkeypatch.setattr(cli, "Store", Mock())
    monkeypatch.setattr(cli, "Incus", Mock(return_value=backend))
    monkeypatch.setattr(cli, "Inspector", Mock())
    monkeypatch.setattr(cli, "server", Mock(return_value=host))
    monkeypatch.setattr(module, "load_pin", Mock(return_value={"expected": "pin"}))
    monkeypatch.setattr(module, "check_scope", Mock())
    monkeypatch.setattr(module, "repair", Mock())
    return cli, module, config, backend, host


@pytest.mark.parametrize("mode,uid", [("controller", 0), ("relay", 0), ("node", 1000)])
def test_startup_cli_rejects_wrong_mode_or_nonroot(startup_cli, monkeypatch, mode, uid):
    cli, module, config, backend, host = startup_cli
    config.mode = mode
    monkeypatch.setattr(cli.os, "geteuid", lambda: uid)
    with pytest.raises(SystemExit):
        cli.main()
    backend.recover.assert_not_called()
    module.repair.assert_not_called()


@pytest.mark.parametrize("stage", ["load_pin", "check_scope"])
def test_invalid_manifest_still_recovers_healthy_without_repair(startup_cli, stage):
    cli, module, config, backend, host = startup_cli
    getattr(module, stage).side_effect = Failure("invalid_repair_manifest")
    cli.main()
    backend.recover.assert_called_once()
    module.repair.assert_not_called()
    host.start.assert_called_once()


@pytest.mark.parametrize(
    "code,expected",
    [
        ("native_tcp_address_in_use", "native_tcp_address_in_use"),
        ("bad\nprivate payload", "recovery_failure"),
    ],
)
def test_startup_cli_repair_failure_code_sanitized(startup_cli, caplog, code, expected):
    cli, module, config, backend, host = startup_cli
    module.repair.side_effect = Failure(code)
    cli.main()
    assert "mc_startup_repair_failed code=" + expected in caplog.text
    assert "private payload" not in caplog.text
    host.start.assert_called_once()
