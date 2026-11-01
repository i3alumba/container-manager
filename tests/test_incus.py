import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from container_manager.errors import Failure
from container_manager.incus import BOOTSTRAP, Incus, owned_name
from container_manager.store import Store
from conftest import FreeInspector

PROFILE = {
    "devices": {
        "root": {"type": "disk", "path": "/", "pool": "pp-ubuntu-ssd"},
        "eth0": {
            "type": "nic",
            "network": "ppub0",
            "security.ipv4_filtering": "true",
            "security.ipv6_filtering": "true",
            "security.mac_filtering": "true",
            "security.port_isolation": "true",
            "ipv6.address": "none",
        },
    }
}


def test_incus_fixed_security_persistent_home_and_secret_stdin(config, spec):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0, stderr=b"", stdout=json.dumps(PROFILE).encode()
        )

    config = replace(config, image_fingerprint="a" * 64, gamma_ip="10.200.73.2")
    node = Incus(
        config,
        Store(config.database),
        FreeInspector(),
        runner,
        ready=lambda *args: True,
    )
    password = "TransientSecret42!"
    resource = spec["instance_id"]
    node.create(resource, 2, 4_000_000_000, password)
    argv = next(a for a, kw in calls if "init" in a)
    assert argv[:3] == ["incus", "--project", "pp-ubuntu"]
    assert "--profile" in argv and "default" in argv
    assert "--network" not in argv and "--storage" not in argv
    assert "--no-profiles" not in argv
    assert all(
        v in argv
        for v in [
            "security.privileged=false",
            "security.nesting=false",
            "security.idmap.isolated=true",
        ]
    )
    volume = next(a for a, _ in calls if a[3:6] == ["storage", "volume", "create"])
    assert "--type=filesystem" in volume
    assert (
        "--type=custom" not in volume
    )  # Incus --type is CONTENT type, not custom-volume kind.
    assert any("path=/home" in a and "pool=pp-ubuntu-ssd" in a for a, _ in calls)
    assert all(password not in " ".join(a) for a, _ in calls)
    stdin_calls = [(a, kw) for a, kw in calls if kw.get("input")]
    assert len(stdin_calls) == 1
    assert stdin_calls[0][0][-1] == "/usr/sbin/chpasswd"
    assert stdin_calls[0][1]["input"] == f"root:{password}\n".encode()
    assert all("shell" not in kw for _, kw in calls)
    assert (
        "PermitRootLogin yes" in BOOTSTRAP and "PasswordAuthentication yes" in BOOTSTRAP
    )
    assert "ssh-keygen -A" in BOOTSTRAP and "sshd -t" in BOOTSTRAP
    assert password.encode() not in open(config.database, "rb").read()
    node.publish(spec)
    assert "listen=tcp:10.200.73.2:2223" in calls[-1][0]
    assert "connect=tcp:127.0.0.1:22" in calls[-1][0]
    node.power(resource, False)
    node.power(resource, True)
    node.password(resource, password)
    node.remove(spec)
    assert not any("delete" in argv for argv, _ in calls)


def test_incus_partial_guest_is_never_recreated_or_deleted(config, spec):
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(
            returncode=1 if "exec" in argv else 0,
            stderr=b"private error never returned",
            stdout=json.dumps(PROFILE).encode(),
        )

    node = Incus(
        config,
        Store(config.database),
        FreeInspector(),
        runner,
        ready=lambda *args: True,
    )
    with pytest.raises(Failure, match="incus_operation_failed"):
        node.create(spec["instance_id"], 1, 1_000_000_000, "TransientSecret42!")
    before = len(calls)
    with pytest.raises(Failure, match="requires_reconciliation"):
        node.create(spec["instance_id"], 1, 1_000_000_000, "TransientSecret42!")
    assert len(calls) == before
    assert not any("delete" in args for args in calls)


@pytest.mark.parametrize(
    "resource", ["../../etc/passwd", "abc", "550E8400-E29B-41D4-A716-446655440000"]
)
def test_owned_uuid_only(resource):
    with pytest.raises(Failure):
        owned_name(resource)


def test_proxy_readiness_failure_retains_owned_error(config, spec):
    def runner(argv, **kwargs):
        return SimpleNamespace(
            returncode=0, stderr=b"", stdout=json.dumps(PROFILE).encode()
        )

    store = Store(config.database)
    store.own(
        spec["instance_id"],
        {"id": spec["instance_id"], "cpu": 1, "memory_bytes": 1_000_000_000},
        "ready",
    )
    node = Incus(config, store, FreeInspector(), runner, ready=lambda *args: False)
    with pytest.raises(Failure, match="proxy_not_ready"):
        node.publish(spec)
    assert (
        next(r for r in store.ownership() if r["id"] == spec["id"])["state"] == "error"
    )
    with pytest.raises(Failure, match="requires_reconciliation"):
        node.remove(spec)


def test_owned_instance_status_queries_only_fixed_project(config, spec):
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(
            stdout=json.dumps(
                [{"name": owned_name(spec["instance_id"]), "status": "Stopped"}]
            ).encode()
        )

    store = Store(config.database)
    store.own(spec["instance_id"], {"id": spec["instance_id"]}, "ready")
    node = Incus(config, store, FreeInspector(), runner)
    assert node.instance_status(spec["instance_id"]) == "stopped"
    assert calls[0] == [
        "incus",
        "--project",
        "pp-ubuntu",
        "list",
        owned_name(spec["instance_id"]),
        "--format=json",
    ]


@pytest.mark.parametrize("change", ["pool", "network", "filtering", "extra-device"])
def test_operator_profile_drift_fails_before_guest_mutation(config, spec, change):
    import copy

    profile = copy.deepcopy(PROFILE)
    if change == "pool":
        profile["devices"]["root"]["pool"] = "wrong-hdd"
    elif change == "network":
        profile["devices"]["eth0"]["network"] = "wrong-bridge"
    elif change == "filtering":
        profile["devices"]["eth0"]["security.ipv4_filtering"] = "false"
    else:
        profile["devices"]["host"] = {"type": "disk", "source": "/", "path": "/host"}
    calls = []

    def runner(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=json.dumps(profile).encode())

    node = Incus(config, Store(config.database), FreeInspector(), runner)
    with pytest.raises(Failure, match="operator_profile_mismatch"):
        node.create(spec["instance_id"], 1, 1_000_000_000, "TransientSecret42!")
    assert len(calls) == 1 and "query" in calls[0]
    assert not node.store.ownership()


def test_restart_partial_creation_marks_error_keeps_metadata(config, spec):
    store = Store(config.database)
    store.own(
        spec["instance_id"],
        {"id": spec["instance_id"], "cpu": 1, "memory_bytes": 1_000_000_000},
        "creating",
    )
    node = Incus(config, store, FreeInspector())
    assert node.store.ownership()[0]["state"] == "error"
