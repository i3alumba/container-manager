import copy
import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from container_manager.api import app_for
from container_manager.controller import Controller
from container_manager.errors import Failure
from container_manager.incus import Incus, owned_name
from container_manager.models import Create, ResourceChange, Resources
from container_manager.resource_control import gpu_device
from container_manager.store import Store
from conftest import FreeInspector
from test_auth_api import client, AUTH
from test_incus import PROFILE

GPU = "0000:01:00.0"


def change(instance, **values):
    return ResourceChange(
        cpu=values.pop("cpu", instance["cpu"]),
        memory_gb=values.pop("memory_gb", instance["memory_gb"]),
        gpu_ids=values.pop("gpu_ids", instance["gpu_ids"]),
        expected_version=values.pop("expected_version", instance["resource_version"]),
        **values,
    )


def test_removed_per_instance_and_default_aggregate_limits(controller, body):
    body.update(cpu=16, memory_gb="32.125", ports=[])
    one = controller.create(Create(**body), "admin")
    body["name"] = "another"
    two = controller.create(Create(**body), "admin")
    assert one["cpu"] == two["cpu"] == 16
    assert one["memory_gb"] == two["memory_gb"] == 32.125
    assert controller.config.pool_cpu is controller.config.pool_memory_gb is None


@pytest.mark.parametrize(
    "fields",
    [
        dict(cpu=True),
        dict(cpu=0),
        dict(cpu=1.5),
        dict(cpu=2**32),
        dict(memory_gb=True),
        dict(memory_gb="NaN"),
        dict(memory_gb="Infinity"),
        dict(memory_gb="0.0001"),
        dict(memory_gb=0),
        dict(gpu_ids=["/dev/dri/renderD128"]),
        dict(gpu_ids=[GPU, GPU]),
        dict(gpu_ids=[True]),
        dict(gpu_ids=["0000:01:00.0;sh"]),
        dict(allow_restart="yes"),
    ],
)
def test_resource_input_fails_closed(fields):
    with pytest.raises(ValidationError):
        ResourceChange(**({"cpu": 8, "memory_gb": 32, "expected_version": 0} | fields))


def test_capabilities_unbounded_and_old_agent_fail_closed(controller):
    api = client(controller)
    caps = api.get("/api/containers/capabilities", headers=AUTH).json()
    assert caps["max_cpu"] is caps["max_memory_gb"] is None
    assert caps["aggregate_budget"] == {"cpu": None, "memory_gb": None}
    assert caps["resources_editing_enabled"] is True and caps["gpu_shared"] is True
    controller.node.fail = "resources"
    caps = api.get("/api/containers/capabilities", headers=AUTH).json()
    assert caps["resources_editing_enabled"] is False and caps["gpus"] == []


def test_existing_edit_is_revisioned_idempotent_and_preserves_ports(controller, body):
    instance = controller.create(Create(**body), "admin")
    key = str(uuid4())
    edited = controller.update_resources(
        instance["id"], change(instance, cpu=8, memory_gb="32.125"), "admin", key
    )
    assert edited["cpu"] == 8 and edited["memory_gb"] == 32.125
    assert edited["resource_version"] == 1 and edited["ports"] == instance["ports"]
    assert (
        edited["id"] == instance["id"]
        and edited["created_at"] == instance["created_at"]
    )
    calls = list(controller.node.calls)
    replay = controller.update_resources(
        instance["id"], change(instance, cpu=12), "admin", key
    )
    assert replay == edited and controller.node.calls == calls
    with pytest.raises(Failure, match="resources_conflict"):
        controller.update_resources(instance["id"], change(instance), "admin")
    assert controller.node.calls == calls


def test_restart_consent_and_stopped_stays_stopped(controller, body):
    instance = controller.create(Create(**body), "admin")
    for values in [dict(memory_gb=1), dict(gpu_ids=[GPU])]:
        with pytest.raises(Failure, match="restart_required"):
            controller.update_resources(
                instance["id"], change(instance, **values), "admin"
            )
    assert not any(c[0] == "update_resources" for c in controller.node.calls)
    controller.power(instance["id"], False, "admin")
    stopped = controller.store.instance(instance["id"])
    result = controller.update_resources(
        instance["id"], change(stopped, memory_gb=1, gpu_ids=[GPU]), "admin"
    )
    assert result["status"] == "stopped" and result["gpu_ids"] == [GPU]


def test_gpu_shared_create_and_updates(controller, body):
    body.update(ports=[], gpu_ids=[GPU])
    one = controller.create(Create(**body), "admin")
    body["name"] = "another"
    two = controller.create(Create(**body), "admin")
    assert one["gpu_ids"] == two["gpu_ids"] == [GPU]
    request = change(one, gpu_ids=[], allow_restart=True)
    updated = controller.update_resources(one["id"], request, "admin")
    assert updated["gpu_ids"] == [] and controller.store.instance(two["id"])[
        "gpu_ids"
    ] == [GPU]


def test_error_keeps_uncertain_reservation_and_no_blind_retry(controller, body):
    instance = controller.create(Create(**body), "admin")
    controller.node.fail = "update_resources"
    key = str(uuid4())
    with pytest.raises(Failure):
        controller.update_resources(
            instance["id"], change(instance, cpu=8, memory_gb=32), "admin", key
        )
    assert controller.store.instance(instance["id"])["status"] == "error"
    with controller.store.transaction() as db:
        cpu, memory = controller.store.reserved_resources(db)
        assert cpu == 8 and memory == 32
    calls = list(controller.node.calls)
    for retry_key in [key, str(uuid4())]:
        with pytest.raises(Failure):
            controller.update_resources(
                instance["id"], change(instance), "admin", retry_key
            )
    assert controller.node.calls == calls
    assert controller.store.instance(instance["id"])["ports"] == instance["ports"]


def test_explicit_optional_budget_is_not_bypassed_by_resize(controller, body):
    instance = controller.create(Create(**body), "admin")
    controller.config = replace(controller.config, pool_cpu=4, pool_memory_gb=16)
    with pytest.raises(Failure, match="aggregate_budget_exceeded"):
        controller.update_resources(instance["id"], change(instance, cpu=8), "admin")
    assert controller.store.instance(instance["id"])["status"] == "running"


@pytest.mark.parametrize(
    "fields", [dict(cpu=4), dict(memory_gb=16), dict(gpu_ids=[GPU])]
)
def test_lowered_budget_allows_corrective_downsize_and_gpu_only(
    controller, body, fields
):
    body.update(cpu=8, memory_gb=32, ports=[])
    instance = controller.create(Create(**body), "admin")
    controller.config = replace(controller.config, pool_cpu=4, pool_memory_gb=16)
    edited = controller.update_resources(
        instance["id"], change(instance, allow_restart=True, **fields), "admin"
    )
    assert edited["resource_version"] == 1
    for key, value in fields.items():
        assert edited[key] == value


@pytest.mark.parametrize("fields", [dict(cpu=9), dict(memory_gb=33)])
def test_lowered_budget_still_blocks_increases(controller, body, fields):
    body.update(cpu=8, memory_gb=32, ports=[])
    instance = controller.create(Create(**body), "admin")
    controller.config = replace(controller.config, pool_cpu=4, pool_memory_gb=16)
    with pytest.raises(Failure, match="aggregate_budget_exceeded"):
        controller.update_resources(instance["id"], change(instance, **fields), "admin")
    assert not any(call[0] == "update_resources" for call in controller.node.calls)


def test_failed_corrective_downsize_retains_previous_reservation(controller, body):
    body.update(cpu=8, memory_gb=32, ports=[])
    instance = controller.create(Create(**body), "admin")
    controller.config = replace(controller.config, pool_cpu=4, pool_memory_gb=16)
    controller.node.fail = "update_resources"
    with pytest.raises(Failure):
        controller.update_resources(
            instance["id"],
            change(instance, cpu=4, memory_gb=16, allow_restart=True),
            "admin",
        )
    with controller.store.transaction() as db:
        assert tuple(controller.store.reserved_resources(db)) == (8, 32)
    assert controller.store.instance(instance["id"])["status"] == "error"


def test_legacy_database_gets_non_destructive_resource_defaults(config):
    store = Store(config.database)
    resource = str(uuid4())
    with store.transaction() as db:
        db.execute(
            "INSERT INTO instances VALUES(?,?,?,?,?,'stopped',?,?,NULL)",
            (resource, "legacy", "legacy.i3alumba.ru", 2, 8, "then", "then"),
        )
    restored = Store(config.database).instance(resource)
    assert restored["gpu_ids"] == [] and restored["resource_version"] == 0
    assert restored["created_at"] == "then" and restored["cpu"] == 2


def test_http_edit_authenticated_and_validated(controller, body):
    instance = controller.create(Create(**body), "admin")
    api = client(controller)
    path = "/api/containers/" + instance["id"] + "/resources"
    assert api.post(path, json={}).status_code == 401
    payload = dict(
        cpu=8, memory_gb=32, gpu_ids=[], expected_version=0, allow_restart=False
    )
    assert (
        api.post(
            path, json=payload | {"host_path": "/dev/nvidia0"}, headers=AUTH
        ).status_code
        == 422
    )
    response = api.post(path, json=payload, headers=AUTH)
    assert response.status_code == 200 and response.json()["resource_version"] == 1
    assert api.post(path, json=payload, headers=AUTH).status_code == 409


class NativeFixture:
    def __init__(self, resource):
        self.resource = resource
        self.calls = []
        self.fail_after_config = False
        self.no_readback = False
        self.name = owned_name(resource)
        self.info = {
            "cpu": {"total": 64},
            "memory": {"total": 128_000_000_000},
            "gpu": {
                "cards": [
                    {
                        "pci_address": GPU,
                        "vendor": "NVIDIA",
                        "product": "Shared test card",
                    }
                ]
            },
        }
        self.project = {
            "config": {"restricted": "true", "restricted.devices.gpu": "allow"}
        }
        home = {
            "type": "disk",
            "pool": "pp-ubuntu-ssd",
            "source": self.name + "-home",
            "path": "/home",
        }
        self.instance = {
            "name": self.name,
            "project": "pp-ubuntu",
            "type": "container",
            "profiles": ["default"],
            "ephemeral": False,
            "status": "Running",
            "devices": {"home": home},
            "expanded_devices": {**copy.deepcopy(PROFILE["devices"]), "home": home},
            "expanded_config": {
                "limits.cpu": "2",
                "limits.memory": "8000000000",
                "security.privileged": "false",
                "security.nesting": "false",
                "security.idmap.isolated": "true",
            },
        }

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ["incus", "query"]:
            uri = argv[2]
            data = (
                self.info
                if uri == "/1.0/resources"
                else (
                    self.project
                    if uri == "/1.0/projects/pp-ubuntu"
                    else PROFILE if "/profiles/" in uri else self.instance
                )
            )
            return SimpleNamespace(
                returncode=0, stdout=json.dumps(data).encode(), stderr=b""
            )
        assert argv[:3] == ["incus", "--project", "pp-ubuntu"]
        args = argv[3:]
        if args[:2] == ["config", "set"]:
            if not self.no_readback:
                for value in args[3:]:
                    key, val = value.split("=", 1)
                    self.instance["expanded_config"][key] = val
            if self.fail_after_config:
                return SimpleNamespace(returncode=1, stderr=b"private host failure")
        elif args[:3] == ["config", "device", "add"]:
            dev = {"type": args[5], **dict(v.split("=", 1) for v in args[6:])}
            self.instance["devices"][args[4]] = dev
            self.instance["expanded_devices"][args[4]] = copy.deepcopy(dev)
        elif args[:3] == ["config", "device", "remove"]:
            del self.instance["devices"][args[4]]
            del self.instance["expanded_devices"][args[4]]
        elif args[0] in {"start", "stop"}:
            self.instance["status"] = "Running" if args[0] == "start" else "Stopped"
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


@pytest.fixture
def native(config, tmp_path):
    resource = str(uuid4())
    fixture = NativeFixture(resource)
    store = Store(str(tmp_path / "native.sqlite"))
    old = {"id": resource, "cpu": 2, "memory_bytes": 8_000_000_000}
    store.own(resource, old, "ready")
    node = Incus(
        replace(config, gpu_allowed_pci=[GPU]), store, FreeInspector(), fixture
    )
    return node, fixture, old


def native_update(native, **values):
    node, fixture, old = native
    return node.update_resources(
        old["id"],
        values.get("cpu", 8),
        values.get("memory_bytes", 32_000_000_000),
        values.get("gpu_ids", []),
        values.get("allow_restart", False),
        str(uuid4()),
        old["cpu"],
        old["memory_bytes"],
        old.get("gpu_ids", []),
    )


def test_native_cpu_memory_hot_update_no_recreate(native):
    node, fixture, old = native
    assert native_update(native) == "running"
    assert not any(
        a[3:4] in [["start"], ["stop"], ["init"], ["delete"], ["storage"]]
        for a in fixture.calls
    )
    assert json.loads(node.store.ownership()[0]["spec"])["cpu"] == 8
    assert fixture.instance["devices"] == {"home": fixture.instance["devices"]["home"]}


def test_native_gpu_restart_and_preserve_home(native):
    node, fixture, old = native
    home = copy.deepcopy(fixture.instance["devices"]["home"])
    with pytest.raises(Failure, match="restart_required"):
        native_update(native, gpu_ids=[GPU])
    assert all(a[:2] == ["incus", "query"] for a in fixture.calls)
    assert native_update(native, gpu_ids=[GPU], allow_restart=True) == "running"
    operations = [a[3:] for a in fixture.calls if a[:2] != ["incus", "query"]]
    assert operations[0] == ["stop", fixture.name] and operations[-1] == [
        "start",
        fixture.name,
    ]
    assert fixture.instance["devices"][gpu_device(GPU)] == {
        "type": "gpu",
        "gputype": "physical",
        "pci": GPU,
    }
    assert fixture.instance["devices"]["home"] == home
    assert not any(a[0] in {"delete", "init", "storage"} for a in operations)


def test_native_gpu_detach_removes_only_owned_device(native):
    node, fixture, old = native
    native_update(native, gpu_ids=[GPU], allow_restart=True)
    current = json.loads(
        next(r["spec"] for r in node.store.ownership() if r["id"] == old["id"])
    )
    assert (
        node.update_resources(
            old["id"],
            current["cpu"],
            current["memory_bytes"],
            [],
            True,
            str(uuid4()),
            current["cpu"],
            current["memory_bytes"],
            [GPU],
        )
        == "running"
    )
    assert gpu_device(GPU) not in fixture.instance["devices"]
    assert "home" in fixture.instance["devices"]
    assert not any(
        "delete" in command or "storage" in command for command in fixture.calls
    )


def test_native_create_attaches_shared_gpu_before_first_start(config, tmp_path):
    resource = str(uuid4())
    fixture = NativeFixture(resource)
    node = Incus(
        replace(config, gpu_allowed_pci=[GPU]),
        Store(str(tmp_path / "gpu-create.sqlite")),
        FreeInspector(),
        fixture,
    )
    node.create(resource, 8, 32_000_000_000, "TransientSecret42!", [GPU])
    gpu_at = next(
        i for i, command in enumerate(fixture.calls) if gpu_device(GPU) in command
    )
    start_at = next(
        i for i, command in enumerate(fixture.calls) if command[3:4] == ["start"]
    )
    assert gpu_at < start_at
    assert json.loads(node.store.ownership()[0]["spec"])["gpu_ids"] == [GPU]
    assert all(
        "TransientSecret42!" not in " ".join(command) for command in fixture.calls
    )


def test_native_stopped_gpu_change_never_starts(native):
    node, fixture, old = native
    fixture.instance["status"] = "Stopped"
    assert native_update(native, gpu_ids=[GPU], memory_bytes=4_000_000_000) == "stopped"
    assert not any(a[3:4] in [["start"], ["stop"]] for a in fixture.calls)


@pytest.mark.parametrize(
    "drift", ["privileged", "foreign-gpu", "home", "cpu", "nic", "foreign-disk"]
)
def test_native_drift_never_adopted_or_mutated(native, drift):
    node, fixture, old = native
    if drift == "privileged":
        fixture.instance["expanded_config"]["security.privileged"] = "true"
    if drift == "cpu":
        fixture.instance["expanded_config"]["limits.cpu"] = "4"
    if drift == "home":
        fixture.instance["devices"]["home"]["source"] = "/host"
    if drift == "nic":
        fixture.instance["expanded_devices"]["eth0"]["network"] = "foreign"
    if drift in {"foreign-gpu", "foreign-disk"}:
        dev = {"type": "gpu" if drift == "foreign-gpu" else "disk", "pci": GPU}
        fixture.instance["devices"]["foreign"] = dev
        fixture.instance["expanded_devices"]["foreign"] = dev
    with pytest.raises(Failure):
        native_update(native)
    assert all(a[:2] == ["incus", "query"] for a in fixture.calls)


@pytest.mark.parametrize(
    "cause", ["capacity", "allowlist", "project-policy", "unknown-gpu"]
)
def test_native_gpu_host_policy_checked_before_stop(native, cause):
    node, fixture, old = native
    if cause == "capacity":
        fixture.info["memory"]["total"] = 16_000_000_000
    if cause == "allowlist":
        node.config = replace(node.config, gpu_allowed_pci=[])
    if cause == "project-policy":
        fixture.project["config"]["restricted.devices.gpu"] = "block"
    if cause == "unknown-gpu":
        fixture.info["gpu"]["cards"] = []
    with pytest.raises(Failure):
        native_update(native, gpu_ids=[GPU], allow_restart=True)
    assert all(a[:2] == ["incus", "query"] for a in fixture.calls)


@pytest.mark.parametrize("failure", ["lost-reply", "readback"])
def test_native_ambiguous_update_persists_error_never_retries(native, failure):
    node, fixture, old = native
    fixture.fail_after_config = failure == "lost-reply"
    fixture.no_readback = failure == "readback"
    with pytest.raises(Failure):
        native_update(native)
    assert node.store.ownership()[0]["state"] == "error"
    calls = list(fixture.calls)
    with pytest.raises(Failure):
        native_update(native)
    assert fixture.calls == calls


def test_node_restart_fences_pending_resource_intent(native):
    node, fixture, old = native
    node.store.begin_resource_intent(old["id"], str(uuid4()), {**old, "cpu": 8})
    restarted = Incus(node.config, node.store, FreeInspector(), fixture)
    with pytest.raises(Failure, match="reconciliation"):
        restarted.require(old["id"])
    assert fixture.calls == []
