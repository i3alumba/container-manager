"""Synthetic Incus 7.5 bare query shapes, never real host snapshots."""

import copy
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from container_manager.allocation import NIC
from container_manager.errors import Failure
from container_manager.incus import Incus, owned_name
from container_manager.store import Store
from conftest import FreeInspector
from test_incus import PROFILE


class Daemon:
    def __init__(self, resource):
        self.calls = []
        self.name = owned_name(resource)
        self.instance = {
            "name": owned_name(resource),
            "project": "pp-ubuntu",
            "type": "container",
            "config": {},
            "expanded_config": {
                "volatile.eth0.hwaddr": "10:66:6a:aa:bb:cc",
                "security.privileged": "false",
                "security.nesting": "false",
                "security.idmap.isolated": "true",
            },
            "devices": {},
            "expanded_devices": {
                "eth0": dict(NIC),
                "root": dict(PROFILE["devices"]["root"]),
            },
            "status": "Running",
        }
        self.network = {
            "managed": True,
            "type": "bridge",
            "config": {"ipv4.address": "10.211.0.1/24", "ipv6.address": "none"},
        }
        self.leases = [
            {
                "address": "10.211.0.42",
                "hwaddr": "10:66:6a:aa:bb:cc",
                "hostname": "untrusted",
                "location": "none",
                "type": "dynamic",
            }
        ]
        self.foreign = []
        self.fail_override = False
        self.drift = False
        self.before_override = lambda: None

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[1] == "query":
            assert "--project" not in argv
            uri = argv[2]
            if uri.startswith("/1.0/profiles/"):
                value = PROFILE
            elif uri == "/1.0/networks/ppub0":
                value = self.network
            elif uri.endswith("/leases"):
                value = self.leases
            elif uri == "/1.0/instances?all-projects=true&recursion=1":
                value = [self.instance, *self.foreign]
            else:
                assert uri == f"/1.0/instances/{self.name}?project=pp-ubuntu"
                value = self.instance
            return SimpleNamespace(stdout=json.dumps(value).encode(), returncode=0)
        assert argv[:3] == ["incus", "--project", "pp-ubuntu"]
        if "override" in argv:
            self.before_override()
            if self.fail_override:
                return SimpleNamespace(returncode=1, stderr=b"private diagnostic")
            nic = {**NIC, "ipv4.address": argv[-1].split("=", 1)[1]}
            if self.drift:
                nic["security.mac_filtering"] = "false"
            self.instance["devices"]["eth0"] = nic
            self.instance["expanded_devices"]["eth0"] = dict(nic)
        if argv[3] in {"start", "stop"}:
            self.instance["status"] = "Running" if argv[3] == "start" else "Stopped"
        return SimpleNamespace(returncode=0, stderr=b"")


@pytest.fixture
def allocation_node(config, spec):
    daemon = Daemon(spec["instance_id"])
    store = Store(config.database)
    store.own(spec["instance_id"], {"id": spec["instance_id"]}, "ready")
    node = Incus(config, store, FreeInspector(), daemon)
    yield node, daemon
    node.close()


def test_pin_writeahead_readback_and_stopped_missing_lease(allocation_node, spec):
    node, daemon = allocation_node

    def pending():
        assert node.store.address_binding(spec["instance_id"])["state"] == "pending"

    daemon.before_override = pending
    pin = node.allocation.pin(spec["instance_id"])
    assert pin["address"] == "10.211.0.42"
    assert pin["state"] == "ready"
    assert daemon.instance["devices"]["eth0"] == {**NIC, "ipv4.address": pin["address"]}
    daemon.leases = []
    daemon.instance["status"] = "Stopped"
    assert node.allocation.validate(spec["instance_id"], pin)[1] == "stopped"
    assert node.allocation.pin(spec["instance_id"]) == pin


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "foreign-mac",
        "duplicate-lease",
        "gateway",
        "network-address",
        "broadcast",
        "outside",
        "project",
        "name",
        "nic",
        "network",
        "network-ipv6",
        "stopped",
        "duplicate-mac",
        "duplicate-ip",
        "missing-claim",
        "local-nic",
    ],
)
def test_pin_denies_untrusted_or_ambiguous_allocation(allocation_node, spec, fault):
    node, daemon = allocation_node
    if fault == "missing":
        daemon.leases = []
    elif fault == "foreign-mac":
        daemon.leases[0]["hwaddr"] = "10:66:6a:aa:bb:dd"
    elif fault == "duplicate-lease":
        daemon.leases *= 2
    elif fault in {"gateway", "network-address", "broadcast", "outside"}:
        daemon.leases[0]["address"] = {
            "gateway": "10.211.0.1",
            "network-address": "10.211.0.0",
            "broadcast": "10.211.0.255",
            "outside": "127.0.0.1",
        }[fault]
    elif fault == "project":
        daemon.instance["project"] = "foreign"
    elif fault == "name":
        daemon.instance["name"] = owned_name(str(uuid4()))
    elif fault == "nic":
        daemon.instance["expanded_devices"]["eth0"]["network"] = "other"
    elif fault == "network":
        daemon.network["managed"] = False
    elif fault == "network-ipv6":
        daemon.network["config"]["ipv6.address"] = "auto"
    elif fault == "stopped":
        daemon.instance["status"] = "Stopped"
    elif fault == "missing-claim":
        daemon.instance["expanded_devices"]["eth0"]["type"] = "disk"
    elif fault == "local-nic":
        daemon.instance["devices"]["eth0"] = {**NIC, "mtu": "9000"}
    else:
        foreign = copy.deepcopy(daemon.instance)
        foreign["project"] = "another-project"
        foreign["name"] = "foreign"
        if fault == "duplicate-ip":
            foreign["expanded_config"]["volatile.eth0.hwaddr"] = "10:66:6a:aa:bb:dd"
            foreign["expanded_devices"]["eth0"]["ipv4.address"] = "10.211.0.42"
        daemon.foreign.append(foreign)
    with pytest.raises(Failure):
        node.allocation.pin(spec["instance_id"])
    assert not any("override" in call for call in daemon.calls)
    assert node.store.address_binding(spec["instance_id"]) is None


@pytest.mark.parametrize("fault", ["command", "readback"])
def test_pin_fault_retains_error_and_unique_reservation(allocation_node, spec, fault):
    node, daemon = allocation_node
    daemon.fail_override = fault == "command"
    daemon.drift = fault == "readback"
    with pytest.raises(Failure):
        node.allocation.pin(spec["instance_id"])
    pin = node.store.address_binding(spec["instance_id"])
    assert pin["state"] == "error"
    with pytest.raises(Failure, match="requires_reconciliation"):
        node.allocation.pin(spec["instance_id"])
    with pytest.raises(Failure, match="allocation_conflict"):
        node.store.save_address({**pin, "instance_id": str(uuid4())}, "pending")


@pytest.mark.parametrize("drift", ["mac", "address", "local", "duplicate"])
def test_pinned_live_drift_denied(allocation_node, spec, drift):
    node, daemon = allocation_node
    pin = node.allocation.pin(spec["instance_id"])
    if drift == "mac":
        daemon.instance["expanded_config"]["volatile.eth0.hwaddr"] = "10:66:6a:aa:bb:dd"
    elif drift == "address":
        daemon.instance["expanded_devices"]["eth0"]["ipv4.address"] = "10.211.0.43"
    elif drift == "local":
        daemon.instance["devices"].clear()
    else:
        daemon.leases.append(
            {
                "address": pin["address"],
                "hwaddr": "10:66:6a:aa:bb:dd",
                "type": "dynamic",
            }
        )
    with pytest.raises(Failure):
        node.allocation.validate(spec["instance_id"], pin)


def test_existing_local_dynamic_nic_never_overwritten_retains_intent(
    allocation_node, spec
):
    node, daemon = allocation_node
    daemon.instance["devices"]["eth0"] = dict(NIC)
    with pytest.raises(Failure, match="local_nic_requires_reconciliation"):
        node.allocation.pin(spec["instance_id"])
    assert node.store.address_binding(spec["instance_id"])["state"] == "error"
    assert not any("override" in call or "set" in call for call in daemon.calls)
    assert daemon.instance["devices"]["eth0"] == NIC


def test_address_intent_commit_failure_prevents_mutation(
    allocation_node, spec, monkeypatch
):
    node, daemon = allocation_node

    def fail(*_):
        raise Failure("injected_commit_failure")

    monkeypatch.setattr(node.store, "save_address", fail)
    with pytest.raises(Failure):
        node.allocation.pin(spec["instance_id"])
    assert not any("override" in call for call in daemon.calls)
    assert node.store.address_binding(spec["instance_id"]) is None


def test_address_ready_commit_failure_retains_error(allocation_node, spec, monkeypatch):
    node, daemon = allocation_node
    original = node.store.save_address

    def save(pin, state):
        if state == "ready":
            raise Failure("injected_commit_failure")
        return original(pin, state)

    monkeypatch.setattr(node.store, "save_address", save)
    with pytest.raises(Failure):
        node.allocation.pin(spec["instance_id"])
    assert node.store.address_binding(spec["instance_id"])["state"] == "error"
    assert daemon.instance["devices"]["eth0"]["ipv4.address"] == "10.211.0.42"


def test_address_unique_across_database_connections(allocation_node, spec):
    node, daemon = allocation_node
    pin = node.allocation.pin(spec["instance_id"])
    other = Store(node.store.path)
    with pytest.raises(Failure, match="allocation_conflict"):
        other.save_address({**pin, "instance_id": str(uuid4())}, "pending")


@pytest.mark.parametrize("field", ["root", "privileged", "nesting", "idmap"])
def test_instance_security_drift_blocks_pin(allocation_node, spec, field):
    node, daemon = allocation_node
    if field == "root":
        daemon.instance["expanded_devices"]["root"]["pool"] = "foreign"
    else:
        key = {
            "privileged": "security.privileged",
            "nesting": "security.nesting",
            "idmap": "security.idmap.isolated",
        }[field]
        daemon.instance["expanded_config"][key] = (
            "true" if field != "idmap" else "false"
        )
    with pytest.raises(Failure):
        node.allocation.pin(spec["instance_id"])
    assert not any("override" in call for call in daemon.calls)
