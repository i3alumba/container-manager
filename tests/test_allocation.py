"""Synthetic Incus 7.5 bare query shapes, never real host snapshots."""

import copy
import json
from types import SimpleNamespace
from uuid import uuid4
from urllib.parse import parse_qs, urlsplit
import subprocess

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
        self.projects = [
            {"name": "default", "config": {"features.networks": "true"}},
            {"name": "pp-ubuntu", "config": {"features.networks": "false"}},
        ]
        self.leases = {
            "default": [{"address": "10.211.0.1", "hwaddr": "", "type": "gateway"}],
            "pp-ubuntu": [
                {
                    "address": "10.211.0.42",
                    "hwaddr": "10:66:6a:aa:bb:cc",
                    "hostname": "untrusted",
                    "location": "none",
                    "type": "dynamic",
                }
            ],
        }
        self.foreign = []
        self.query_calls = []
        self.before_query = lambda uri, kwargs: None
        self.fail_override = False
        self.drift = False
        self.before_override = lambda: None

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[1] == "query":
            assert "--project" not in argv
            uri = argv[2]
            self.query_calls.append((uri, kwargs))
            self.before_query(uri, kwargs)
            if uri.startswith("/1.0/profiles/"):
                value = PROFILE
            elif uri == "/1.0/networks/ppub0?project=default":
                value = self.network
            elif uri == "/1.0/projects?recursion=1":
                value = self.projects
            elif urlsplit(uri).path == "/1.0/networks/ppub0/leases":
                params = parse_qs(urlsplit(uri).query, strict_parsing=True)
                assert set(params) == {"project"}
                assert len(params["project"]) == 1
                value = self.leases[params["project"][0]]
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
    daemon.leases["pp-ubuntu"] = []
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
        daemon.leases["pp-ubuntu"] = []
    elif fault == "foreign-mac":
        daemon.leases["pp-ubuntu"][0]["hwaddr"] = "10:66:6a:aa:bb:dd"
    elif fault == "duplicate-lease":
        daemon.leases["pp-ubuntu"] *= 2
    elif fault in {"gateway", "network-address", "broadcast", "outside"}:
        daemon.leases["pp-ubuntu"][0]["address"] = {
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
        daemon.projects.append(
            {"name": "another-project", "config": {"features.networks": "false"}}
        )
        daemon.leases["another-project"] = []
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
        daemon.leases["pp-ubuntu"].append(
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


def add_project(daemon, name, isolated="false", leases=None):
    daemon.projects.append({"name": name, "config": {"features.networks": isolated}})
    daemon.leases[name] = [] if leases is None else leases


def queried_scopes(daemon):
    return [
        parse_qs(urlsplit(uri).query)["project"][0]
        for uri, _ in daemon.query_calls
        if urlsplit(uri).path == "/1.0/networks/ppub0/leases"
    ]


def assert_rejected_before_intent(node, daemon, spec, monkeypatch, match=None):
    def no_write(*_):
        pytest.fail("Rejected snapshot must not write even pending address intent")

    monkeypatch.setattr(node.store, "save_address", no_write)
    with pytest.raises(Failure, match=match):
        node.allocation.pin(spec["instance_id"])
    assert node.store.address_binding(spec["instance_id"]) is None
    assert not any("override" in call for call in daemon.calls)


def test_default_gateway_only_and_owned_dynamic_scope_pin_success(
    allocation_node, spec
):
    node, daemon = allocation_node
    pin = node.allocation.pin(spec["instance_id"])
    assert pin["address"] == daemon.leases["pp-ubuntu"][0]["address"]
    assert queried_scopes(daemon) == ["default", "pp-ubuntu"] * 2
    assert [uri for uri, _ in daemon.query_calls].count(
        "/1.0/networks/ppub0?project=default"
    ) == 2


@pytest.mark.parametrize("conflict", ["ip", "mac", "identical-static", "uppercase-mac"])
def test_shared_foreign_scope_collision_never_deduplicated(
    allocation_node, spec, monkeypatch, conflict
):
    node, daemon = allocation_node
    foreign = dict(daemon.leases["pp-ubuntu"][0])
    if conflict == "ip":
        foreign["hwaddr"] = "10:66:6a:aa:bb:dd"
    elif conflict == "mac":
        foreign["address"] = "10.211.0.43"
    elif conflict == "uppercase-mac":
        foreign["hwaddr"] = foreign["hwaddr"].upper()
    else:
        foreign["type"] = "static"
    add_project(daemon, "shared-third", leases=[foreign])
    assert_rejected_before_intent(
        node, daemon, spec, monkeypatch, "address_lease_ambiguous"
    )
    assert queried_scopes(daemon) == ["default", "pp-ubuntu", "shared-third"]


def test_missing_owned_dynamic_cannot_borrow_foreign_same_mac(
    allocation_node, spec, monkeypatch
):
    node, daemon = allocation_node
    add_project(daemon, "shared-third", leases=daemon.leases["pp-ubuntu"])
    daemon.leases["pp-ubuntu"] = []
    assert_rejected_before_intent(
        node, daemon, spec, monkeypatch, "address_lease_ambiguous"
    )
    assert queried_scopes(daemon) == ["default", "pp-ubuntu", "shared-third"]


def test_identical_static_records_across_scopes_remain_ambiguous(allocation_node, spec):
    node, daemon = allocation_node
    pin = node.allocation.pin(spec["instance_id"])
    daemon.leases["pp-ubuntu"][0]["type"] = "static"
    add_project(
        daemon, "shared-third", leases=copy.deepcopy(daemon.leases["pp-ubuntu"])
    )
    with pytest.raises(Failure, match="address_lease_ambiguous"):
        node.allocation.validate(spec["instance_id"], pin)
    assert node.store.address_binding(spec["instance_id"]) == pin


@pytest.mark.parametrize(
    "fault",
    [
        "not-list",
        "entry-not-dict",
        "missing-default",
        "missing-owned",
        "duplicate-default",
        "duplicate-owned",
        "duplicate-third",
        "missing-name",
        "empty-name",
        "blank-name",
        "control-name",
        "nonstring-name",
        "missing-config",
        "config-not-dict",
        "missing-flag",
        "bool-flag",
        "unknown-flag",
        "owned-isolated",
        "unknown-default-flag",
        "unknown-isolated-flag",
        "inventory-excess",
        "scope-excess",
    ],
)
def test_inventory_ambiguity_rejects_before_any_intent(
    allocation_node, spec, monkeypatch, fault
):
    node, daemon = allocation_node
    if fault == "not-list":
        daemon.projects = {}
    elif fault == "entry-not-dict":
        daemon.projects.append("unknown")
    elif fault == "missing-default":
        daemon.projects.pop(0)
    elif fault == "missing-owned":
        daemon.projects.pop(1)
    elif fault == "duplicate-default":
        daemon.projects.append(copy.deepcopy(daemon.projects[0]))
    elif fault == "duplicate-owned":
        daemon.projects.append(copy.deepcopy(daemon.projects[1]))
    elif fault == "duplicate-third":
        add_project(daemon, "third")
        add_project(daemon, "third")
    elif fault == "missing-name":
        daemon.projects[1].pop("name")
    elif fault in {"empty-name", "blank-name", "control-name", "nonstring-name"}:
        daemon.projects[1]["name"] = {
            "empty-name": "",
            "blank-name": " ",
            "control-name": "bad\nproject",
            "nonstring-name": 42,
        }[fault]
    elif fault == "missing-config":
        daemon.projects[1].pop("config")
    elif fault == "config-not-dict":
        daemon.projects[1]["config"] = []
    elif fault == "missing-flag":
        daemon.projects[1]["config"] = {}
    elif fault == "bool-flag":
        daemon.projects[1]["config"]["features.networks"] = False
    elif fault == "unknown-flag":
        daemon.projects[1]["config"]["features.networks"] = "False"
    elif fault == "owned-isolated":
        daemon.projects[1]["config"]["features.networks"] = "true"
    elif fault == "unknown-default-flag":
        daemon.projects[0]["config"] = {}
    elif fault == "unknown-isolated-flag":
        add_project(daemon, "third", isolated="unknown")
    elif fault == "inventory-excess":
        for index in range(255):
            add_project(daemon, f"isolated-{index}", isolated="true")
    else:
        for index in range(15):
            add_project(daemon, f"shared-{index}")
    assert_rejected_before_intent(
        node, daemon, spec, monkeypatch, "address_lease_domain_unavailable"
    )
    assert not queried_scopes(daemon)


@pytest.mark.parametrize("limit", ["inventory", "scopes"])
def test_inventory_and_scope_limits_accept_complete_boundary(
    allocation_node, spec, limit
):
    node, daemon = allocation_node
    count, isolated = (254, "true") if limit == "inventory" else (14, "false")
    for index in range(count):
        add_project(daemon, f"third-{index:03}", isolated=isolated)
    node.allocation.pin(spec["instance_id"])
    expected = sorted(
        ["default", "pp-ubuntu"]
        + ([] if isolated == "true" else [f"third-{i:03}" for i in range(count)])
    )
    assert queried_scopes(daemon) == expected * 2


@pytest.mark.parametrize("scope", ["inventory", "default", "pp-ubuntu", "shared-third"])
@pytest.mark.parametrize("fault", ["denied", "timeout"])
def test_any_scope_or_inventory_query_failure_rejects_before_intent(
    allocation_node, spec, monkeypatch, scope, fault
):
    node, daemon = allocation_node
    add_project(daemon, "shared-third")

    def fail_selected(uri, kwargs):
        selected = (
            uri == "/1.0/projects?recursion=1"
            if scope == "inventory"
            else (
                urlsplit(uri).path == "/1.0/networks/ppub0/leases"
                and parse_qs(urlsplit(uri).query)["project"] == [scope]
            )
        )
        if selected:
            if fault == "timeout":
                raise subprocess.TimeoutExpired("incus", kwargs["timeout"])
            raise subprocess.CalledProcessError(
                1, "incus", stderr=b"private diagnostic"
            )

    daemon.before_query = fail_selected
    assert_rejected_before_intent(
        node, daemon, spec, monkeypatch, "incus_query_unavailable"
    )


@pytest.mark.parametrize(
    "fault",
    [
        "not-list",
        "entry-not-dict",
        "missing-address",
        "missing-mac",
        "missing-type",
        "bad-ip",
        "ipv6",
        "numeric-ip",
        "bad-mac",
        "empty-mac",
        "unknown-type",
        "gateway-address",
        "gateway-mac",
        "gateway-as-dynamic",
        "multicast-mac",
        "null-scope",
    ],
)
def test_malformed_foreign_lease_is_not_silently_skipped(
    allocation_node, spec, monkeypatch, fault
):
    node, daemon = allocation_node
    lease = {"address": "10.211.0.43", "hwaddr": "10:66:6a:aa:bb:dd", "type": "static"}
    entries = [lease]
    if fault == "not-list":
        entries = {}
    elif fault == "null-scope":
        entries = None
    elif fault == "entry-not-dict":
        entries = ["unrecognized"]
    elif fault.startswith("missing-"):
        lease.pop(
            {
                "missing-address": "address",
                "missing-mac": "hwaddr",
                "missing-type": "type",
            }[fault]
        )
    elif fault in {"bad-ip", "ipv6", "numeric-ip"}:
        lease["address"] = {"bad-ip": "not-ip", "ipv6": "::1", "numeric-ip": 42}[fault]
    elif fault == "bad-mac":
        lease["hwaddr"] = "wrong"
    elif fault == "empty-mac":
        lease["hwaddr"] = ""
    elif fault == "unknown-type":
        lease["type"] = "unknown"
    elif fault == "gateway-address":
        lease.update(type="gateway", hwaddr="")
    elif fault == "gateway-mac":
        lease.update(type="gateway", address="10.211.0.1")
    elif fault == "gateway-as-dynamic":
        lease["address"] = "10.211.0.1"
    else:
        lease["hwaddr"] = "11:66:6a:aa:bb:dd"
    add_project(daemon, "shared-third", leases=entries)
    if fault == "null-scope":
        daemon.leases["shared-third"] = None
    assert_rejected_before_intent(
        node, daemon, spec, monkeypatch, "address_lease_domain_unavailable"
    )


@pytest.mark.parametrize("slow", ["inventory", "union", "last-scope"])
def test_lease_domain_has_one_shared_two_second_deadline(
    allocation_node, spec, monkeypatch, slow
):
    import container_manager.allocation as module

    node, daemon = allocation_node
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    budgets = []

    def consume_time(uri, kwargs):
        inventory = uri == "/1.0/projects?recursion=1"
        leases = urlsplit(uri).path == "/1.0/networks/ppub0/leases"
        if inventory or leases:
            budgets.append(kwargs["timeout"])
            if slow == "inventory":
                clock[0] += 2.01 if inventory else 0
            elif slow == "union":
                clock[0] += 0.7
            elif leases and parse_qs(urlsplit(uri).query)["project"] == ["pp-ubuntu"]:
                clock[0] += 2.0

    daemon.before_query = consume_time
    assert_rejected_before_intent(
        node, daemon, spec, monkeypatch, "address_lease_domain_timeout"
    )
    assert budgets[0] == pytest.approx(2.0)
    assert all(0 < budget <= 2.0 for budget in budgets)
    if slow == "union":
        assert budgets == pytest.approx([2.0, 1.3, 0.6])


def test_project_query_delimiters_are_encoded_deterministically(allocation_node, spec):
    node, daemon = allocation_node
    project = "third&project=foreign?extra/#unicode-é"
    add_project(daemon, project)
    node.allocation.pin(spec["instance_id"])
    assert queried_scopes(daemon) == sorted(["default", "pp-ubuntu", project]) * 2
    encoded = [uri for uri, _ in daemon.query_calls if "third" in uri]
    assert encoded and all(
        "third%26project%3Dforeign%3Fextra%2F%23unicode-%C3%A9" in uri
        for uri in encoded
    )


def test_stopped_static_pin_inspects_every_scope_without_dynamic_lease(
    allocation_node, spec
):
    node, daemon = allocation_node
    pin = node.allocation.pin(spec["instance_id"])
    daemon.leases["pp-ubuntu"] = []
    daemon.instance["status"] = "Stopped"
    add_project(daemon, "shared-third")
    daemon.query_calls.clear()
    assert node.allocation.validate(spec["instance_id"], pin)[1] == "stopped"
    assert queried_scopes(daemon) == ["default", "pp-ubuntu", "shared-third"]

    def deny(uri, kwargs):
        if "project=shared-third" in uri:
            raise subprocess.CalledProcessError(1, "incus")

    daemon.before_query = deny
    with pytest.raises(Failure):
        node.allocation.validate(spec["instance_id"], pin)
    assert node.store.address_binding(spec["instance_id"]) == pin


@pytest.mark.parametrize("isolated", ["true", "false", "unknown-project"])
def test_same_named_network_claim_scope_requires_explicit_inventory(
    allocation_node, spec, monkeypatch, isolated
):
    node, daemon = allocation_node
    foreign = copy.deepcopy(daemon.instance)
    foreign.update(name="foreign", project="third")
    foreign["expanded_devices"]["eth0"]["ipv4.address"] = "10.211.0.42"
    daemon.foreign.append(foreign)
    if isolated != "unknown-project":
        add_project(daemon, "third", isolated=isolated)
    if isolated == "true":
        node.allocation.pin(spec["instance_id"])
        assert "third" not in queried_scopes(daemon)
    else:
        assert_rejected_before_intent(
            node, daemon, spec, monkeypatch, "address_claim_ambiguous"
        )


def test_isolated_project_direct_host_bridge_parent_is_still_a_claim(
    allocation_node, spec, monkeypatch
):
    node, daemon = allocation_node
    add_project(daemon, "isolated", isolated="true")
    foreign = copy.deepcopy(daemon.instance)
    foreign.update(name="foreign", project="isolated")
    foreign["expanded_devices"]["eth0"] = {
        "type": "nic",
        "nictype": "bridged",
        "parent": "ppub0",
        "ipv4.address": "10.211.0.42",
    }
    daemon.foreign.append(foreign)
    assert_rejected_before_intent(
        node, daemon, spec, monkeypatch, "address_claim_ambiguous"
    )
    assert "isolated" not in queried_scopes(daemon)
