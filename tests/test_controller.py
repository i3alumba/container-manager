from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import pytest

from container_manager.controller import Controller
from container_manager.errors import Failure
from container_manager.models import Check, Create, Port
from container_manager.store import Store


def test_missing_upstream_ingress_blocks_checks_and_creation_before_host_mutations(
    config, body
):
    from conftest import FakeAgent

    instance = Controller(
        replace(config, public_port_ranges={"tcp": [], "udp": []}),
        Store(config.database),
        FakeAgent(),
        FakeAgent(),
    )
    result = instance.check(Check(protocol="tcp", public_port=8000))
    assert result["available"] is False
    assert result["reason"] == "external_ingress_not_configured"
    assert result["checks"]["alpha"]["status"] == "unknown"
    with pytest.raises(Failure, match="external_ingress_not_configured"):
        instance.create(Create(**body), "admin")
    assert instance.store.instances() == []
    assert instance.node.calls == [] and instance.relay.calls == []


def test_only_operator_certified_ingress_ranges_can_be_published(config, body):
    from conftest import FakeAgent

    instance = Controller(
        replace(config, public_port_ranges={"tcp": [[20000, 29999]], "udp": []}),
        Store(config.database),
        FakeAgent(),
        FakeAgent(),
    )
    body["ports"] = [{"protocol": "tcp", "public_port": 25565, "target_port": 8000}]
    guest = instance.create(Create(**body), "admin")
    assert guest["ports"][0]["public_port"] == 25565
    with pytest.raises(Failure, match="external_ingress_not_configured"):
        instance.add_port(
            guest["id"],
            Port(protocol="tcp", public_port=8000, target_port=8000),
            "admin",
        )
    assert instance.store.instance(guest["id"]) == guest


def test_explicit_upstream_single_port_exceptions_allow_user_examples(config, body):
    from conftest import FakeAgent

    instance = Controller(
        replace(
            config, public_port_ranges={"tcp": [[2223, 2223], [8000, 8000]], "udp": []}
        ),
        Store(config.database),
        FakeAgent(),
        FakeAgent(),
    )
    guest = instance.create(Create(**body), "admin")
    updated = instance.add_port(
        guest["id"], Port(protocol="tcp", public_port=8000, target_port=8000), "admin"
    )
    assert len(updated["ports"]) == 2
    # Routing TCP at the upstream gateway says nothing about UDP ownership.
    with pytest.raises(Failure, match="external_ingress_not_configured"):
        instance.add_port(
            guest["id"],
            Port(protocol="udp", public_port=8000, target_port=8000),
            "admin",
        )
    assert instance.store.instance(guest["id"]) == updated


def test_concurrent_create_one_wins(controller, body):
    def create(i):
        try:
            return controller.create(Create(**{**body, "name": f"guest-{i}"}), "admin")
        except Failure as error:
            return error.status

    with ThreadPoolExecutor(2) as workers:
        result = list(workers.map(create, range(2)))
    assert sum(isinstance(r, dict) for r in result) == 1
    assert 409 in result
    assert len(controller.store.instances()) == 1


@pytest.mark.parametrize("stage", ["reserve", "publish", "activate"])
def test_failed_edit_keeps_existing_guest_mappings(controller, body, stage):
    original = controller.create(Create(**body), "admin")
    backend = controller.node if stage == "publish" else controller.relay
    backend.fail = stage
    with pytest.raises(Failure):
        controller.add_port(
            original["id"],
            Port(protocol="udp", public_port=2224, target_port=53),
            "admin",
        )
    final = controller.store.instance(original["id"])
    assert final == original
    assert len(controller.node.ports) == 1
    assert len(controller.relay.ports) == 1
    assert not any(c[0] in {"create", "power"} for c in controller.node.calls[2:])


def test_failed_compensation_retains_unique_reservation(controller, body):
    instance = controller.create(Create(**body), "admin")
    controller.node.fail = "publish"
    controller.relay.fail = "remove"
    with pytest.raises(Failure):
        controller.add_port(
            instance["id"],
            Port(protocol="udp", public_port=2224, target_port=53),
            "admin",
        )
    ports = controller.store.instance(instance["id"])["ports"]
    assert next(p for p in ports if p["public_port"] == 2224)["status"] == "error"
    with pytest.raises(Failure, match="port_reserved"):
        controller.add_port(
            instance["id"],
            Port(protocol="udp", public_port=2224, target_port=53),
            "admin",
        )


def test_advisory_check_not_reservation(controller, body):
    assert controller.check(Check(protocol="tcp", public_port=2223))["available"]
    controller.node.available = False
    with pytest.raises(Failure, match="host_port_conflict"):
        controller.create(Create(**body), "admin")
    assert not any(c[0] == "create" for c in controller.node.calls)


@pytest.mark.parametrize(
    "port",
    [
        1023,
        2222,
        2379,
        2380,
        5000,
        5187,
        6443,
        8472,
        9443,
        9444,
        9445,
        10250,
        10257,
        10259,
        30000,
        31000,
        32767,
    ],
)
def test_reserved_ports(controller, body, port):
    body["ports"][0]["public_port"] = port
    with pytest.raises(Exception):
        controller.create(Create(**body), "admin")
    assert not controller.store.instances()


def test_pool_budget_counts_stopped_and_error(controller, body):
    body["cpu"], body["memory_gb"] = 4, 16
    instance = controller.create(Create(**body), "admin")
    controller.power(instance["id"], False, "admin")
    body["name"], body["ports"] = "another", []
    with pytest.raises(Failure, match="aggregate_budget"):
        controller.create(Create(**body), "admin")


def test_sqlite_persistence_restart_retains_ports(controller, body):
    instance = controller.create(Create(**body), "admin")
    resource = instance["id"]
    key = str(uuid4())
    controller.store.begin_operation(key, "add_port", resource, "admin")
    restarted = Controller(
        controller.config,
        Store(controller.store.path),
        controller.node,
        controller.relay,
    )
    result = restarted.store.instance(resource)
    assert result["status"] == "error"
    assert result["ports"] == instance["ports"]
    assert result["error"] == "interrupted_operation"
    with pytest.raises(Failure, match="requires_reconciliation"):
        restarted.store.begin_operation(key, "add_port", resource, "admin")


def test_order_reserve_publish_activate_and_idempotency(controller, body):
    sequence = []
    for host, method in (
        (controller.relay, "reserve"),
        (controller.node, "publish"),
        (controller.relay, "activate"),
    ):
        original = getattr(host, method)

        def record(spec, original=original, method=method):
            sequence.append(method)
            return original(spec)

        setattr(host, method, record)
    key = str(uuid4())
    instance = controller.create(Create(**body), "admin", key)
    assert sequence == ["reserve", "publish", "activate"]
    assert controller.create(Create(**body), "admin", key)["id"] == instance["id"]
    assert sequence == ["reserve", "publish", "activate"]
    with pytest.raises(Failure, match="idempotency_conflict"):
        controller.create(Create(**body), "other-admin", key)


def test_remove_only_owned_port(controller, body):
    instance = controller.create(Create(**body), "admin")
    with pytest.raises(Failure, match="port_not_found"):
        controller.remove_port(instance["id"], str(uuid4()), "admin")
    final = controller.remove_port(instance["id"], instance["ports"][0]["id"], "admin")
    assert final["ports"] == []
    assert final["status"] == "running"


def test_reconcile_failed_daemon_keeps_reservation(controller, body):
    instance = controller.create(Create(**body), "admin")
    controller.relay.fail = "port_status"
    controller.reconcile()
    port = controller.store.instance(instance["id"])["ports"][0]
    assert port["status"] == "error"
    assert not controller.check(Check(protocol="tcp", public_port=2223))["available"]


def test_failed_power_is_not_reported_successfully_stopped(controller, body):
    instance = controller.create(Create(**body), "admin")
    controller.node.fail = "power"
    with pytest.raises(Failure):
        controller.power(instance["id"], False, "admin")
    final = controller.store.instance(instance["id"])
    assert final["status"] == "error"
    assert final["ports"] == instance["ports"]


def test_check_reserved_policy_has_checks(controller):
    result = controller.check(Check(protocol="udp", public_port=31000))
    assert result["available"] is False
    assert result["checks"]["registry"]["status"] == "conflict"
    assert set(result["checks"]) == {"alpha", "gamma", "registry"}


def test_atomic_unique_across_independent_sqlite_connections(controller):
    resource = str(uuid4())
    port = Port(protocol="tcp", public_port=2223, target_port=22)

    def reserve(_):
        try:
            with Store(controller.store.path).transaction() as db:
                controller.reserve_row(db, resource, port)
            return "won"
        except Failure:
            return "lost"

    with ThreadPoolExecutor(8) as workers:
        results = list(workers.map(reserve, range(8)))
    assert results.count("won") == 1
    assert results.count("lost") == 7


def test_async_prepare_is_durable_secret_transient_and_idempotent(controller, body):
    key = str(uuid4())
    instance, work = controller.prepare_create(Create(**body), "admin", key)
    assert instance["status"] == "creating"
    assert controller.node.calls == [] and controller.relay.calls == []
    assert instance["ports"][0]["status"] == "reserved"
    assert (
        body["root_password"].encode() not in open(controller.store.path, "rb").read()
    )
    again, duplicate = controller.prepare_create(Create(**body), "admin", key)
    assert again == instance and duplicate is None
    with pytest.raises(Failure, match="instance_creating"):
        controller.power(instance["id"], True, "admin")
    with pytest.raises(Failure, match="instance_creating"):
        controller.remove_port(instance["id"], instance["ports"][0]["id"], "admin")
    controller.complete_create(work)
    assert controller.store.instance(instance["id"])["status"] == "running"


def test_async_create_failure_persists_error_not_password(controller, body):
    instance, work = controller.prepare_create(Create(**body), "admin")
    controller.node.fail = "create"
    controller.run_create(work)
    final = controller.store.instance(instance["id"])
    assert final["status"] == "error" and final["error"] == "create_failed"
    assert (
        body["root_password"].encode() not in open(controller.store.path, "rb").read()
    )


def test_restart_after_async_prepare_never_replays_password(controller, body):
    instance, _ = controller.prepare_create(Create(**body), "admin")
    recovered = Controller(
        controller.config,
        Store(controller.store.path),
        controller.node,
        controller.relay,
    )
    assert recovered.store.instance(instance["id"])["status"] == "error"
    assert controller.node.calls == []
    assert recovered.store.instance(instance["id"])["ports"][0]["status"] == "reserved"


@pytest.mark.parametrize("port", [3306, 5432, 8000, 8080, 8443, 9100, 51820])
def test_common_service_ports_allowed_after_real_checks(controller, body, port):
    body["ports"][0]["public_port"] = port
    assert controller.check(Check(protocol="tcp", public_port=port))["available"]
    instance = controller.create(Create(**body), "admin")
    assert instance["ports"][0]["status"] == "active"
    assert any(
        call[0] == "inspect" and call[1]["public_port"] == port
        for call in controller.node.calls
    )
    assert any(
        call[0] == "inspect" and call[1]["public_port"] == port
        for call in controller.relay.calls
    )


@pytest.mark.parametrize("port", [5432, 8000])
def test_common_service_ports_still_reject_real_host_conflicts(controller, body, port):
    body["ports"][0]["public_port"] = port
    controller.relay.available = False
    assert not controller.check(Check(protocol="tcp", public_port=port))["available"]
    with pytest.raises(Failure, match="host_port_conflict"):
        controller.create(Create(**body), "admin")


@pytest.mark.parametrize("port", [5432, 8000])
def test_operator_configured_service_reservations_still_apply(controller, body, port):
    from dataclasses import replace

    controller.config = replace(controller.config, reserved_ports=[port])
    body["ports"][0]["public_port"] = port
    assert not controller.check(Check(protocol="tcp", public_port=port))["available"]
    with pytest.raises(Failure, match="reserved_port"):
        controller.create(Create(**body), "admin")


def test_fixed_reservations_are_only_the_operator_infrastructure_set():
    from container_manager.models import RESERVED

    # Includes stable k3s/containerd and existing Jenkins ports discovered in
    # fresh alpha/gamma inspection, protected even during maintenance outages.
    assert RESERVED == {
        2222,
        2379,
        2380,
        5000,
        5187,
        6443,
        6444,
        8090,
        8472,
        9443,
        9444,
        9445,
        10010,
        10248,
        10249,
        10250,
        10256,
        10257,
        10258,
        10259,
    }
