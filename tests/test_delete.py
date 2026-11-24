from unittest.mock import Mock
from uuid import uuid4

import pytest

from container_manager.errors import Failure
from container_manager.incus import Incus, POOL, owned_name
from container_manager.models import Create


def test_delete_orders_cleanup_and_replays(controller, body):
    guest = controller.create(Create(**body), "admin")
    events = []
    controller.relay.remove = lambda spec: events.append("relay")
    controller.node.remove = lambda spec: events.append("node")
    controller.node.delete = lambda resource: events.append("delete")
    key = str(uuid4())
    expected = {"deleted": True, "id": guest["id"]}
    assert controller.delete(guest["id"], "admin", key) == expected
    assert events == ["relay", "node", "delete"]
    assert controller.store.instances() == []
    assert controller.delete(guest["id"], "admin", key) == expected
    assert len(events) == 3


@pytest.mark.parametrize("stage", ["relay", "node", "delete"])
def test_delete_failure_keeps_allocations(controller, body, stage):
    guest = controller.create(Create(**body), "admin")
    controller.node.delete = Mock()
    backend = controller.relay if stage == "relay" else controller.node
    setattr(
        backend,
        "delete" if stage == "delete" else "remove",
        Mock(side_effect=Failure("unconfirmed")),
    )
    with pytest.raises(Failure):
        controller.delete(guest["id"], "admin")
    retained = controller.store.instance(guest["id"])
    assert retained["ports"] == guest["ports"]
    assert retained["status"] == "error"


def test_incus_delete_confirms_absence_and_retains_tombstone(config, tmp_path):
    from container_manager.store import Store

    store = Store(str(tmp_path / "node.sqlite"))
    node = Incus(config, store, Mock())
    resource = str(uuid4())
    name = owned_name(resource)
    store.own(resource, {"id": resource}, "ready")
    guest = {
        "name": name,
        "type": "container",
        "expanded_devices": {
            "root": {"type": "disk", "pool": POOL, "path": "/"},
            "home": {
                "type": "disk",
                "pool": POOL,
                "source": name + "-home",
                "path": "/home",
            },
        },
        "expanded_config": {
            "security.privileged": "false",
            "security.nesting": "false",
            "security.idmap.isolated": "true",
        },
    }
    home = {"name": name + "-home", "type": "custom", "content_type": "filesystem"}
    node.query = Mock(side_effect=[[guest], [home], [], []])
    node.command = Mock()
    node.delete(resource)
    assert node.command.call_args_list[0].args[0] == ["delete", name, "--force"]
    assert store.ownership()[0]["state"] == "deleted"
    node.delete(resource)
    assert node.command.call_count == 2


def test_incus_delete_rejects_unowned(config, tmp_path):
    from container_manager.store import Store

    node = Incus(config, Store(str(tmp_path / "node.sqlite")), Mock())
    node.command = Mock()
    with pytest.raises(Failure):
        node.delete(str(uuid4()))
    node.command.assert_not_called()


@pytest.mark.parametrize("state", ["creating", "error"])
def test_incus_delete_rejects_uncertain_ownership(config, tmp_path, state):
    from container_manager.store import Store

    store = Store(str(tmp_path / "node.sqlite"))
    resource = str(uuid4())
    store.own(resource, {"id": resource}, state)
    node = Incus(config, store, Mock())
    node.command = Mock()
    with pytest.raises(Failure):
        node.delete(resource)
    node.command.assert_not_called()


def test_incus_partial_delete_retries_home_without_freeing_pin(config, tmp_path):
    from container_manager.store import Store

    store = Store(str(tmp_path / "node.sqlite"))
    resource = str(uuid4())
    store.own(resource, {"id": resource}, "deleting")
    node = Incus(config, store, Mock())
    home = {
        "name": owned_name(resource) + "-home",
        "type": "custom",
        "content_type": "filesystem",
    }
    node.query = Mock(side_effect=[[], [home], [], [home]])
    node.command = Mock()
    with pytest.raises(Failure, match="deletion_requires_reconciliation"):
        node.delete(resource)
    assert store.ownership()[0]["state"] == "deleting"
    node.query = Mock(side_effect=[[], [home], [], []])
    node.delete(resource)
    assert store.ownership()[0]["state"] == "deleted"


@pytest.mark.parametrize("inventory_index", range(4))
@pytest.mark.parametrize(
    "malformed",
    [
        {},
        "",
        None,
        [None],
        [""],
        [{}],
        [{"name": "", "type": "container"}],
        [{"name": 123, "type": "custom", "content_type": "filesystem"}],
        [{"name": "unrelated"}],
        [{"name": "unrelated", "type": "custom"}],
        [{"name": "unrelated", "type": "custom", "content_type": ""}],
        [{"name": "unrelated", "type": "unknown", "content_type": "unknown"}],
    ],
)
def test_delete_malformed_inventory_retains_pin_and_controller_reservations(
    controller, body, config, tmp_path, inventory_index, malformed
):
    from container_manager.store import Store

    guest = controller.create(Create(**body), "admin")
    resource = guest["id"]
    name = owned_name(resource)
    store = Store(str(tmp_path / "native-delete.sqlite"))
    store.own(resource, {"id": resource}, "ready")
    with store.transaction() as db:
        db.execute(
            "INSERT INTO address_bindings_v1 VALUES (?,?,?,?,?,?,?)",
            (resource, "eth0", "ppub0", "00:16:3e:00:00:01", "10.211.0.2", 1, "ready"),
        )
    instance = {
        "name": name,
        "type": "container",
        "expanded_devices": {
            "root": {"type": "disk", "pool": POOL, "path": "/"},
            "home": {
                "type": "disk",
                "pool": POOL,
                "source": name + "-home",
                "path": "/home",
            },
        },
        "expanded_config": {
            "security.privileged": "false",
            "security.nesting": "false",
            "security.idmap.isolated": "true",
        },
    }
    home = {"name": name + "-home", "type": "custom", "content_type": "filesystem"}
    responses = [[instance], [home], [], []]
    responses[inventory_index] = malformed
    # Reproduce the original false-absence sequence exactly for final dictionaries.
    if inventory_index == 2 and malformed == {}:
        responses[3] = {}
    node = Incus(config, store, Mock())
    node.query = Mock(side_effect=responses)
    node.command = Mock()
    controller.node.delete = node.delete
    with pytest.raises(Failure, match="invalid_agent_state"):
        controller.delete(resource, "admin")
    retained = controller.store.instance(resource)
    assert retained["ports"] == guest["ports"]
    assert retained["error"] == "deletion_requires_reconciliation"
    assert store.ownership()[0]["state"] == (
        "ready" if inventory_index < 2 else "deleting"
    )
    with store.transaction() as db:
        assert (
            db.execute(
                "SELECT address FROM address_bindings_v1 WHERE instance_id=?",
                (resource,),
            ).fetchone()["address"]
            == "10.211.0.2"
        )
    assert node.command.call_count == (0 if inventory_index < 2 else 2)
