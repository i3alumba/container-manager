from unittest.mock import Mock

import pytest

from container_manager.errors import Failure
from container_manager.models import Create


@pytest.mark.parametrize("actual", ["running", "stopped"])
def test_reconcile_recovers_node_outage_after_controller_restart(
    controller, body, actual
):
    guest = controller.create(Create(**body), "admin")
    controller.node.fail = "instance_status"
    controller.reconcile()
    failed = controller.store.instance(guest["id"])
    assert failed["error"] == "node_requires_reconciliation"
    controller.node.fail = None
    controller.node.states[guest["id"]] = actual
    restarted = type(controller)(
        controller.config, controller.store, controller.node, controller.relay
    )
    restarted.reconcile()
    recovered = controller.store.instance(guest["id"])
    assert recovered["status"] == actual
    assert recovered["error"] is None
    assert recovered["ports"] == guest["ports"]


@pytest.mark.parametrize("peer,state", [("node", "missing"), ("relay", "missing")])
def test_recovery_requires_every_mapping_confirmed(controller, body, peer, state):
    guest = controller.create(Create(**body), "admin")
    controller.store.status(guest["id"], "error", "node_requires_reconciliation")
    getattr(controller, peer).port_status = Mock(return_value=state)
    controller.reconcile()
    retained = controller.store.instance(guest["id"])
    assert retained["status"] == "error"
    assert retained["ports"] == guest["ports"]


@pytest.mark.parametrize("actual", ["missing", "error", None])
def test_recovery_rejects_uncertain_node_state(controller, body, actual):
    guest = controller.create(Create(**body), "admin")
    controller.store.status(guest["id"], "error", "node_requires_reconciliation")
    controller.node.instance_status = Mock(return_value=actual)
    controller.reconcile()
    assert controller.store.instance(guest["id"])["status"] == "error"


@pytest.mark.parametrize("state", ["pending", "error"])
def test_recovery_does_not_bypass_unfinished_operation(controller, body, state):
    guest = controller.create(Create(**body), "admin")
    controller.store.status(guest["id"], "error", "node_requires_reconciliation")
    with controller.store.transaction() as db:
        db.execute(
            "INSERT INTO operations VALUES (?,?,?,?,?)",
            ("unfinished", "delete", guest["id"], state, "admin"),
        )
    controller.node.instance_status = Mock()
    controller.reconcile()
    controller.node.instance_status.assert_not_called()
    assert controller.store.instance(guest["id"])["status"] == "error"


def test_recovery_rechecks_snapshot_before_commit(controller, body):
    guest = controller.create(Create(**body), "admin")
    controller.store.status(guest["id"], "error", "node_requires_reconciliation")

    def during_probe(resource):
        controller.store.status(resource, "error", "deletion_requires_reconciliation")
        return "running"

    controller.node.instance_status = during_probe
    controller.reconcile()
    assert (
        controller.store.instance(guest["id"])["error"]
        == "deletion_requires_reconciliation"
    )


@pytest.mark.parametrize("stage", ["relay", "node", "delete"])
def test_reconcile_never_resurrects_failed_deletion(controller, body, stage):
    guest = controller.create(Create(**body), "admin")
    controller.node.delete = Mock()
    peer = controller.relay if stage == "relay" else controller.node
    method = "delete" if stage == "delete" else "remove"
    setattr(peer, method, Mock(side_effect=Failure("unconfirmed")))
    with pytest.raises(Failure):
        controller.delete(guest["id"], "admin")
    controller.node.instance_status = Mock(return_value="running")
    controller.reconcile()
    controller.node.instance_status.assert_not_called()
    retained = controller.store.instance(guest["id"])
    assert retained["error"] == "deletion_requires_reconciliation"
    assert retained["ports"] == guest["ports"]


def test_reconcile_keeps_deleted_guest_absent_and_updates_normal_inventory(
    controller, body
):
    removed = controller.create(Create(**body), "admin")
    controller.node.delete = Mock()
    controller.delete(removed["id"], "admin")
    guest = controller.create(Create(**{**body, "name": "survivor"}), "admin")
    controller.node.instance_status = Mock(return_value="stopped")
    controller.reconcile()
    controller.node.instance_status.assert_called_once_with(guest["id"])
    assert [i["id"] for i in controller.store.instances()] == [guest["id"]]
    assert controller.store.instance(guest["id"])["status"] == "stopped"


@pytest.mark.parametrize("peer", ["node", "relay"])
def test_recovery_leaves_reservations_on_agent_outage(controller, body, peer):
    guest = controller.create(Create(**body), "admin")
    controller.store.status(guest["id"], "error", "node_requires_reconciliation")
    getattr(controller, peer).port_status = Mock(side_effect=Failure("offline"))
    controller.reconcile()
    assert controller.store.instance(guest["id"])["ports"] == guest["ports"]
    assert controller.store.instance(guest["id"])["status"] == "error"


def test_recovery_restores_confirmed_error_mapping(controller, body):
    guest = controller.create(Create(**body), "admin")
    controller.store.status(guest["id"], "error", "node_requires_reconciliation")
    with controller.store.transaction() as db:
        db.execute(
            "UPDATE ports SET status='error' WHERE instance_id=?", (guest["id"],)
        )
    controller.reconcile()
    assert controller.store.instance(guest["id"])["ports"] == guest["ports"]
    assert controller.store.instance(guest["id"])["status"] == "running"


def test_recovery_refuses_pending_resource_change(controller, body):
    guest = controller.create(Create(**body), "admin")
    controller.store.status(guest["id"], "error", "node_requires_reconciliation")
    with controller.store.transaction() as db:
        db.execute(
            "INSERT INTO resource_changes_v1 VALUES (?,?,?,?,?)",
            (guest["id"], 1, 1, "[]", "pending"),
        )
    controller.node.instance_status = Mock()
    controller.reconcile()
    controller.node.instance_status.assert_not_called()
    assert controller.store.instance(guest["id"])["status"] == "error"
