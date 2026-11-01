"""Real HTTP startup stays available while private agents stall status RPCs."""

import socket
import threading
import time

import httpx
import uvicorn

from container_manager.api import app_for
from container_manager.auth import Auth
from container_manager.controller import Controller
from container_manager.errors import Failure
from container_manager.models import Check, Create, Port
from container_manager.store import Store


def test_stalled_agents_cannot_block_listener_or_spawn_overlapping_reconciliation(
    controller, body
):
    guest = controller.create(Create(**body), "admin")
    for port in [2224, 2225, 2226, 2227]:
        guest = controller.add_port(
            guest["id"], Port(protocol="tcp", public_port=port, target_port=22), "admin"
        )
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    status_calls = []

    def stalled_status(resource):
        status_calls.append(resource)
        entered.set()
        release.wait(10)
        raise Failure("private_agent_unavailable")

    controller.node.instance_status = stalled_status
    controller.relay.fail = "port_status"
    started = time.monotonic()
    recovered = Controller(
        controller.config,
        Store(controller.store.path),
        controller.node,
        controller.relay,
    )
    assert time.monotonic() - started < 1
    assert not entered.is_set()  # Constructor does local durable recovery only.
    original_reconcile = recovered.reconcile

    def reconcile():
        try:
            original_reconcile()
        finally:
            finished.set()

    recovered.reconcile = reconcile
    auth = Auth(
        httpx.MockTransport(
            lambda request: httpx.Response(
                200, json={"id": 1, "is_active": True, "is_staff": True}
            )
        )
    )
    app = app_for(recovered, auth)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    port = listener.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="critical", access_log=False))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [listener]}, daemon=True
    )
    thread.start()
    try:
        assert entered.wait(2)
        # Agent remains stalled; neither ASGI lifespan nor real TCP HTTP waits for it.
        with httpx.Client(
            base_url=f"http://127.0.0.1:{port}",
            timeout=2,
            trust_env=False,
            headers={"Authorization": "Bearer fixture"},
        ) as client:
            response = client.get("/api/containers/capabilities")
            assert response.status_code == 200
            response = client.get("/api/containers/")
            assert response.status_code == 200
            assert len(response.json()["instances"][0]["ports"]) == 5
            assert client.get("/api/containers/capabilities").status_code == 200
        assert not recovered.schedule_reconcile()
        assert len(status_calls) == 1
        release.set()
        assert finished.wait(3)
        after = recovered.store.instance(guest["id"])
        assert after["status"] == "error"
        assert len(after["ports"]) == 5
        assert all(p["status"] == "error" for p in after["ports"])
        for p in after["ports"]:
            assert not recovered.check(
                Check(protocol=p["protocol"], public_port=p["public_port"])
            )["available"]
    finally:
        release.set()
        server.should_exit = True
        thread.join(3)
        listener.close()
    assert not thread.is_alive()
