"""Real loopback sockets with an injected authoritative allocation (no Incus)."""

import json
import socket
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from container_manager.errors import Failure
from container_manager.incus import Incus
from container_manager.relay import copy_tcp
from container_manager.store import Store
from conftest import FreeInspector
from test_relay import available_port


class FakeAllocation:
    def __init__(self, store, pin):
        self.pin_value = pin
        self.status = "running"
        self.valid = True
        self.calls = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.store = store

    def pin(self, resource):
        self.validate(resource, self.pin_value)
        return self.pin_value

    def validate(self, resource, pin):
        self.calls += 1
        self.entered.set()
        assert self.release.wait(5)
        if not self.valid:
            raise Failure("address_binding_mismatch", 409)
        assert resource == pin["instance_id"]
        return pin, self.status


@pytest.fixture
def native_node(config, spec):
    store = Store(config.database)
    store.own(spec["instance_id"], {"id": spec["instance_id"]}, "ready")
    pin = {
        "instance_id": spec["instance_id"],
        "network": "ppub0",
        "nic": "eth0",
        "address": "127.0.0.1",
        "mac": "10:66:6a:aa:bb:cc",
        "version": 1,
    }
    store.save_address(pin, "ready")
    node = Incus(config, store, FreeInspector())
    node.allocation = FakeAllocation(store, pin)
    node.command = lambda args: setattr(
        node.allocation, "status", "running" if args[0] == "start" else "stopped"
    )
    # Probe the actual listener address, not the distinct guest-loopback alias.
    spec["public_port"] = available_port(address=config.gamma_ip)
    spec["target_port"] = available_port()
    yield node
    node.allocation.release.set()
    node.close()


def receive_all(sock):
    data = bytearray()
    while block := sock.recv(16384):
        data.extend(block)
    return bytes(data)


def connect(node, spec):
    return socket.create_connection(
        (node.config.gamma_ip, spec["public_port"]), timeout=3
    )


def server_for(spec):
    server = socket.socket()
    server.bind(("127.0.0.1", spec["target_port"]))
    server.listen()
    server.settimeout(3)
    return server


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("size", [7, 1048576])
def test_native_tcp_both_fin_directions_delayed_large_backpressure(
    native_node, spec, reverse, size
):
    node = native_node
    with server_for(spec) as server:
        node.publish(spec)
        with connect(node, spec) as client, server.accept()[0] as peer:
            client.settimeout(5)
            peer.settimeout(5)
            first, second = (peer, client) if reverse else (client, peer)
            payload = b"x" * size
            result = []

            def send():
                first.sendall(payload)
                first.shutdown(socket.SHUT_WR)

            sender = threading.Thread(target=send)
            sender.start()
            time.sleep(0.03)  # Reader pauses: payload exceeds both pump buffers.
            result.append(receive_all(second))
            sender.join(5)
            assert not sender.is_alive()
            assert result == [payload]
            time.sleep(0.03)
            second.sendall(b"response after FIN")
            second.shutdown(socket.SHUT_WR)
            assert receive_all(first) == b"response after FIN"
            assert node.allocation.calls >= 3  # pin, activation, each connection
            assert node.port_status(spec) == "ready"


def test_native_tcp_remove_closes_both_streams_and_releases_owned_rows(
    native_node, spec
):
    node = native_node
    with server_for(spec) as server:
        node.publish(spec)
        with connect(node, spec) as client, server.accept()[0] as peer:
            client.sendall(b"ready")
            assert peer.recv(99) == b"ready"
            node.remove(spec)
            assert client.recv(99) == b""
            assert peer.recv(99) == b""
            assert not node.store.native_records()
            assert all(row["id"] != spec["id"] for row in node.store.ownership())
            assert node.store.address_binding(spec["instance_id"])["state"] == "ready"


def test_native_tcp_idle_and_simultaneous_close(native_node, spec, monkeypatch):
    import container_manager.native_tcp as module

    monkeypatch.setattr(module, "copy_tcp", lambda a, b: copy_tcp(a, b, idle=0.05))
    node = native_node
    with server_for(spec) as server:
        node.publish(spec)
        with connect(node, spec) as client, server.accept()[0] as peer:
            assert client.recv(99) == b""
            assert peer.recv(99) == b""
        with connect(node, spec) as client, server.accept()[0] as peer:
            client.shutdown(socket.SHUT_WR)
            peer.shutdown(socket.SHUT_WR)
            assert receive_all(client) == b""
            assert receive_all(peer) == b""


def test_native_tcp_capacity_rejects_without_extra_upstream(native_node, spec):
    node = native_node
    node.native.capacity = threading.BoundedSemaphore(1)
    with server_for(spec) as server:
        node.publish(spec)
        with connect(node, spec) as first, server.accept()[0] as peer:
            first.sendall(b"held")
            assert peer.recv(99) == b"held"
            with connect(node, spec) as rejected:
                assert rejected.recv(99) == b""
            assert node.allocation.calls == 3


def test_native_tcp_validation_capacity_rejects_excess(native_node, spec):
    node = native_node
    node.publish(spec)
    # Occupy all eight root validation slots; rejection never invokes the daemon.
    for _ in range(8):
        assert node.native.validation.acquire(blocking=False)
    calls = node.allocation.calls
    try:
        with connect(node, spec) as client:
            assert client.recv(99) == b""
        assert node.allocation.calls == calls
    finally:
        for _ in range(8):
            node.native.validation.release()


@pytest.mark.parametrize("transition", ["remove", "pause"])
def test_native_tcp_generation_fences_inflight_validation(
    native_node, spec, transition
):
    node = native_node
    node.publish(spec)
    node.allocation.entered.clear()
    node.allocation.release.clear()
    with connect(node, spec) as client:
        assert node.allocation.entered.wait(2)
        if transition == "remove":
            node.remove(spec)
        else:
            node.power(spec["instance_id"], False)
        node.allocation.release.set()
        assert client.recv(99) == b""


def test_native_tcp_stop_start_closes_streams_retains_exclusive_pause(
    native_node, spec
):
    node = native_node
    with server_for(spec) as server:
        node.publish(spec)
        with connect(node, spec) as client, server.accept()[0] as peer:
            node.power(spec["instance_id"], False)
            assert client.recv(99) == b""
            assert peer.recv(99) == b""
        assert node.port_status(spec) == "ready"
        assert node.store.native_records()[0]["state"] == "paused"
        with socket.socket() as collision, pytest.raises(OSError):
            collision.bind((node.config.gamma_ip, spec["public_port"]))
        with connect(node, spec) as rejected:
            assert rejected.recv(99) == b""
        node.power(spec["instance_id"], True)
        with connect(node, spec) as client, server.accept()[0] as peer:
            client.sendall(b"resumed")
            assert peer.recv(99) == b"resumed"


@pytest.mark.parametrize("stopped", [False, True])
def test_native_tcp_agent_recovery_never_starts_guest(native_node, spec, stopped):
    node = native_node
    node.publish(spec)
    node.close()
    recovered = Incus(node.config, node.store, FreeInspector())
    recovered.allocation = node.allocation
    recovered.allocation.status = "stopped" if stopped else "running"
    recovered.command = lambda *_: pytest.fail("Recovery must not start a guest")
    try:
        recovered.recover()
        assert recovered.port_status(spec) == "ready"
        assert recovered.store.native_records()[0]["state"] == (
            "paused" if stopped else "active"
        )
        assert recovered.native.ready(spec, not stopped)
    finally:
        recovered.close()


def test_native_tcp_paused_recovery_stays_paused_even_running(native_node, spec):
    node = native_node
    node.publish(spec)
    node.power(spec["instance_id"], False)
    node.allocation.status = "running"
    node.close()
    recovered = Incus(node.config, node.store, FreeInspector())
    recovered.allocation = node.allocation
    try:
        recovered.recover()
        assert recovered.native.ready(spec, False)
    finally:
        recovered.close()


@pytest.mark.parametrize("mixed", [False, True])
def test_native_tcp_legacy_ownership_requires_reconciliation(native_node, spec, mixed):
    node = native_node
    node.store.own(spec["id"], spec, "ready")
    node.recover()
    assert node.port_status(spec) == "error"
    assert not node.native.bindings
    assert not node.store.native_records()
    with pytest.raises(Failure, match="requires_reconciliation"):
        node.publish(spec)
    with pytest.raises(Failure, match="requires_reconciliation"):
        node.remove(spec)
    if mixed:
        native_spec = {
            **spec,
            "id": str(uuid4()),
            "public_port": available_port(address=node.config.gamma_ip),
        }
        node.publish(native_spec)
    calls = []
    command = node.command

    def record_command(args):
        calls.append(args)
        command(args)

    node.command = record_command
    # Stopping remains available even with legacy error ownership present.
    node.power(spec["instance_id"], False)
    before_ownership = node.store.ownership()
    before_native = node.store.native_records()
    with pytest.raises(Failure, match="requires_reconciliation"):
        node.power(spec["instance_id"], True)
    assert [args[0] for args in calls] == ["stop"]
    assert node.allocation.status == "stopped"
    assert node.store.ownership() == before_ownership
    assert node.store.native_records() == before_native
    if mixed:
        assert node.native.ready(native_spec, False)
    node.power(spec["instance_id"], False)
    assert [args[0] for args in calls] == ["stop", "stop"]


@pytest.mark.parametrize("fault", ["bind", "activation", "remove", "stop", "pin"])
def test_native_tcp_faults_retain_error_reservation(
    native_node, spec, monkeypatch, fault
):
    node = native_node

    def fail(*_):
        raise Failure("injected_failure")

    if fault == "bind":
        monkeypatch.setattr(node.native, "bind", fail)
    elif fault == "activation":
        monkeypatch.setattr(node.native, "ready", lambda *_: False)
    else:
        node.publish(spec)
    if fault == "remove":
        monkeypatch.setattr(node.store, "remove_native", fail)
        action = lambda: node.remove(spec)
    elif fault == "stop":
        node.command = fail
        action = lambda: node.power(spec["instance_id"], False)
    elif fault == "pin":
        node.allocation.valid = False
        assert node.port_status(spec) == "error"
        action = lambda: node.publish(spec)
    else:
        action = lambda: node.publish(spec)
    with pytest.raises(Failure):
        action()
    assert node.store.native_records()[0]["state"] == "error"
    assert (
        next(r for r in node.store.ownership() if r["id"] == spec["id"])["state"]
        == "error"
    )
    assert node.store.address_binding(spec["instance_id"])["state"] == "ready"


def test_native_tcp_other_listener_is_not_readiness(native_node, spec):
    node = native_node
    node.publish(spec)
    node.native.remove(spec)
    with socket.socket() as foreign:
        foreign.bind((node.config.gamma_ip, spec["public_port"]))
        foreign.listen()
        assert node.port_status(spec) == "error"


def test_native_tcp_shutdown_preserves_durable_transport(native_node, spec):
    node = native_node
    node.publish(spec)
    before = node.store.native_records()
    node.close()
    assert node.store.native_records() == before
    assert json.loads(before[0]["spec"]) == spec


def test_native_tcp_every_connection_revalidates_and_closes_on_drift(native_node, spec):
    node = native_node
    with server_for(spec) as server:
        node.publish(spec)
        with connect(node, spec) as first, server.accept()[0] as peer:
            first.sendall(b"first")
            assert peer.recv(99) == b"first"
            node.allocation.valid = False
            with connect(node, spec) as rejected:
                assert rejected.recv(99) == b""
            assert first.recv(99) == b""
            assert peer.recv(99) == b""
            # EOF is observable before the validation callback commits its
            # durable phase. Join the same lifecycle lock used by that callback
            # instead of racing its final SQLite transaction.
            with node.instance_lock(spec["instance_id"]):
                assert node.store.native_records()[0]["state"] == "error"


def test_native_tcp_generation_fences_connect_completion(
    native_node, spec, monkeypatch
):
    node = native_node
    original = socket.create_connection
    entered, release = threading.Event(), threading.Event()

    def delayed(address, **kwargs):
        upstream = original(address, **kwargs)
        if address == ("127.0.0.1", spec["target_port"]):
            entered.set()
            assert release.wait(3)
        return upstream

    with server_for(spec) as server:
        node.publish(spec)
        monkeypatch.setattr(socket, "create_connection", delayed)
        with connect(node, spec) as client, server.accept()[0] as peer:
            assert entered.wait(2)
            node.power(spec["instance_id"], False)
            node.power(spec["instance_id"], True)
            release.set()
            assert client.recv(99) == b""
            peer.settimeout(3)
            assert peer.recv(99) == b""


def test_native_tcp_sql_reservation_atomic_with_ownership(native_node, spec):
    node = native_node
    node.publish(spec)
    other = {**spec, "id": str(uuid4())}
    with pytest.raises(Failure, match="allocation_conflict"):
        Store(node.store.path).native_state(other, "creating")
    assert all(row["id"] != other["id"] for row in node.store.ownership())
    assert len(node.store.native_records()) == 1


def test_native_tcp_recovery_invalid_pin_errors_without_reassignment(native_node, spec):
    node = native_node
    node.publish(spec)
    node.close()
    node.store.save_address(node.allocation.pin_value, "error")
    recovered = Incus(node.config, node.store, FreeInspector())
    recovered.allocation = node.allocation
    calls = node.allocation.calls
    try:
        recovered.recover()
        assert node.allocation.calls == calls
        assert not recovered.native.bindings
        assert node.store.native_records()[0]["state"] == "error"
    finally:
        recovered.close()


def test_native_tcp_bind_collision_retains_error_never_steals(native_node, spec):
    node = native_node
    with socket.socket() as foreign:
        foreign.bind((node.config.gamma_ip, spec["public_port"]))
        foreign.listen()
        with pytest.raises(Failure, match="native_tcp_bind_failed"):
            node.publish(spec)
        assert foreign.fileno() >= 0
        assert not node.native.bindings
        assert node.store.native_records()[0]["state"] == "error"


def test_native_tcp_interrupted_create_never_rebound(native_node, spec):
    node = native_node
    node.store.native_state(spec, "creating")
    node.recover()
    assert not node.native.bindings
    assert node.store.native_records()[0]["state"] == "error"
    with pytest.raises(Failure, match="requires_reconciliation"):
        node.publish(spec)


def test_native_tcp_start_pin_failure_never_starts_guest(native_node, spec):
    node = native_node
    node.publish(spec)
    node.power(spec["instance_id"], False)
    node.allocation.valid = False
    node.command = lambda *_: pytest.fail("must validate before starting")
    with pytest.raises(Failure, match="address_binding_mismatch"):
        node.power(spec["instance_id"], True)
    assert node.native.ready(spec, False)
    assert node.store.native_records()[0]["state"] == "error"


@pytest.mark.parametrize("negative", ["stopped", "failure"])
def test_native_tcp_stale_negative_validation_cannot_pause_resumed_generation(
    native_node, spec, monkeypatch, negative
):
    node = native_node
    node.publish(spec)
    entered, release, completed = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    selection_lock = threading.Lock()
    selected = False
    validate = node.allocation.validate
    pause_validation = node.pause_native_validation

    def delayed_negative(resource, pin):
        nonlocal selected
        result = validate(resource, pin)
        with selection_lock:
            old_result = not selected
            selected = True
        if old_result:
            # The authoritative validation has returned/released its allocation
            # lock, but this old connection has not delivered its result yet.
            entered.set()
            assert release.wait(5)
            if negative == "failure":
                raise Failure("address_binding_mismatch", 409)
            return pin, "stopped"
        return result

    def observe_negative(binding, generation, state):
        try:
            pause_validation(binding, generation, state)
        finally:
            completed.set()

    monkeypatch.setattr(node.allocation, "validate", delayed_negative)
    monkeypatch.setattr(node, "pause_native_validation", observe_negative)
    try:
        with server_for(spec) as server, connect(node, spec) as old_client:
            assert entered.wait(2)
            binding = node.native.bindings[spec["id"]]
            old_generation = binding.generation
            node.power(spec["instance_id"], False)
            node.power(spec["instance_id"], True)
            assert binding.generation > old_generation
            assert node.native.bindings[spec["id"]] is binding
            with connect(node, spec) as current, server.accept()[0] as peer:
                peer.settimeout(3)
                current.sendall(b"new generation before old result")
                assert peer.recv(99) == b"new generation before old result"
                release.set()
                assert completed.wait(2)
                assert old_client.recv(99) == b""
                assert node.native.ready(spec, True)
                assert node.store.native_records()[0]["state"] == "active"
                assert (
                    next(
                        row for row in node.store.ownership() if row["id"] == spec["id"]
                    )["state"]
                    == "ready"
                )
                current.sendall(b"still usable after old result")
                assert peer.recv(99) == b"still usable after old result"
                peer.sendall(b"reverse direction intact")
                assert current.recv(99) == b"reverse direction intact"
    finally:
        release.set()
