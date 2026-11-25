import ast
import errno
import logging
from pathlib import Path
import json
import subprocess
import time
from unittest.mock import Mock

import pytest

from container_manager.diagnostics import CODES, emit, emit_transition
from container_manager.errors import Failure
from container_manager.incus import Incus
from container_manager.native_tcp import NativeTCP

RESOURCE = "cbbee3d4-d034-4bba-96a9-a6e548ccfa9b"
SPEC = dict(
    id=RESOURCE,
    instance_id=RESOURCE,
    protocol="tcp",
    public_port=3002,
    target_port=25565,
)


def test_emit_strict_safety(caplog):
    class Hostile:
        def __str__(self):
            raise AssertionError("must not stringify")

    emit(
        "native_tcp",
        "bind",
        Failure("password=secret"),
        started=time.monotonic(),
        spec={**SPEC, "target_port": Hostile()},
        category=Hostile(),
        password="secret",
        instance_id=Hostile(),
    )
    record = json.loads(caplog.records[-1].message)
    assert record["code"] == "internal_error"
    assert record["mapping_id"] == RESOURCE
    assert record["stage"] == "bind" and record["duration_ms"] >= 0
    assert "secret" not in caplog.text and "target_port" not in record


@pytest.mark.parametrize(
    "error,category",
    [
        (subprocess.TimeoutExpired("token", 5), "timeout"),
        (subprocess.CalledProcessError(7, "password", output="secret"), "exit"),
        (OSError(errno.EACCES, "secret"), "oserror"),
        (ValueError("secret"), "json"),
    ],
)
def test_query_failure_categories(caplog, error, category):
    node = object.__new__(Incus)
    node.runner = Mock(side_effect=error)
    with pytest.raises(Failure, match="incus_query_unavailable"):
        node.query("/1.0/instances/private?token=secret")
    record = json.loads(caplog.records[-1].message)
    assert record["category"] == category
    assert record["route_kind"] == "instance" and record["stage"] == "query"
    assert record["duration_ms"] >= 0
    assert "secret" not in caplog.text and "private" not in caplog.text


@pytest.mark.parametrize(
    "number,code",
    [
        (errno.EADDRINUSE, "native_tcp_address_in_use"),
        (errno.EACCES, "native_tcp_bind_failed"),
    ],
)
def test_bind_failure_code(caplog, monkeypatch, number, code):
    sock = Mock()
    sock.bind.side_effect = OSError(number, "secret")
    monkeypatch.setattr("container_manager.native_tcp.socket.socket", lambda: sock)
    native = NativeTCP(Mock())
    try:
        with pytest.raises(Failure, match=code):
            native.bind(SPEC, True)
        record = json.loads(caplog.records[-1].message)
        assert record["mapping_id"] == RESOURCE
        assert record["errno"] == number
        assert record["code"] == code
        assert record["stage"] == "bind" and record["duration_ms"] >= 0
        assert "secret" not in caplog.text
    finally:
        native.close()


def test_logging_handler_failure_does_not_escape(monkeypatch):
    monkeypatch.setattr(
        "logging.Logger.error", Mock(side_effect=RuntimeError("secret"))
    )
    emit("incus", "query", Failure("incus_query_unavailable"))


@pytest.mark.parametrize("state", ["paused", "error"])
@pytest.mark.parametrize("stale", [False, True])
def test_pause_generation_outcome(caplog, stale, state):
    import threading
    from types import SimpleNamespace

    binding = SimpleNamespace(spec=SPEC, clients_lock=threading.Lock(), generation=2)
    node = object.__new__(Incus)
    node.instance_lock = lambda _: threading.RLock()
    node.native = SimpleNamespace(bindings={RESOURCE: binding}, pause=Mock())
    node.store = Mock()
    caplog.set_level(logging.INFO, logger="container_manager.diagnostics")
    node.pause_native_validation(binding, 1 if stale else 2, state)
    record = json.loads(caplog.records[-1].message)
    assert record["mapping_id"] == RESOURCE and record["stage"] == "pause"
    assert record["outcome"] == ("stale" if stale else "applied")
    assert record["event"] == "mapping_transition" and record["level"] == "INFO"
    assert caplog.records[-1].levelno == logging.INFO
    assert "code" not in record
    assert not any(r.levelno >= logging.ERROR for r in caplog.records)
    assert record["duration_ms"] >= 0
    assert node.store.native_state.call_count == (0 if stale else 1)
    assert node.native.pause.call_count == (0 if stale else 1)


def test_instrumented_failure_constants_are_allowlisted():
    root = Path(__file__).resolve().parents[1] / "container_manager"
    codes = set()
    for module in ("native_tcp", "incus", "allocation", "controller"):
        tree = ast.parse((root / f"{module}.py").read_text())
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "Failure"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and type(node.args[0].value) is str
            ):
                codes.add(node.args[0].value)
            # bind selects its controlled code before constructing Failure(code).
            if (
                module == "native_tcp"
                and isinstance(node, ast.Constant)
                and type(node.value) is str
                and node.value.startswith("native_tcp_")
            ):
                codes.add(node.value)
    assert codes
    assert codes <= CODES


def test_socket_creation_failure_retains_exception_and_code(caplog, monkeypatch):
    error = OSError(errno.EMFILE, "secret")
    monkeypatch.setattr(
        "container_manager.native_tcp.socket.socket", Mock(side_effect=error)
    )
    native = NativeTCP(Mock())
    try:
        with pytest.raises(OSError) as caught:
            native.bind(SPEC, True)
        assert caught.value is error
        record = json.loads(caplog.records[-1].message)
        assert record["code"] == "native_tcp_bind_failed"
        assert record["errno"] == errno.EMFILE and record["stage"] == "bind"
    finally:
        native.close()


@pytest.mark.parametrize("boundary", ["pause", "persist"])
def test_pause_failure_never_logs_applied(caplog, boundary):
    import threading
    from types import SimpleNamespace

    caplog.set_level(logging.INFO, logger="container_manager.diagnostics")
    binding = SimpleNamespace(spec=SPEC, clients_lock=threading.Lock(), generation=2)
    node = object.__new__(Incus)
    node.instance_lock = lambda _: threading.RLock()
    node.native = SimpleNamespace(bindings={RESOURCE: binding}, pause=Mock())
    node.store = Mock()
    error = RuntimeError("private payload")
    failing = node.native.pause if boundary == "pause" else node.store.native_state
    failing.side_effect = error
    with pytest.raises(RuntimeError) as caught:
        node.pause_native_validation(binding, 2, "paused")
    assert caught.value is error
    assert node.native.pause.call_count == 1
    assert node.store.native_state.call_count == (0 if boundary == "pause" else 1)
    assert not caplog.records


def test_transition_logging_failure_does_not_escape(monkeypatch):
    monkeypatch.setattr("logging.Logger.info", Mock(side_effect=RuntimeError("secret")))
    emit_transition("incus", "pause", spec=SPEC, outcome="stale")
