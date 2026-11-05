import socket
import threading
import time
from dataclasses import replace
from unittest.mock import Mock
from uuid import uuid4

import pytest

from container_manager.errors import Failure
from container_manager.relay import Relay, copy_tcp
from container_manager.store import Store
from conftest import FreeInspector


def available_port(protocol="tcp", address="127.0.0.1"):
    with socket.socket(
        type=socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    ) as sock:
        sock.bind((address, 0))
        port = sock.getsockname()[1]
    # Test ports must not be NodePort/reserved. Ask for another ephemeral port.
    from container_manager.models import RESERVED

    if 30000 <= port <= 32767 or port in RESERVED:
        return available_port(protocol, address)
    return port


def test_available_port_probes_requested_bind_address(monkeypatch):
    original_socket = socket.socket
    bound = []

    class TracedSocket:
        def __init__(self, **kwargs):
            self.sock = original_socket(**kwargs)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            self.sock.close()

        def bind(self, address):
            bound.append(address)
            self.sock.bind(address)

        def getsockname(self):
            return self.sock.getsockname()

    monkeypatch.setattr(socket, "socket", TracedSocket)
    assert available_port(address="127.0.0.2") > 0
    assert bound and all(address == ("127.0.0.2", 0) for address in bound)


def test_exclusive_reservation_and_remove(config, spec):
    spec["public_port"] = available_port()
    relay = Relay(config, Store(config.database), FreeInspector())
    try:
        relay.reserve(spec)
        with socket.socket() as collision, pytest.raises(OSError):
            collision.bind(("127.0.0.1", spec["public_port"]))
        relay.reserve(spec)  # Same ID is idempotent.
        other = {**spec, "id": str(uuid4())}
        with pytest.raises(Failure, match="host_listener_conflict"):
            relay.reserve(other)
        relay.remove(spec)
        with socket.socket() as freed:
            freed.bind(("127.0.0.1", spec["public_port"]))
    finally:
        relay.close()


def test_restart_reserved_socket_and_rebind_failure_keeps_ownership(config, spec):
    spec["public_port"] = available_port()
    first = Relay(config, Store(config.database), FreeInspector())
    first.reserve(spec)
    first.close()
    second = Relay(config, Store(config.database), FreeInspector())
    second.recover()
    assert spec["id"] in second.bindings
    second.close()
    with socket.socket() as squatter:
        squatter.bind(("127.0.0.1", spec["public_port"]))
        third = Relay(config, Store(config.database), FreeInspector())
        third.recover()
        try:
            assert third.store.ownership()[0]["state"] == "error"
            assert not third.bindings
        finally:
            third.close()


def test_copy_tcp_half_close_and_bounded_idle():
    client, relay_left = socket.socketpair()
    relay_right, server = socket.socketpair()
    worker = threading.Thread(target=copy_tcp, args=(relay_left, relay_right, 1))
    worker.start()
    try:
        client.settimeout(2)
        server.settimeout(2)
        client.sendall(b"request")
        client.shutdown(socket.SHUT_WR)
        assert server.recv(99) == b"request"
        assert server.recv(99) == b""
        server.sendall(b"response after request FIN")
        server.shutdown(socket.SHUT_WR)
        result = b""
        while data := client.recv(99):
            result += data
        assert result == b"response after request FIN"
    finally:
        client.close()
        server.close()
        worker.join(3)
    assert not worker.is_alive()
    a, b = socket.socketpair()
    c, d = socket.socketpair()
    start = time.monotonic()
    copy_tcp(a, c, idle=0.05)
    b.close()
    d.close()
    assert time.monotonic() - start < 1


@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_copy_tcp_enables_nodelay_on_both_tcp_streams(family):
    address = "127.0.0.1" if family == socket.AF_INET else "::1"
    with socket.socket(family) as listener:
        try:
            listener.bind((address, 0))
        except OSError:
            if family == socket.AF_INET6:
                pytest.skip("IPv6 loopback is unavailable")
            raise
        listener.listen()
        listener.settimeout(2)
        with (
            socket.create_connection(listener.getsockname()[:2], timeout=2) as client,
            listener.accept()[0] as relay_left,
            socket.create_connection(
                listener.getsockname()[:2], timeout=2
            ) as relay_right,
            listener.accept()[0] as server,
        ):
            assert relay_left.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 0
            assert relay_right.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 0
            worker = threading.Thread(
                target=copy_tcp, args=(relay_left, relay_right, 1)
            )
            worker.start()
            try:
                client.settimeout(2)
                server.settimeout(2)
                client.sendall(b"request")
                assert server.recv(99) == b"request"
                assert (
                    relay_left.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1
                )
                assert (
                    relay_right.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) == 1
                )
                client.shutdown(socket.SHUT_WR)
                assert server.recv(99) == b""
                server.sendall(b"response after request FIN")
                server.shutdown(socket.SHUT_WR)
                response = bytearray()
                while block := client.recv(99):
                    response.extend(block)
                assert response == b"response after request FIN"
            finally:
                client.close()
                server.close()
                worker.join(3)
            assert not worker.is_alive()


@pytest.mark.parametrize("failing_stream", [0, 1])
def test_copy_tcp_nodelay_failure_closes_both_streams(failing_stream):
    streams = [Mock(spec=socket.socket), Mock(spec=socket.socket)]
    for stream in streams:
        stream.family = socket.AF_INET
    streams[failing_stream].setsockopt.side_effect = OSError("socket closed")
    copy_tcp(*streams)
    for stream in streams:
        stream.close.assert_called_once_with()
    streams[failing_stream].setsockopt.assert_called_once_with(
        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
    )


def test_real_tcp_relay_fixed_target_and_removal_closes_connections(config, spec):
    spec["public_port"] = available_port()
    relay = Relay(config, Store(config.database), FreeInspector())
    with socket.socket() as server:
        server.bind((config.gamma_ip, spec["public_port"]))
        server.listen()
        server.settimeout(3)
        try:
            relay.reserve(spec)
            relay.activate(spec)
            with socket.create_connection(
                (config.public_ip, spec["public_port"]), timeout=2
            ) as client:
                peer, _ = server.accept()
                with peer:
                    peer.settimeout(2)
                    client.sendall(b"hello")
                    assert peer.recv(99) == b"hello"
                    peer.sendall(b"world")
                    assert client.recv(99) == b"world"
                    binding = relay.bindings[spec["id"]]
                    with binding.clients_lock:
                        assert len(binding.clients) == 2
                        assert all(
                            stream.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY)
                            == 1
                            for stream in binding.clients
                        )
                    relay.remove(spec)
                    assert client.recv(99) == b""
        finally:
            relay.close()


def test_real_udp_per_client_reply_and_ttl(config, spec, monkeypatch):
    import container_manager.relay as module

    monkeypatch.setattr(module, "UDP_TTL", 0.1)
    spec["protocol"] = "udp"
    spec["public_port"] = available_port("udp")
    relay = Relay(config, Store(config.database), FreeInspector())
    with socket.socket(type=socket.SOCK_DGRAM) as server:
        server.bind((config.gamma_ip, spec["public_port"]))
        server.settimeout(2)
        try:
            relay.reserve(spec)
            relay.activate(spec)
            with (
                socket.socket(type=socket.SOCK_DGRAM) as first,
                socket.socket(type=socket.SOCK_DGRAM) as second,
            ):
                clients = [first, second]
                upstreams = []
                for n, client in enumerate(clients):
                    client.settimeout(2)
                    client.sendto(
                        str(n).encode(), (config.public_ip, spec["public_port"])
                    )
                    data, upstream = server.recvfrom(99)
                    upstreams.append(upstream)
                    server.sendto(b"reply-" + data, upstream)
                    assert client.recv(99) == b"reply-" + str(n).encode()
                assert upstreams[0] != upstreams[1]
                time.sleep(0.5)
                server.sendto(b"stale", upstreams[0])
                first.settimeout(0.2)
                with pytest.raises(socket.timeout):
                    first.recv(99)
            assert relay.store.ownership()[0]["state"] == "active"
            # No UDP reachability inference exists in durable metadata.
            assert "reachable" not in relay.store.ownership()[0]["spec"]
        finally:
            relay.close()


def test_restart_interrupted_reserve_is_error_never_freed(config, spec):
    store = Store(config.database)
    store.own(spec["id"], spec, "reserving")
    relay = Relay(config, store, FreeInspector())
    try:
        relay.recover()
        assert relay.store.ownership()[0]["state"] == "error"
        assert not relay.bindings
    finally:
        relay.close()
