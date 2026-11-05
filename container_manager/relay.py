"""Bounded native relay. Reserved sockets stay bound and do not forward.

TCP FIN propagates to the other stream without discarding the reverse direction.
UDP associations are per-client, connected to the fixed gamma address, capped/TTL.
"""

import json
import selectors
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .errors import Failure
from .models import Port, canonical_id, validate_port

TCP_IDLE = 120
UDP_TTL = 30
MAX_CONNECTIONS = 128
MAX_UDP_CLIENTS = 256
MAX_UDP_ASSOCIATIONS = 1024
BUFFER = 65536


def copy_tcp(client: socket.socket, upstream: socket.socket, idle: float = TCP_IDLE):
    peers = {client: upstream, upstream: client}
    pending = {client: bytearray(), upstream: bytearray()}
    readable = {client, upstream}
    write_closed = set()
    deadline = time.monotonic() + idle
    try:
        for stream in peers:
            if stream.family in (socket.AF_INET, socket.AF_INET6):
                # Keep small protocol messages out of Nagle/delayed-ACK stalls.
                stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            stream.setblocking(False)
        with selectors.DefaultSelector() as selector:
            while time.monotonic() < deadline:
                for stream in peers:
                    events = 0
                    if stream in readable and len(pending[peers[stream]]) < BUFFER:
                        events |= selectors.EVENT_READ
                    if pending[stream]:
                        events |= selectors.EVENT_WRITE
                    try:
                        selector.unregister(stream)
                    except KeyError:
                        pass
                    if events:
                        selector.register(stream, events)
                    if (
                        peers[stream] not in readable
                        and not pending[stream]
                        and stream not in write_closed
                    ):
                        stream.shutdown(socket.SHUT_WR)
                        write_closed.add(stream)
                if not readable and not any(pending.values()):
                    break
                events = selector.select(min(1, max(0, deadline - time.monotonic())))
                for key, mask in events:
                    stream = key.fileobj
                    if mask & selectors.EVENT_READ:
                        data = stream.recv(
                            min(16384, BUFFER - len(pending[peers[stream]]))
                        )
                        if data:
                            pending[peers[stream]].extend(data)
                            deadline = time.monotonic() + idle
                        else:
                            readable.discard(stream)
                    if mask & selectors.EVENT_WRITE:
                        sent = stream.send(pending[stream])
                        del pending[stream][:sent]
                        if sent:
                            deadline = time.monotonic() + idle
    except (OSError, ValueError):
        pass
    finally:
        client.close()
        upstream.close()


@dataclass
class Binding:
    spec: dict
    sock: socket.socket
    active: threading.Event = field(default_factory=threading.Event)
    stop: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    clients: set[socket.socket] = field(default_factory=set)
    clients_lock: threading.Lock = field(default_factory=threading.Lock)


class Relay:
    def __init__(self, config, store, inspector):
        self.config, self.store, self.inspector = config, store, inspector
        self.bindings: dict[str, Binding] = {}
        self.lock = threading.RLock()
        self.capacity = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.udp_capacity = threading.BoundedSemaphore(MAX_UDP_ASSOCIATIONS)
        self.workers = ThreadPoolExecutor(
            max_workers=MAX_CONNECTIONS, thread_name_prefix="tcp"
        )

    def bind(self, spec: dict) -> Binding:
        family = socket.AF_INET6 if ":" in self.config.public_ip else socket.AF_INET
        sock = socket.socket(
            family,
            socket.SOCK_STREAM if spec["protocol"] == "tcp" else socket.SOCK_DGRAM,
        )
        try:
            # No SO_REUSEPORT or SO_REUSEADDR: exclusive public reservation.
            if family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((self.config.public_ip, spec["public_port"]))
            if spec["protocol"] == "tcp":
                sock.listen(32)
            sock.settimeout(0.2)
            return Binding(spec, sock)
        except OSError:
            sock.close()
            raise Failure("host_listener_conflict", 409) from None

    def reserve(self, spec: dict):
        canonical_id(spec["id"])
        canonical_id(spec["instance_id"])
        validate_port(
            Port(**{k: spec[k] for k in ("protocol", "public_port", "target_port")}),
            set(self.config.reserved_ports),
        )
        with self.lock:
            old = next(
                (r for r in self.store.ownership() if r["id"] == spec["id"]), None
            )
            if old:
                if (
                    json.loads(old["spec"]) == spec
                    and old["state"] in {"reserved", "active"}
                    and spec["id"] in self.bindings
                ):
                    return
                raise Failure("relay_requires_reconciliation", 409)
            self.inspector.check(spec["protocol"], spec["public_port"])
            self.store.own(spec["id"], spec, "reserving")
            try:
                binding = self.bind(spec)
                self.bindings[spec["id"]] = binding
                self.store.own(spec["id"], spec, "reserved")
            except BaseException:
                self.store.own(spec["id"], spec, "error")
                raise

    def activate(self, spec: dict):
        with self.lock:
            binding = self.bindings.get(spec["id"])
            if not binding or binding.spec != spec:
                raise Failure("relay_requires_reconciliation", 409)
            if binding.active.is_set():
                return
            self.store.own(spec["id"], spec, "active")
            binding.active.set()
            binding.thread = threading.Thread(
                target=self.tcp if spec["protocol"] == "tcp" else self.udp,
                args=(binding,),
                daemon=True,
            )
            binding.thread.start()

    def port_status(self, spec: dict) -> str:
        with self.lock:
            canonical_id(spec["id"])
            row = next(
                (r for r in self.store.ownership() if r["id"] == spec["id"]), None
            )
            if row is None:
                return "missing"
            if json.loads(row["spec"]) != spec:
                raise Failure("ownership_conflict", 409)
            binding = self.bindings.get(spec["id"])
            if (
                not binding
                or binding.sock.fileno() < 0
                or (
                    row["state"] == "active"
                    and (not binding.thread or not binding.thread.is_alive())
                )
            ):
                self.store.own(spec["id"], spec, "error")
                return "error"
            return row["state"]

    def remove(self, spec: dict):
        with self.lock:
            row = next(
                (r for r in self.store.ownership() if r["id"] == spec["id"]), None
            )
            if row is None:
                return
            if json.loads(row["spec"]) != spec:
                raise Failure("ownership_conflict", 409)
            binding = self.bindings.pop(spec["id"], None)
            if binding:
                binding.stop.set()
                binding.sock.close()
                with binding.clients_lock:
                    for client in binding.clients:
                        try:
                            client.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        client.close()
                if binding.thread:
                    binding.thread.join(timeout=2)
            self.store.disown(spec["id"])

    def recover(self):
        for row in self.store.ownership():
            spec = json.loads(row["spec"])
            if row["state"] not in {"active", "reserved"}:
                self.store.own(row["id"], spec, "error")
                continue
            try:
                # Inspect before rebinding: an existing mapping must never be stolen.
                self.inspector.check(spec["protocol"], spec["public_port"])
                self.bindings[row["id"]] = self.bind(spec)
                if row["state"] == "active":
                    self.activate(spec)
            except Failure:
                self.store.own(row["id"], spec, "error")

    def tcp(self, binding: Binding):
        while not binding.stop.is_set():
            try:
                client, _ = binding.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.capacity.acquire(blocking=False):
                client.close()
                continue
            with binding.clients_lock:
                if binding.stop.is_set():
                    client.close()
                    self.capacity.release()
                    continue
                binding.clients.add(client)
            self.workers.submit(self.tcp_client, client, binding)

    def tcp_client(self, client: socket.socket, binding: Binding):
        try:
            # Target never comes from the request. External == gamma proxy port.
            upstream = socket.create_connection(
                (self.config.gamma_ip, binding.spec["public_port"]), timeout=3
            )
            with binding.clients_lock:
                if binding.stop.is_set():
                    upstream.close()
                    client.close()
                    return
                binding.clients.add(upstream)
            copy_tcp(client, upstream)
        except OSError:
            client.close()
        finally:
            with binding.clients_lock:
                binding.clients.discard(client)
                if "upstream" in locals():
                    binding.clients.discard(upstream)
            self.capacity.release()

    def udp(self, binding: Binding):
        clients: dict[tuple, tuple[socket.socket, float]] = {}
        family = socket.AF_INET6 if ":" in self.config.gamma_ip else socket.AF_INET
        try:
            with selectors.DefaultSelector() as selector:
                binding.sock.setblocking(False)
                selector.register(binding.sock, selectors.EVENT_READ, None)
                while not binding.stop.is_set():
                    for key, _ in selector.select(0.2):
                        if key.fileobj is binding.sock:
                            data, address = binding.sock.recvfrom(BUFFER)
                            if address not in clients:
                                if len(clients) >= MAX_UDP_CLIENTS:
                                    continue
                                if not self.udp_capacity.acquire(blocking=False):
                                    continue
                                upstream = None
                                try:
                                    upstream = socket.socket(family, socket.SOCK_DGRAM)
                                    upstream.setblocking(False)
                                    upstream.connect(
                                        (
                                            self.config.gamma_ip,
                                            binding.spec["public_port"],
                                        )
                                    )
                                except OSError:
                                    if upstream is not None:
                                        upstream.close()
                                    self.udp_capacity.release()
                                    continue
                                clients[address] = (upstream, time.monotonic())
                                selector.register(
                                    upstream, selectors.EVENT_READ, address
                                )
                            upstream, _ = clients[address]
                            try:
                                upstream.send(data)
                            except OSError:
                                pass
                            clients[address] = (upstream, time.monotonic())
                        else:
                            try:
                                data = key.fileobj.recv(BUFFER)
                                binding.sock.sendto(data, key.data)
                            except OSError:
                                pass
                    cutoff = time.monotonic() - UDP_TTL
                    for address, (upstream, touched) in list(clients.items()):
                        if touched < cutoff:
                            selector.unregister(upstream)
                            upstream.close()
                            self.udp_capacity.release()
                            del clients[address]
        except OSError:
            # Persistent state remains active/error for operator review, never free.
            if not binding.stop.is_set():
                self.store.own(binding.spec["id"], binding.spec, "error")
        finally:
            for upstream, _ in clients.values():
                upstream.close()
                self.udp_capacity.release()

    def close(self):
        for binding in self.bindings.values():
            binding.stop.set()
            binding.sock.close()
            with binding.clients_lock:
                for client in binding.clients:
                    try:
                        client.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    client.close()
            if binding.thread:
                binding.thread.join(timeout=2)
        self.workers.shutdown(wait=False, cancel_futures=True)
