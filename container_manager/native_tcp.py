"""Gamma-only exclusive TCP listeners; state belongs to the node SQLite store."""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from .errors import Failure
from .relay import Binding, MAX_CONNECTIONS, copy_tcp


@dataclass
class NativeBinding(Binding):
    generation: int = 0


class NativeTCP:
    def __init__(self, node):
        self.node = node
        self.bindings: dict[str, NativeBinding] = {}
        self.capacity = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.validation = threading.BoundedSemaphore(8)
        self.workers = ThreadPoolExecutor(
            max_workers=MAX_CONNECTIONS, thread_name_prefix="gamma-tcp"
        )

    def bind(self, spec: dict, active: bool) -> NativeBinding:
        sock = socket.socket()
        try:
            sock.bind((self.node.config.gamma_ip, spec["public_port"]))
            sock.listen(32)
            sock.settimeout(0.2)
            binding = NativeBinding(dict(spec), sock)
            if active:
                binding.active.set()
            self.bindings[spec["id"]] = binding
            binding.thread = threading.Thread(
                target=self.accept, args=(binding,), daemon=True
            )
            binding.thread.start()
            return binding
        except (OSError, RuntimeError):
            sock.close()
            binding = self.bindings.pop(spec["id"], None)
            if binding:
                binding.stop.set()
            raise Failure("native_tcp_bind_failed", 409) from None

    def ready(self, spec: dict, active: bool) -> bool:
        binding = self.bindings.get(spec["id"])
        return bool(
            binding
            and binding.spec == spec
            and not binding.stop.is_set()
            and binding.sock.fileno() >= 0
            and binding.thread
            and binding.thread.is_alive()
            and binding.sock.getsockname()
            == (self.node.config.gamma_ip, spec["public_port"])
            and binding.active.is_set() == active
        )

    def accept(self, binding: NativeBinding):
        while not binding.stop.is_set():
            try:
                client, _ = binding.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with binding.clients_lock:
                if not binding.active.is_set() or binding.stop.is_set():
                    client.close()
                    continue
                if not self.capacity.acquire(blocking=False):
                    client.close()
                    continue
                binding.clients.add(client)
                generation = binding.generation
            try:
                self.workers.submit(self.client, binding, client, generation)
            except RuntimeError:
                with binding.clients_lock:
                    binding.clients.discard(client)
                client.close()
                self.capacity.release()

    def client(self, binding: NativeBinding, client: socket.socket, generation: int):
        upstream = None
        try:
            if not self.validation.acquire(blocking=False):
                return
            try:
                pin = self.node.store.address_binding(binding.spec["instance_id"])
                if not pin or pin["state"] != "ready":
                    raise Failure("address_requires_reconciliation", 409)
                _, status = self.node.allocation.validate(
                    binding.spec["instance_id"], pin
                )
                if status != "running":
                    self.node.pause_native_validation(binding, generation, "paused")
                    return
            finally:
                self.validation.release()
            with binding.clients_lock:
                if (
                    binding.stop.is_set()
                    or not binding.active.is_set()
                    or generation != binding.generation
                ):
                    return
            upstream = socket.create_connection(
                (pin["address"], binding.spec["target_port"]), timeout=3
            )
            with binding.clients_lock:
                if (
                    binding.stop.is_set()
                    or not binding.active.is_set()
                    or generation != binding.generation
                ):
                    return
                binding.clients.add(upstream)
            copy_tcp(client, upstream)
        except Failure:
            self.node.pause_native_validation(binding, generation, "error")
        except OSError:
            pass
        finally:
            with binding.clients_lock:
                binding.clients.discard(client)
                if upstream is not None:
                    binding.clients.discard(upstream)
            client.close()
            if upstream is not None:
                upstream.close()
            self.capacity.release()

    def pause(self, spec: dict):
        binding = self.bindings.get(spec["id"])
        if not binding or binding.spec != spec:
            raise Failure("proxy_requires_reconciliation", 409)
        with binding.clients_lock:
            binding.active.clear()
            binding.generation += 1
            for client in binding.clients:
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()

    def resume(self, spec: dict):
        binding = self.bindings.get(spec["id"])
        if not binding or not self.ready(spec, False):
            raise Failure("proxy_requires_reconciliation", 409)
        with binding.clients_lock:
            binding.generation += 1
            binding.active.set()

    def remove(self, spec: dict):
        self.pause(spec)
        binding = self.bindings.pop(spec["id"])
        binding.stop.set()
        binding.sock.close()
        binding.thread.join(timeout=2)

    def close(self):
        for binding in list(self.bindings.values()):
            self.remove(binding.spec)
        self.workers.shutdown(wait=True)
