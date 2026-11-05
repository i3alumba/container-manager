from dataclasses import replace
from uuid import uuid4

import pytest

from container_manager.config import Config
from container_manager.controller import Controller
from container_manager.store import Store


class FakeAgent:
    def __init__(self):
        self.calls = []
        self.fail = None
        self.available = True
        self.ports = {}
        self.states = {}

    def inspect(self, spec):
        self.calls.append(("inspect", spec))
        self.check("inspect")
        return {"available": self.available, "reason": "free"}

    def check(self, action):
        from container_manager.errors import Failure

        if self.fail == action:
            raise Failure("fake_unavailable")

    def instance_status(self, resource):
        self.check("instance_status")
        return self.states.get(resource, "running")

    def port_status(self, spec):
        self.check("port_status")
        return "active" if "activate" in [c[0] for c in self.calls] else "ready"

    def resources(self):
        self.check("resources")
        return {
            "cpu": 64,
            "memory_bytes": 128_000_000_000,
            "gpus": [{"id": "0000:01:00.0", "name": "Test shared GPU"}],
        }

    def update_resources(
        self,
        resource,
        cpu,
        memory,
        gpu_ids,
        allow_restart,
        operation_id,
        expected_cpu,
        expected_memory,
        expected_gpu_ids,
    ):
        self.calls.append(
            ("update_resources", resource, cpu, memory, gpu_ids, allow_restart)
        )
        self.check("update_resources")
        return self.states.get(resource, "running")

    def create(self, resource, cpu, memory, password, gpu_ids=()):
        self.states[resource] = "running"
        self.calls.append(("create", resource))
        self.check("create")

    def reserve(self, spec):
        self.calls.append(("reserve", spec))
        self.ports[spec["id"]] = spec
        self.check("reserve")

    def publish(self, spec):
        self.calls.append(("publish", spec))
        self.ports[spec["id"]] = spec
        self.check("publish")

    def activate(self, spec):
        self.calls.append(("activate", spec))
        self.check("activate")

    def remove(self, spec):
        self.calls.append(("remove", spec))
        self.check("remove")
        self.ports.pop(spec["id"], None)

    def power(self, resource, start):
        self.states[resource] = "running" if start else "stopped"
        self.calls.append(("power", resource, start))
        self.check("power")

    def password(self, resource, password):
        self.calls.append(("password", resource))
        self.check("password")


class FreeInspector:
    def check(self, protocol, port):
        pass


@pytest.fixture
def config(tmp_path):
    return Config(
        mode="controller",
        domain_suffix="i3alumba.ru",  # Isolated legacy-shaped fixtures, not operator DNS policy.
        database=str(tmp_path / "state.sqlite"),
        bind="127.0.0.1:8000",
        ca="unused",
        cert="unused",
        key="unused",
        gamma_ip="127.0.0.2",
        public_ip="127.0.0.1",
        public_port_ranges={"tcp": [[1024, 65535]], "udp": [[1024, 65535]]},
    )


@pytest.fixture
def controller(config):
    return Controller(config, Store(config.database), FakeAgent(), FakeAgent())


@pytest.fixture
def body():
    return {
        "name": "test-guest",
        "domain": "mc.i3alumba.ru",
        "cpu": 1,
        "memory_gb": 2,
        "root_password": "TransientSecret42!",
        "ports": [{"protocol": "tcp", "public_port": 2223, "target_port": 22}],
    }


@pytest.fixture
def spec():
    return {
        "id": str(uuid4()),
        "instance_id": str(uuid4()),
        "protocol": "tcp",
        "public_port": 2223,
        "target_port": 22,
    }
