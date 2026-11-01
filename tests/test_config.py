import json
from pathlib import Path

import pytest

from container_manager.config import Config


def test_controller_example_loads():
    config = Config.load("examples/controller.json")
    assert config.pool_cpu == 4 and config.pool_memory_gb == 16
    assert config.domain_suffix == "hosting.i3alumba.ru"
    assert config.public_port_ranges == {
        "tcp": [[3000, 50000]],
        "udp": [[3000, 50000]],
    }  # Explicitly confirmed operator forwarding, not a default.


@pytest.mark.parametrize(
    "address", ["0.0.0.0", "127.0.0.1", "203.0.113.5", "169.254.0.1", "224.0.0.1", "::"]
)
def test_agent_cannot_bind_wildcard_public_or_non_wg_address(tmp_path, address):
    data = json.loads(Path("examples/node.json").read_text())
    data.update(
        bind=f"{address}:9443",
        wireguard_ip=address,
        gamma_ip=address,
        host_addresses=[address],
        image_fingerprint="a" * 64,
    )
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        Config.load(str(path))


@pytest.mark.parametrize(
    "field,value",
    [
        ("pool_cpu", True),
        ("pool_memory_gb", True),
        ("domain_suffix", ["hosting.i3alumba.ru"]),
        ("reserved_ports", [True]),
        ("public_port_ranges", "all"),
        ("public_port_ranges", {"tcp": [[True, 65535]], "udp": []}),
        ("public_port_ranges", {"tcp": [[1, 65535]], "udp": []}),
        ("public_port_ranges", {"tcp": [[9000, 8000]], "udp": []}),
        ("public_port_ranges", {"tcp": [[8000, 65536]], "udp": []}),
        ("public_port_ranges", {"tcp": [[8000]], "udp": []}),
    ],
)
def test_operator_policy_requires_correct_types(tmp_path, field, value):
    data = json.loads(Path("examples/controller.json").read_text())
    data[field] = value
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        Config.load(str(path))
