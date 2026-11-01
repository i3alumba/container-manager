"""Operator-approved forwarded span and single-label hosting-domain boundaries."""

from dataclasses import replace

import pytest

from conftest import FakeAgent
from container_manager.config import Config
from container_manager.controller import Controller
from container_manager.errors import Failure
from container_manager.models import Check, Create
from container_manager.store import Store


@pytest.fixture
def hosting(config):
    policy = replace(
        config,
        domain_suffix="hosting.i3alumba.ru",
        public_port_ranges={"tcp": [[3000, 50000]], "udp": [[3000, 50000]]},
    )
    return Controller(policy, Store(policy.database), FakeAgent(), FakeAgent())


def test_defaults_never_assume_gateway_port_ownership():
    config = Config(mode="controller", database="", bind="", ca="", cert="", key="")
    assert config.public_port_ranges == {"tcp": [], "udp": []}
    assert config.domain_suffix == "hosting.i3alumba.ru"


@pytest.mark.parametrize("label", ["mc", "build-2", "build--2", "3", "a" * 63])
def test_any_single_valid_label_can_be_selected(hosting, label, body):
    domain = f"{label}.hosting.i3alumba.ru"
    assert hosting.config.domain_allowed(domain)
    body.update(domain=domain, ports=[])
    assert hosting.create(Create(**body), "admin")["domain"] == domain


@pytest.mark.parametrize(
    "domain",
    [
        "hosting.i3alumba.ru",
        "mc.i3alumba.ru",
        "mc.hosting.i3alumba.ru.evil.test",
        "a.b.hosting.i3alumba.ru",
        "-bad.hosting.i3alumba.ru",
        "bad-.hosting.i3alumba.ru",
        "UPPER.hosting.i3alumba.ru",
        "https://mc.hosting.i3alumba.ru",
        "*.hosting.i3alumba.ru",
        "a" * 64 + ".hosting.i3alumba.ru",
    ],
)
def test_domain_scope_cannot_be_escaped(hosting, domain):
    assert not hosting.config.domain_allowed(domain)


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("port", [2999, 50001])
def test_outside_forwarded_span_never_says_free_or_mutates_hosts(
    hosting, body, protocol, port
):
    result = hosting.check(Check(protocol=protocol, public_port=port))
    assert result["available"] is False
    assert result["reason"] == "external_ingress_not_configured"
    body.update(
        domain="mc.hosting.i3alumba.ru",
        ports=[{"protocol": protocol, "public_port": port, "target_port": 22}],
    )
    with pytest.raises(Failure, match="external_ingress_not_configured"):
        hosting.create(Create(**body), "admin")
    assert hosting.store.instances() == []
    assert hosting.node.calls == hosting.relay.calls == []


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("port", [3000, 3001, 5432, 8000, 25565, 50000])
def test_forwarded_ports_still_require_both_actual_host_inspections(
    hosting, protocol, port
):
    request = Check(protocol=protocol, public_port=port)
    assert hosting.check(request)["available"] is True
    hosting.node.available = False
    assert hosting.check(request)["available"] is False


@pytest.mark.parametrize(
    "port",
    [
        5000,
        5187,
        6443,
        6444,
        8090,
        8472,
        9443,
        9444,
        9445,
        10010,
        10248,
        10249,
        10250,
        10256,
        10258,
        30000,
        32767,
    ],
)
def test_forwarding_does_not_make_infrastructure_allocatable(hosting, port):
    assert hosting.check(Check(protocol="tcp", public_port=port))["available"] is False


def test_selected_subdomain_is_preserved_without_changing_guest_identity_policy(
    hosting, body
):
    body.update(
        domain="build-2.hosting.i3alumba.ru",
        ports=[{"protocol": "tcp", "public_port": 3001, "target_port": 22}],
    )
    guest = hosting.create(Create(**body), "admin")
    assert guest["domain"] == "build-2.hosting.i3alumba.ru"
    assert guest["name"] == body["name"]
    assert guest["ports"][0]["public_port"] == 3001
