import json
import socket

import pytest

from container_manager.errors import Failure
from container_manager.inspection import (
    Inspector,
    iptables_conflict,
    nft_conflict,
    port_match,
    run_read,
)

HOSTS = ["203.0.113.5", "10.200.73.2", "2001:db8::5"]


def rules(*lines):
    return (
        "*nat\n:PREROUTING ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        + "\n".join(lines)
        + "\nCOMMIT\n"
    )


@pytest.mark.parametrize(
    "spec,port,expected",
    [
        ("2222", 2222, True),
        ("2222:2230", 2225, True),
        ("2222-2230", 2225, True),
        ("2222,2230", 2225, False),
        ("2222:2230", 2231, False),
    ],
)
def test_port_ranges(spec, port, expected):
    assert port_match(spec, port) is expected


@pytest.mark.parametrize(
    "destination,expected",
    [
        ("0.0.0.0/0", True),
        ("203.0.113.5/32", True),
        ("10.43.0.5/32", False),
        ("::/0", True),
        ("2001:db8::5/128", True),
        ("fd00::5/128", False),
    ],
)
def test_iptables_public_vs_clusterip(destination, expected):
    text = rules(
        f"-A PREROUTING -d {destination} -p tcp --dport 2222 -j DNAT --to-destination 10.0.0.2:22"
    )
    assert iptables_conflict(text, "tcp", 2222, HOSTS) is expected
    assert not iptables_conflict(text, "udp", 2222, HOSTS)


def test_iptables_chained_clusterip_not_public_conflict():
    text = rules(
        "-A PREROUTING -j KUBE-SERVICES",
        "-A KUBE-SERVICES -d 10.43.0.1/32 -p tcp --dport 443 -j KUBE-SVC-X",
        "-A KUBE-SVC-X -m statistic --mode random --probability 0.5 -j DNAT --to-destination 10.42.0.5:6443",
    )
    assert not iptables_conflict(text, "tcp", 443, HOSTS)


def test_iptables_relevant_portset_failclosed():
    text = rules(
        "-A PREROUTING -p tcp -m set --match-set publicports dst -j DNAT --to-destination 10.0.0.2"
    )
    with pytest.raises(Failure, match="unsupported_relevant_nat_match"):
        iptables_conflict(text, "tcp", 2222, HOSTS)


def nft(expr, child=None):
    entries = [
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "prerouting",
                "type": "nat",
                "hook": "prerouting",
            }
        },
        {"rule": {"family": "ip", "table": "nat", "chain": "prerouting", "expr": expr}},
    ]
    if child:
        entries += [
            {"chain": {"family": "ip", "table": "nat", "name": "child"}},
            {"rule": {"family": "ip", "table": "nat", "chain": "child", "expr": child}},
        ]
    return json.dumps({"nftables": entries})


def match(field, right, protocol="tcp"):
    return {
        "match": {
            "op": "==",
            "left": {"payload": {"protocol": protocol, "field": field}},
            "right": right,
        }
    }


def test_nft_range_and_protocol():
    text = nft(
        [match("dport", {"range": [2222, 2230]}), {"dnat": {"addr": "10.0.0.2"}}]
    )
    assert nft_conflict(text, "tcp", 2225, HOSTS)
    assert not nft_conflict(text, "tcp", 2231, HOSTS)
    assert not nft_conflict(text, "udp", 2225, HOSTS)


def test_nft_chained_clusterip_excluded_before_portsets():
    text = nft(
        [{"jump": {"target": "child"}}],
        [
            match("daddr", "10.43.0.1", "ip"),
            match("dport", "@unknownset"),
            {"dnat": {"addr": "10.0.0.2"}},
        ],
    )
    assert not nft_conflict(text, "tcp", 2222, HOSTS)


@pytest.mark.parametrize(
    "expr",
    [
        [match("dport", "@ports"), {"dnat": {"addr": "10.0.0.2"}}],
        [{"vmap": {}}],
        [{"xt": {"type": "target", "name": "UNSUPPORTED"}}],
    ],
)
def test_nft_unknown_relevant_failclosed(expr):
    with pytest.raises(Failure):
        nft_conflict(nft(expr), "tcp", 2222, HOSTS)


def test_filter_chain_not_nat():
    text = json.dumps(
        {
            "nftables": [
                {
                    "chain": {
                        "family": "ip",
                        "table": "filter",
                        "name": "input",
                        "type": "filter",
                        "hook": "input",
                    }
                },
                {
                    "rule": {
                        "family": "ip",
                        "table": "filter",
                        "chain": "input",
                        "expr": [{"jump": {"target": "something"}}],
                    }
                },
            ]
        }
    )
    assert not nft_conflict(text, "tcp", 2222, HOSTS)


def test_real_local_listener_collision_tcp_udp():
    def reader(argv):
        if argv[0] == "cat":
            return run_read(argv)
        if argv[0] == "nft":
            return '{"nftables":[]}'
        return rules()

    inspector = Inspector(["127.0.0.1"], reader)
    for kind, protocol in ((socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")):
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.bind(("0.0.0.0", 0))
            if protocol == "tcp":
                sock.listen()
            with pytest.raises(Failure, match="host_listener_conflict"):
                inspector.check(protocol, sock.getsockname()[1])


def test_real_ipv6_wildcard():
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind(("::", 0))
        sock.listen()
    except OSError:
        pytest.skip("IPv6 unavailable")
    with sock, pytest.raises(Failure, match="host_listener_conflict"):
        Inspector(["::1"]).check("tcp", sock.getsockname()[1])


def test_introspection_denied_failclosed():
    def denied(argv):
        raise Failure("inspection_unavailable")

    with pytest.raises(Failure):
        Inspector(HOSTS, denied).check("tcp", 2222)


@pytest.mark.parametrize("text", ["{}", "nonsense", '{"nftables":null}'])
def test_unparseable_nft_failclosed(text):
    with pytest.raises(Failure):
        nft_conflict(text, "tcp", 2222, HOSTS)


def test_listener_readiness_is_binding_not_application_reachability():
    from container_manager.inspection import listener_ready

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        assert listener_ready("tcp", port, "127.0.0.1")
        assert not listener_ready("tcp", port, "127.0.0.2")


def test_firewall_sudo_has_exact_read_only_arguments():
    seen = []

    def reader(argv):
        seen.append(argv)
        if argv[0] == "cat":
            return "  sl local_address rem_address st\n"
        if argv[-1] == "ruleset":
            return '{"nftables":[]}'
        return rules()

    Inspector(HOSTS, reader, sudo=True).check("tcp", 2222)
    assert ["sudo", "-n", "/usr/sbin/iptables-save", "-t", "nat"] in seen
    assert ["sudo", "-n", "/usr/sbin/ip6tables-save", "-t", "nat"] in seen
    assert ["sudo", "-n", "/usr/sbin/nft", "-j", "list", "ruleset"] in seen


@pytest.mark.parametrize("target", ["MARK", "CONNMARK", "SNAT", "MASQUERADE", "RETURN"])
def test_iptables_verified_nonallocating_branch_with_source_negation(target):
    text = rules(
        "-A PREROUTING ! -s 10.42.0.0/16 -j SIDE",
        f"-A SIDE -j {target}",
    )
    assert not iptables_conflict(text, "tcp", 2223, HOSTS)


def test_iptables_nonallocating_branch_never_hides_later_dnat():
    text = rules(
        "-A PREROUTING -s 10.42.0.0/16 -j MARKING",
        "-A PREROUTING -p tcp --dport 2222 -j DNAT --to-destination 10.42.0.20:22",
        "-A MARKING -j MARK --set-xmark 0x4000/0x4000",
    )
    assert iptables_conflict(text, "tcp", 2222, HOSTS)
    assert not iptables_conflict(text, "udp", 2222, HOSTS)


def test_iptables_empty_declared_chain_is_not_unknown_target():
    assert not iptables_conflict(
        rules(":DOCKER - [0:0]", "-A PREROUTING -j DOCKER"), "tcp", 2223, HOSTS
    )
    with pytest.raises(Failure, match="unsupported_nat_target"):
        iptables_conflict(rules("-A PREROUTING -j UNDECLARED"), "tcp", 2223, HOSTS)


@pytest.mark.parametrize(
    "declaration", [":DOCKER", ":DOCKER - invalid", ":DOCKER ACCEPT [x:y]"]
)
def test_iptables_malformed_declarations_fail_closed(declaration):
    with pytest.raises(Failure, match="unparseable_nat_declaration"):
        iptables_conflict(rules(declaration), "tcp", 2223, HOSTS)


def test_iptables_unknown_match_on_allocating_branch_stays_closed():
    text = rules(
        "-A PREROUTING -m set --match-set unknown dst -j FORWARDING",
        "-A FORWARDING -p tcp --dport 2223 -j DNAT --to-destination 10.42.0.20:22",
    )
    with pytest.raises(Failure, match="unsupported_relevant_nat_match"):
        iptables_conflict(text, "tcp", 2223, HOSTS)


@pytest.mark.parametrize("comment", ["-p", "--dport", "!", "-j", "--match-set"])
def test_iptables_comment_values_cannot_become_predicates(comment):
    text = rules(
        f'-A PREROUTING -m comment --comment "{comment}" -p tcp --dport 2223 -j DNAT --to-destination 10.42.0.20:22'
    )
    assert iptables_conflict(text, "tcp", 2223, HOSTS)


@pytest.mark.parametrize("port", [2223, 5432, 8000])
def test_representative_kube_cni_empty_docker_dialects_free(port):
    from pathlib import Path

    root = Path(__file__).parent / "fixtures"
    hosts = ["198.51.100.10", "10.200.0.1"]
    text = (root / "iptables-kube-cni.nat").read_text()
    native = (root / "nft-kube-cni.json").read_text()
    for protocol in ("tcp", "udp"):
        assert not iptables_conflict(text, protocol, port, hosts)
        assert not nft_conflict(native, protocol, port, hosts)


def test_representative_kube_service_dnat_cannot_be_hidden_by_mark_branch():
    from pathlib import Path

    root = Path(__file__).parent / "fixtures"
    hosts = ["198.51.100.10", "10.200.0.1"]
    for filename, parser in (
        ("iptables-kube-cni.nat", iptables_conflict),
        ("nft-kube-cni.json", nft_conflict),
    ):
        text = (root / filename).read_text()
        assert parser(text, "tcp", 2222, hosts)
        assert not parser(text, "udp", 2222, hosts)


def test_nft_unknown_predicate_projection_only_for_proven_nonallocating_branch():
    opaque = {"xt": {"type": "match", "name": "multiport"}}
    jump = {"jump": {"target": "child"}}
    text = nft(
        [opaque, jump],
        [match("dport", 2222), {"xt": {"type": "target", "name": "DNAT"}}],
    )
    assert not nft_conflict(text, "tcp", 2223, HOSTS)
    with pytest.raises(Failure, match="unsupported_relevant_nft_rule"):
        nft_conflict(text, "tcp", 2222, HOSTS)


@pytest.mark.parametrize(
    "unknown",
    [
        match("dport", "@ports"),
        {
            "match": {
                "op": "==",
                "left": {"meta": {"key": "l4proto"}},
                "right": {"set": ["tcp", "udp"]},
            }
        },
    ],
)
def test_nft_relevant_unknown_sets_on_allocating_branch_fail_closed(unknown):
    text = nft(
        [unknown, {"jump": {"target": "child"}}], [{"dnat": {"addr": "10.42.0.20"}}]
    )
    with pytest.raises(Failure, match="unsupported_relevant_nft_rule"):
        nft_conflict(text, "tcp", 2223, HOSTS)


@pytest.mark.parametrize(
    "effect",
    [
        {"vmap": {}},
        {"map": {}},
        {"mangle": {}},
        {"xt": {"type": "target", "name": "UNKNOWN"}},
        {"xt": {"type": "match", "name": "bpf"}},
    ],
)
def test_nft_unknown_effect_not_projected_through_empty_child(effect):
    text = nft([effect, {"jump": {"target": "child"}}], [{"return": None}])
    with pytest.raises(Failure, match="unsupported_relevant_nft_rule"):
        nft_conflict(text, "tcp", 2223, HOSTS)


def test_nft_compat_dnat_is_a_real_destination_allocation():
    assert nft_conflict(
        nft([match("dport", 2223), {"xt": {"type": "target", "name": "DNAT"}}]),
        "tcp",
        2223,
        HOSTS,
    )
