"""Operator guard is additive/idempotent and refuses misplaced or duplicate hooks."""

import importlib.util
import ipaddress
from pathlib import Path
import shlex

import pytest

spec = importlib.util.spec_from_file_location(
    "network_guard", Path(__file__).parents[1] / "examples/network-guard.py"
)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class Firewall:
    def __init__(self):
        self.rules = {
            "INPUT": [["-j", "OLD"]],
            "FORWARD": [["-j", "ACCEPT"]],
            "OUTPUT": [],
            "OLD": [["-j", "ACCEPT"]],
        }
        self.mutations = []

    def snapshot(self):
        lines = ["-P INPUT ACCEPT", "-P FORWARD DROP", "-P OUTPUT ACCEPT"]
        lines += [
            "-N " + name
            for name in self.rules
            if name not in {"INPUT", "FORWARD", "OUTPUT"}
        ]
        lines += [
            shlex.join(["-A", name, *rule])
            for name, entries in self.rules.items()
            for rule in entries
        ]
        return "\n".join(lines) + "\n"

    def __call__(self, args):
        if args == ["-S"]:
            return self.snapshot()
        self.mutations.append(args)
        if args[0] == "-N":
            assert args[1] not in self.rules
            self.rules[args[1]] = []
        elif args[0] == "-A":
            self.rules[args[1]].append(args[2:])
        elif args[:3] == ["-I", "INPUT", "1"]:
            self.rules["INPUT"].insert(0, args[3:])
        else:
            raise AssertionError("Unexpected mutation: " + repr(args))
        return ""


@pytest.fixture(params=["alpha", "gamma"])
def policy(request):
    return {
        "role": request.param,
        "pod_cidr": "10.42.0.0/24",
        "reserved_ports": [5000, 6443, 6444, 7946, 9443, 9444, 10010, 10250],
    }


def test_fresh_and_exact_repeat_preserve_all_old_rules(policy):
    firewall = Firewall()
    before = guard.parse(firewall.snapshot())[1]
    assert guard.ensure(policy, firewall)
    chains, hooks = guard.policy(policy)
    assert firewall.rules["INPUT"] == hooks + before["INPUT"]
    assert all(
        firewall.rules[name] == rules
        for name, rules in before.items()
        if name != "INPUT"
    )
    firewall.mutations.clear()
    assert guard.ensure(policy, firewall) is False
    assert firewall.mutations == []
    if policy["role"] == "gamma":
        assert all("3000:29999,32768:50000" in hook for hook in hooks[1:])
        assert chains["PPUBUNTU_PROXY"][-2:] == [
            ["-s", "10.200.73.1/32", "-j", "RETURN"],
            ["-j", "DROP"],
        ]


@pytest.mark.parametrize(
    "drift", ["duplicate", "below_accept", "missing_hook", "chain_rule", "partial"]
)
def test_drift_refused_before_any_further_mutation(policy, drift):
    firewall = Firewall()
    guard.ensure(policy, firewall)
    if drift == "duplicate":
        firewall.rules["INPUT"].append(list(firewall.rules["INPUT"][0]))
    elif drift == "below_accept":
        firewall.rules["INPUT"].insert(0, ["-j", "ACCEPT"])
    elif drift == "missing_hook":
        firewall.rules["INPUT"].pop(0)
    elif drift == "chain_rule":
        firewall.rules["PPUBUNTU_RPC"].insert(0, ["-j", "ACCEPT"])
    else:
        firewall.rules["INPUT"] = [["-j", "OLD"]]
    firewall.mutations.clear()
    with pytest.raises(RuntimeError, match="drift"):
        guard.ensure(policy, firewall)
    assert firewall.mutations == []


def test_inspection_failure_never_becomes_absence(policy):
    calls = []

    def denied(args):
        calls.append(args)
        raise RuntimeError("inspection failed")

    with pytest.raises(RuntimeError, match="inspection failed"):
        guard.ensure(policy, denied)
    assert calls == [["-S"]]


REPLY_RETURN = [
    "-m",
    "conntrack",
    "--ctstate",
    "ESTABLISHED",
    "--ctdir",
    "REPLY",
    "-j",
    "RETURN",
]


def gamma_config():
    return {
        "role": "gamma",
        "pod_cidr": "10.42.0.0/24",
        "reserved_ports": [5000, 6443, 9443, 9444],
    }


def proxy_verdict(protocol, state, direction, incumbent):
    """Evaluate only the actual guarded-chain predicates, never kernel proof."""
    chains, _ = guard.policy(gamma_config())
    for rule in chains["PPUBUNTU_PROXY"]:
        assert set(rule[::2]) <= {
            "-m",
            "--ctstate",
            "--ctdir",
            "-p",
            "--dports",
            "-s",
            "-j",
        }
        options = dict(zip(rule[::2], rule[1::2]))
        if "-p" in options and options["-p"] != protocol:
            continue
        if "--ctstate" in options and options["--ctstate"] != state:
            continue
        if "--ctdir" in options and options["--ctdir"] != direction:
            continue
        if "--dports" in options and "8000" not in options["--dports"].split(","):
            continue
        if "-s" in options and ipaddress.ip_address(
            "10.200.73.3"
        ) not in ipaddress.ip_network(options["-s"]):
            continue
        assert options["-j"] in {"RETURN", "DROP"}
        return incumbent if options["-j"] == "RETURN" else "DROP"
    raise AssertionError("Missing terminal verdict")


def test_exact_reply_rule_is_gamma_only():
    config = gamma_config()
    chains, _ = guard.policy(config)
    assert chains["PPUBUNTU_PROXY"][0] == REPLY_RETURN
    assert chains["PPUBUNTU_PROXY"].count(REPLY_RETURN) == 1
    alpha, _ = guard.policy({**config, "role": "alpha"})
    assert set(alpha) == {"PPUBUNTU_RPC"}
    assert alpha["PPUBUNTU_RPC"] == chains["PPUBUNTU_RPC"]


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize(
    "state,direction",
    [
        ("NEW", "ORIGINAL"),
        ("ESTABLISHED", "ORIGINAL"),
        ("RELATED", "REPLY"),
        ("INVALID", "REPLY"),
        ("UNTRACKED", "REPLY"),
    ],
)
def test_nonalpha_ingress_does_not_gain_reply_exception(protocol, state, direction):
    assert proxy_verdict(protocol, state, direction, "ACCEPT") == "DROP"


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
@pytest.mark.parametrize("incumbent", ["ACCEPT", "DROP"])
def test_established_reply_obeys_incumbent_policy(protocol, incumbent):
    assert proxy_verdict(protocol, "ESTABLISHED", "REPLY", incumbent) == incumbent


@pytest.mark.parametrize("fault", ["duplicate", "misplaced"])
def test_reply_rule_drift_never_gets_automatic_repair(fault):
    firewall = Firewall()
    config = gamma_config()
    guard.ensure(config, firewall)
    rules = firewall.rules["PPUBUNTU_PROXY"]
    if fault == "duplicate":
        rules.insert(0, list(REPLY_RETURN))
    else:
        rules.append(rules.pop(0))
    firewall.mutations.clear()
    with pytest.raises(RuntimeError, match="drift"):
        guard.ensure(config, firewall)
    assert firewall.mutations == []


def local_pod(config):
    return "10.42.0.0/24" if config["role"] == "gamma" else "10.42.1.0/24"


def installed_prefix(config, root_rules=None):
    """Synthetic structural graph only; no host/workload snapshots."""
    firewall = Firewall()
    guard.ensure(config, firewall)
    firewall.rules["INPUT"].insert(0, list(guard.K3S_PREFIX))
    firewall.rules["KUBE-ROUTER-INPUT"] = (
        [["-j", "RETURN"]] if root_rules is None else root_rules
    )
    firewall.mutations.clear()
    return firewall


def assert_refused(config, firewall):
    with pytest.raises(RuntimeError):
        guard.ensure(config, firewall)
    assert firewall.mutations == []


def test_synthetic_observed_graph_both_roles_preserves_exact_packet_policy(policy):
    firewall = installed_prefix(
        policy,
        [
            [
                "-s",
                local_pod(policy),
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
            [
                "-d",
                local_pod(policy),
                "-m",
                "comment",
                "--comment",
                "synthetic Pod destination",
                "-j",
                "SYNTHETIC-POLICY",
            ],
            *[
                ["-p", "icmp", "-m", "icmp", "--icmp-type", kind, "-j", "ACCEPT"]
                for kind in ["8", "3", "11"]
            ],
            [
                "-m",
                "addrtype",
                "--src-type",
                "LOCAL",
                "--dst-type",
                "LOCAL",
                "-j",
                "SYNTHETIC-LOG",
            ],
            ["-m", "mark", "!", "--mark", "0x10000/0x10000", "-j", "RETURN"],
        ],
    )
    firewall.rules["SYNTHETIC-POLICY"] = [
        ["-j", "MARK", "--set-xmark", "0x10000/0x10000"],
        [
            "-m",
            "comment",
            "--comment",
            "ACCEPT after mark and RETURN is still scanned",
            "-j",
            "RETURN",
        ],
        ["-j", "ACCEPT"],
    ]
    firewall.rules["SYNTHETIC-LOG"] = [
        [
            "-m",
            "limit",
            "--limit",
            "10/min",
            "--limit-burst",
            "10",
            "-j",
            "NFLOG",
            "--nflog-group",
            "100",
        ],
        ["-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
    ]
    # Outside prefix reachability, opaque incumbent grammar is preserved, not
    # treated as a proof or rewritten by the standalone helper.
    firewall.rules["FORWARD"].append(
        ["-m", "recent", "--rcheck", "--name", "synthetic", "-j", "ACCEPT"]
    )
    before = guard.ordered_records(firewall.snapshot())
    assert guard.ensure(policy, firewall) is False
    assert firewall.mutations == []
    assert guard.ordered_records(firewall.snapshot()) == before
    if policy["role"] == "alpha":
        assert "PPUBUNTU_PROXY" not in firewall.rules
    # Controller RPC allowlist is identical for both roles, not alpha-local.
    assert firewall.rules["PPUBUNTU_RPC"][0] == ["-s", "10.42.0.0/24", "-j", "ACCEPT"]


@pytest.mark.parametrize(
    "fault",
    [
        "foreign-prefix",
        "duplicate-prefix",
        "moved-hook",
        "missing-hook",
        "duplicate-hook",
        "extra-reference",
        "long-jump-reference",
        "goto-reference",
    ],
)
def test_prefixed_attachment_drift_refuses_without_mutation(policy, fault):
    firewall = installed_prefix(policy)
    if fault == "foreign-prefix":
        firewall.rules["INPUT"][0][3] = "untrusted comment"
    elif fault == "duplicate-prefix":
        firewall.rules["INPUT"].append(list(guard.K3S_PREFIX))
    elif fault == "moved-hook":
        firewall.rules["INPUT"].insert(1, ["-j", "OLD"])
    elif fault == "missing-hook":
        firewall.rules["INPUT"].pop(1)
    elif fault == "duplicate-hook":
        firewall.rules["INPUT"].append(list(firewall.rules["INPUT"][1]))
    else:
        firewall.rules["OLD"].append(
            [
                {
                    "extra-reference": "-j",
                    "long-jump-reference": "--jump",
                    "goto-reference": "-g",
                }[fault],
                "PPUBUNTU_RPC",
            ]
        )
    assert_refused(policy, firewall)


def test_exact_k3s_hook_is_not_itself_a_proof(policy):
    firewall = installed_prefix(policy, [["-j", "ACCEPT"]])
    assert_refused(policy, firewall)


def test_fresh_prefix_missing_owned_hooks_is_never_automatically_installed(policy):
    firewall = Firewall()
    firewall.rules["INPUT"].insert(0, list(guard.K3S_PREFIX))
    firewall.rules["KUBE-ROUTER-INPUT"] = [["-j", "RETURN"]]
    assert_refused(policy, firewall)


def test_comments_are_opaque_not_owned_jump_references(policy):
    firewall = installed_prefix(
        policy, [["-m", "comment", "--comment", "-j PPUBUNTU_RPC", "-j", "RETURN"]]
    )
    firewall.rules["OLD"].append(
        ["-m", "comment", "--comment", "PPUBUNTU_RPC", "-j", "RETURN"]
    )
    assert guard.ensure(policy, firewall) is False
    assert firewall.mutations == []


@pytest.mark.parametrize("states", ["ESTABLISHED", "RELATED", "ESTABLISHED,RELATED"])
def test_only_local_role_pod_state_exception_is_accepted(policy, states):
    firewall = installed_prefix(
        policy,
        [
            [
                "-s",
                local_pod(policy),
                "-m",
                "conntrack",
                "--ctstate",
                states,
                "-j",
                "ACCEPT",
            ]
        ],
    )
    assert guard.ensure(policy, firewall) is False


@pytest.mark.parametrize(
    "fault",
    [
        "swapped-pod",
        "nonlocal",
        "no-source",
        "new",
        "mixed-new",
        "no-state",
        "unconditional",
        "broad-pod",
    ],
)
def test_overlapping_accept_has_no_broad_state_or_source_exception(policy, fault):
    source = local_pod(policy)
    if fault == "swapped-pod":
        source = "10.42.1.0/24" if policy["role"] == "gamma" else "10.42.0.0/24"
    elif fault == "nonlocal":
        source = "192.0.2.0/24"
    elif fault == "broad-pod":
        source = "10.42.0.0/16"
    states = (
        "NEW"
        if fault == "new"
        else "NEW,ESTABLISHED" if fault == "mixed-new" else "ESTABLISHED,RELATED"
    )
    rule = [] if fault in {"no-source", "unconditional"} else ["-s", source]
    if fault not in {"no-state", "unconditional"}:
        rule += ["-m", "conntrack", "--ctstate", states]
    firewall = installed_prefix(policy, [rule + ["-j", "ACCEPT"]])
    assert_refused(policy, firewall)


@pytest.mark.parametrize(
    "predicate",
    [
        ["-d", "10.42.0.0/16"],
        ["-p", "icmp", "-m", "icmp", "--icmp-type", "8"],
        ["-p", "tcp", "-m", "multiport", "--dports", "1:2999,50001:65535"],
    ],
)
def test_disjoint_destination_protocol_and_port_accepts(policy, predicate):
    firewall = installed_prefix(policy, [predicate + ["-j", "ACCEPT"]])
    assert guard.ensure(policy, firewall) is False


@pytest.mark.parametrize(
    "protocol,port",
    [("tcp", "8000"), ("udp", "8000"), ("tcp", "9443"), ("tcp", "9444")],
)
def test_protected_classes_are_role_specific(policy, protocol, port):
    address = "10.200.73.2/32" if policy["role"] == "gamma" else "10.200.73.1/32"
    rule = [
        "-d",
        address,
        "-p",
        protocol,
        "-m",
        protocol,
        "--dport",
        port,
        "-j",
        "ACCEPT",
    ]
    firewall = installed_prefix(policy, [rule])
    protected = (policy["role"] == "gamma" and port == "8000") or (
        protocol == "tcp" and port == ("9443" if policy["role"] == "gamma" else "9444")
    )
    if protected:
        assert_refused(policy, firewall)
    else:
        assert guard.ensure(policy, firewall) is False


@pytest.mark.parametrize(
    "port", ["3000", "29999", "32768", "50000", "2999:3001", "49999:50001"]
)
@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_gamma_proxy_span_overlap_is_not_hidden_by_range(protocol, port):
    config = gamma_config()
    firewall = installed_prefix(
        config, [["-p", protocol, "-m", "multiport", "--dports", port, "-j", "ACCEPT"]]
    )
    assert_refused(config, firewall)


@pytest.mark.parametrize("port", ["5000", "30000:32767", "2999", "50001"])
def test_gamma_infrastructure_and_nodeport_exclusions_remain_incumbent(port):
    config = gamma_config()
    firewall = installed_prefix(
        config, [["-p", "udp", "-m", "multiport", "--dports", port, "-j", "ACCEPT"]]
    )
    assert guard.ensure(config, firewall) is False


@pytest.mark.parametrize("terminal", ["RETURN", "DROP", "REJECT", "NFLOG", "MARK"])
def test_later_child_accept_is_not_pruned_by_prior_verdict(policy, terminal):
    effect = (
        ["--set-xmark", "1/1"]
        if terminal == "MARK"
        else ["--nflog-group", "0"] if terminal == "NFLOG" else []
    )
    firewall = installed_prefix(
        policy, [["-j", terminal, *effect], ["-j", "HIDDEN-CHILD"]]
    )
    firewall.rules["HIDDEN-CHILD"] = [["-j", "RETURN"], ["-j", "ACCEPT"]]
    assert_refused(policy, firewall)


def test_child_return_never_terminates_later_caller_accept(policy):
    firewall = installed_prefix(policy, [["-j", "CHILD"], ["-j", "ACCEPT"]])
    firewall.rules["CHILD"] = [["-j", "RETURN"]]
    assert_refused(policy, firewall)


def test_shared_child_is_checked_under_both_call_contexts(policy):
    firewall = installed_prefix(
        policy,
        [
            [
                "-s",
                local_pod(policy),
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED",
                "-j",
                "SHARED",
            ],
            [
                "-s",
                "192.0.2.0/24",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED",
                "-j",
                "SHARED",
            ],
        ],
    )
    firewall.rules["SHARED"] = [["-j", "ACCEPT"]]
    assert_refused(policy, firewall)


def test_positive_predicates_intersect_across_paths(policy):
    firewall = installed_prefix(
        policy,
        [
            [
                "-s",
                local_pod(policy),
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "CHILD",
            ]
        ],
    )
    firewall.rules["CHILD"] = [
        [
            "-s",
            local_pod(policy).replace("0/24", "128/25"),
            "-m",
            "conntrack",
            "--ctstate",
            "RELATED",
            "-j",
            "ACCEPT",
        ]
    ]
    assert guard.ensure(policy, firewall) is False


@pytest.mark.parametrize(
    "unknown",
    [
        ["-m", "mark", "!", "--mark", "1/1"],
        ["-m", "addrtype", "--dst-type", "LOCAL"],
        ["-m", "limit", "--limit", "10/min", "--limit-burst", "10"],
    ],
)
def test_unknown_predicates_cannot_narrow_unsafe_accept(policy, unknown):
    firewall = installed_prefix(policy, [unknown + ["-j", "ACCEPT"]])
    assert_refused(policy, firewall)


@pytest.mark.parametrize(
    "rule",
    [
        ["-j", "CONNMARK", "--restore-mark"],
        ["-j", "CT"],
        ["-j", "DNAT"],
        ["-m", "set", "--match-set", "unknown", "-j", "ACCEPT"],
        ["!", "-s", "10.42.0.0/24", "-j", "ACCEPT"],
        ["-p", "!", "tcp", "-j", "ACCEPT"],
        ["-m", "conntrack", "!", "--ctstate", "NEW", "-j", "ACCEPT"],
        ["!", "-m", "mark", "--mark", "1/1", "-j", "RETURN"],
        ["-m", "mark", "!", "!", "--mark", "1/1", "-j", "RETURN"],
        ["-s", "::/0", "-j", "RETURN"],
        ["-s", "not-ip", "-j", "RETURN"],
        ["-p", "sctp", "-j", "RETURN"],
        ["-p", "tcp", "-p", "tcp", "-j", "RETURN"],
        ["-m", "comment", "-m", "comment", "--comment", "x", "-j", "RETURN"],
        ["-m", "conntrack", "--ctstate", "SNAT", "-j", "RETURN"],
        ["-m", "conntrack", "--ctstate", "ESTABLISHED,ESTABLISHED", "-j", "RETURN"],
        ["-p", "tcp", "-m", "multiport", "--dports", "8000:7000", "-j", "RETURN"],
        ["-p", "tcp", "-m", "multiport", "--dports", "65536", "-j", "RETURN"],
        ["-p", "tcp", "-m", "tcp", "--dport", "22,23", "-j", "RETURN"],
        ["-m", "mark", "--mark", "no-mark", "-j", "RETURN"],
        ["-m", "mark", "--mark", "0x100000000/1", "-j", "RETURN"],
        ["-m", "addrtype", "--dst-type", "MULTICAST", "-j", "RETURN"],
        ["-m", "limit", "--limit", "0/min", "-j", "RETURN"],
        ["-m", "limit", "--limit-burst", "0", "-j", "RETURN"],
        ["-p", "icmp", "-m", "icmp", "--icmp-type", "256", "-j", "RETURN"],
        ["-j", "NFLOG", "--nflog-group", "65536"],
        ["-j", "REJECT", "--reject-with", "tcp-reset"],
        ["-j", "MARK"],
        ["-j", "ACCEPT", "--set-xmark", "1/1"],
        ["-g", "CHILD"],
        ["--goto", "CHILD"],
        ["-j", "INPUT"],
        ["-j", "MISSING"],
        ["-j", "RETURN", "--unknown", "1"],
    ],
)
def test_unknown_or_malformed_reachable_grammar_fails_even_after_return(policy, rule):
    firewall = installed_prefix(policy, [["-j", "RETURN"], rule])
    firewall.rules["CHILD"] = [["-j", "RETURN"]]
    assert_refused(policy, firewall)


def test_reachable_cycle_is_not_pruned_even_on_disjoint_path(policy):
    firewall = installed_prefix(policy, [["-p", "icmp", "-j", "CHILD"]])
    firewall.rules["CHILD"] = [["-j", "KUBE-ROUTER-INPUT"]]
    assert_refused(policy, firewall)


def test_unreachable_opaque_effects_never_become_proof(policy):
    firewall = installed_prefix(policy)
    firewall.rules["OPAQUE"] = [["-j", "UNKNOWN-EFFECT", "--opaque", "value"]]
    assert guard.ensure(policy, firewall) is False
    firewall.rules["KUBE-ROUTER-INPUT"] = [["-j", "OPAQUE"]]
    assert_refused(policy, firewall)


@pytest.mark.parametrize(
    "bad",
    [
        "-P INPUT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n",
        "-P INPUT UNKNOWN\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n",
        "-P INPUT ACCEPT\n-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n",
        "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-N DUP\n-N DUP\n",
        "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A MISSING -j ACCEPT\n",
        "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT -j ACCEPT -j DROP\n",
        "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-A INPUT --comment 'unterminated\n",
        "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n-F INPUT\n",
    ],
)
def test_complete_snapshot_parser_refuses_malformed_records(bad):
    with pytest.raises(RuntimeError):
        guard.parse_snapshot(bad)


@pytest.mark.parametrize(
    "limit", ["MAX_SNAPSHOT_BYTES", "MAX_RECORDS", "MAX_TOKENS", "MAX_TOKEN_BYTES"]
)
def test_whole_snapshot_budget_exact_boundary_and_exhaustion(monkeypatch, limit):
    snapshot = Firewall().snapshot()
    parsed = guard.parse_snapshot(snapshot)
    used = {
        "MAX_SNAPSHOT_BYTES": len(snapshot.encode()),
        "MAX_RECORDS": len(parsed["records"]),
        "MAX_TOKENS": sum(map(len, parsed["records"])),
        "MAX_TOKEN_BYTES": max(
            len(token.encode()) for record in parsed["records"] for token in record
        ),
    }[limit]
    monkeypatch.setattr(guard, limit, used)
    assert guard.parse_snapshot(snapshot)["records"] == parsed["records"]
    monkeypatch.setattr(guard, limit, used - 1)
    with pytest.raises(RuntimeError):
        guard.parse_snapshot(snapshot)


@pytest.mark.parametrize("limit", ["chains", "rules", "depth", "contexts"])
def test_graph_budget_actual_boundary_and_exhaustion(limit):
    config = gamma_config()
    if limit == "chains":
        firewall = installed_prefix(config, [["-j", f"C{i}"] for i in range(63)])
        for index in range(63):
            firewall.rules[f"C{index}"] = [["-j", "RETURN"]]
        extend = lambda: (
            firewall.rules["KUBE-ROUTER-INPUT"].append(["-j", "EXTRA"]),
            firewall.rules.update(EXTRA=[["-j", "RETURN"]]),
        )
    elif limit == "rules":
        firewall = installed_prefix(
            config,
            [
                ["-m", "comment", "--comment", str(index), "-j", "RETURN"]
                for index in range(2048)
            ],
        )
        extend = lambda: firewall.rules["KUBE-ROUTER-INPUT"].append(
            ["-m", "comment", "--comment", "extra", "-j", "RETURN"]
        )
    elif limit == "depth":
        firewall = installed_prefix(config, [["-j", "D1"]])
        for index in range(1, 32):
            firewall.rules[f"D{index}"] = [
                ["-j", "RETURN" if index == 31 else f"D{index + 1}"]
            ]
        extend = lambda: (
            firewall.rules.update(D31=[["-j", "EXTRA"]]),
            firewall.rules.update(EXTRA=[["-j", "RETURN"]]),
        )
    else:
        # One root context + 1365*(root-rule, child-entry, child-rule) = 4096.
        firewall = installed_prefix(
            config,
            [
                ["-m", "comment", "--comment", str(index), "-j", "LEAF"]
                for index in range(1365)
            ],
        )
        firewall.rules["LEAF"] = [["-j", "RETURN"]]
        extend = lambda: firewall.rules["KUBE-ROUTER-INPUT"].append(
            ["-m", "comment", "--comment", "extra", "-j", "LEAF"]
        )
    assert guard.ensure(config, firewall) is False
    extend()
    assert_refused(config, firewall)


def test_policy_values_and_record_order_are_preservation_evidence(policy):
    firewall = Firewall()
    before = firewall.snapshot()
    changed = before.replace("-P FORWARD DROP", "-P FORWARD ACCEPT")
    assert guard.parse(before) == guard.parse(changed)  # old tuple API lacks values
    assert guard.ordered_records(before) != guard.ordered_records(changed)
    original = firewall.__call__

    def concurrent_policy_change(args):
        result = original(args)
        return (
            result.replace("-P FORWARD DROP", "-P FORWARD ACCEPT")
            if args == ["-S"] and firewall.mutations
            else result
        )

    with pytest.raises(RuntimeError, match="concurrently"):
        guard.ensure(policy, concurrent_policy_change)


def test_old_reply_missing_refuses_normal_ensure_but_manual_readonly_classify_works():
    config = gamma_config()
    firewall = installed_prefix(config)
    chains, hooks = guard.policy(config)
    firewall.rules["PPUBUNTU_PROXY"].pop(0)
    old_chains = {name: rules for name, rules in chains.items()}
    old_chains["PPUBUNTU_PROXY"] = chains["PPUBUNTU_PROXY"][1:]
    before = guard.ordered_records(firewall.snapshot())
    assert guard.classify(firewall.snapshot(), old_chains, hooks, config) == "installed"
    assert_refused(config, firewall)
    assert guard.ordered_records(firewall.snapshot()) == before
    # Exposed records permit a root operator to fence precisely one insertion;
    # this test mutates ONLY the synthetic model, never a real firewall.
    firewall.rules["PPUBUNTU_PROXY"].insert(0, list(REPLY_RETURN))
    after = guard.ordered_records(firewall.snapshot())
    insertion = after.index(("-A", "PPUBUNTU_PROXY", *REPLY_RETURN))
    assert after[:insertion] + after[insertion + 1 :] == before
    assert guard.ensure(config, firewall) is False


def test_reachable_unknown_effect_after_disjoint_accept_still_refuses(policy):
    firewall = installed_prefix(
        policy,
        [
            ["-p", "icmp", "-j", "ACCEPT"],
            ["-j", "CT"],
        ],
    )
    assert_refused(policy, firewall)


def test_snapshot_invalid_unicode_is_not_a_partial_inspection():
    with pytest.raises(RuntimeError):
        guard.parse_snapshot(Firewall().snapshot() + "\ud800")


def test_proof_limits_are_fixed_not_caller_overrides():
    assert (
        guard.MAX_SNAPSHOT_BYTES,
        guard.MAX_RECORDS,
        guard.MAX_TOKENS,
        guard.MAX_TOKEN_BYTES,
    ) == (4194304, 65536, 262144, 4096)
    assert (guard.MAX_CHAINS, guard.MAX_RULES, guard.MAX_DEPTH, guard.MAX_CONTEXTS) == (
        64,
        2048,
        32,
        4096,
    )


def test_overlapping_port_lists_are_normalized_before_path_intersection(policy):
    firewall = installed_prefix(
        policy,
        [
            [
                "-p",
                "tcp",
                "-m",
                "multiport",
                "--dports",
                "1:1000,1:1000,1:1000",
                "-j",
                "CHILD",
            ]
        ],
    )
    firewall.rules["CHILD"] = [
        ["-p", "tcp", "-m", "multiport", "--dports", "900:950,900:950", "-j", "ACCEPT"]
    ]
    assert guard.ensure(policy, firewall) is False


def test_controller_cidr_cannot_be_replaced_by_alpha_local_proof_domain():
    calls = []
    with pytest.raises(ValueError, match="topology"):
        guard.ensure(
            {"role": "alpha", "pod_cidr": "10.42.1.0/24", "reserved_ports": []},
            lambda args: calls.append(args),
        )
    assert calls == []


@pytest.mark.parametrize("limit", ["bytes", "records", "tokens", "token-bytes"])
def test_actual_whole_snapshot_limits_accept_boundary_and_refuse_excess(limit):
    base = "-P INPUT ACCEPT\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n"
    if limit == "bytes":
        snapshot = base + "\n" * (guard.MAX_SNAPSHOT_BYTES - len(base.encode()))
        assert len(snapshot.encode()) == guard.MAX_SNAPSHOT_BYTES
        excess = snapshot + "\n"
    elif limit == "records":
        snapshot = base + "".join(
            f"-N SYNTHETIC-{index}\n" for index in range(guard.MAX_RECORDS - 3)
        )
        excess = snapshot + "-N EXCESS\n"
    elif limit == "tokens":
        snapshot = base + "".join(
            f"-A INPUT -m comment --comment synthetic-{index} -j RETURN\n"
            for index in range(32766)
        )
        snapshot += "-A INPUT -p tcp -f -j RETURN\n"
        assert (
            sum(len(record) for record in guard.ordered_records(snapshot))
            == guard.MAX_TOKENS
        )
        excess = snapshot + "-N EXCESS\n"
    else:
        snapshot = (
            base
            + shlex.join(
                [
                    "-A",
                    "INPUT",
                    "-m",
                    "comment",
                    "--comment",
                    "x" * guard.MAX_TOKEN_BYTES,
                    "-j",
                    "RETURN",
                ]
            )
            + "\n"
        )
        excess = snapshot.replace(
            "x" * guard.MAX_TOKEN_BYTES, "x" * (guard.MAX_TOKEN_BYTES + 1)
        )
    assert guard.ordered_records(snapshot)
    with pytest.raises(RuntimeError):
        guard.ordered_records(excess)


@pytest.mark.parametrize(
    "role,target",
    [
        ("gamma", "PPUBUNTU_PROXY"),
        ("gamma", "PPUBUNTU_RPC"),
        ("alpha", "PPUBUNTU_RPC"),
    ],
)
@pytest.mark.parametrize("prefixed", [False, True])
@pytest.mark.parametrize("option", ["-j", "--jump", "-g", "--goto"])
@pytest.mark.parametrize("entrypoint", ["ensure", "trusted-old-preflight"])
def test_option_like_operand_cannot_hide_extra_owned_reference(
    role, target, prefixed, option, entrypoint
):
    config = {**gamma_config(), "role": role}
    if prefixed:
        firewall = installed_prefix(config)
    else:
        firewall = Firewall()
        guard.ensure(config, firewall)
        firewall.mutations.clear()
    firewall.rules["OLD"].append(["-i", "--comment", option, target])
    before = guard.ordered_records(firewall.snapshot())
    if entrypoint == "ensure":
        assert_refused(config, firewall)
    else:
        old_chains, hooks = guard.policy(config)
        if role == "gamma":
            old_chains["PPUBUNTU_PROXY"] = old_chains["PPUBUNTU_PROXY"][1:]
            firewall.rules["PPUBUNTU_PROXY"] = old_chains["PPUBUNTU_PROXY"]
        old_before = guard.ordered_records(firewall.snapshot())
        with pytest.raises(RuntimeError):
            guard.classify(firewall.snapshot(), old_chains, hooks, config)
        assert guard.ordered_records(firewall.snapshot()) == old_before
        # Put the synthetic current chain back only to check model preservation.
        if role == "gamma":
            firewall.rules["PPUBUNTU_PROXY"] = guard.policy(config)[0]["PPUBUNTU_PROXY"]
    assert firewall.mutations == []
    assert guard.ordered_records(firewall.snapshot()) == before


@pytest.mark.parametrize("option", ["-j", "--jump", "-g", "--goto"])
def test_single_opaque_comment_value_is_not_an_adjacent_reference(policy, option):
    firewall = installed_prefix(policy)
    firewall.rules["OLD"].append(
        [
            "-m",
            "comment",
            "--comment",
            f"{option} PPUBUNTU_RPC",
            "-j",
            "RETURN",
        ]
    )
    before = guard.ordered_records(firewall.snapshot())
    assert guard.ensure(policy, firewall) is False
    assert firewall.mutations == []
    assert guard.ordered_records(firewall.snapshot()) == before


@pytest.mark.parametrize("operand", ["-j", "--jump", "-g", "--goto"])
@pytest.mark.parametrize("option", ["-j", "--jump", "-g", "--goto"])
def test_adjacent_targets_cannot_be_hidden_by_target_like_operands(operand, option):
    # Without extension arity parsing this is ambiguous, so refuse rather than
    # consume the real adjacent owned-target pair as another option's operand.
    with pytest.raises(RuntimeError):
        guard.jump(["-i", operand, option, "PPUBUNTU_RPC"])
