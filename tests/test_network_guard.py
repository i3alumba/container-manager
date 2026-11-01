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
