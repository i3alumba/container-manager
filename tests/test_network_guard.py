"""Operator guard is additive/idempotent and refuses misplaced or duplicate hooks."""

import importlib.util
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
