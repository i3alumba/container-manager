"""Operator-owned INPUT isolation for this service, never called by the API.

Requires root and /etc/pp-ubuntu/network-guard.json. Refuses partial/drifted state;
never flushes, deletes, moves or rewrites incumbent rules. Use under operator
serialization with other firewall writers. No NAT/FORWARD/Docker modifications.
"""

import json
from pathlib import Path
import shlex
import subprocess


def policy(config):
    role = config["role"]
    if role not in {"alpha", "gamma"} or config["pod_cidr"] != "10.42.0.0/24":
        raise ValueError("unexpected topology")
    ports = config["reserved_ports"]
    if (
        not isinstance(ports, list)
        or any(type(p) is not int or not 1 <= p <= 65535 for p in ports)
        or ports != sorted(set(ports))
    ):
        raise ValueError("invalid reserved ports")
    address = "10.200.73.2/32" if role == "gamma" else "10.200.73.1/32"
    rpc = "9443" if role == "gamma" else "9444"
    sources = ["10.42.0.0/24", "10.200.73.2/32", "10.200.73.1/32"]
    chains = {
        "PPUBUNTU_RPC": [["-s", s, "-j", "ACCEPT"] for s in sources] + [["-j", "DROP"]]
    }
    hooks = [
        ["-d", address, "-p", "tcp", "-m", "tcp", "--dport", rpc, "-j", "PPUBUNTU_RPC"]
    ]
    if role == "gamma":
        reserved = [p for p in ports if 3000 <= p <= 50000]
        rules = []
        for protocol in ["tcp", "udp"]:
            for offset in range(0, len(reserved), 15):
                rules.append(
                    [
                        "-p",
                        protocol,
                        "-m",
                        "multiport",
                        "--dports",
                        ",".join(map(str, reserved[offset : offset + 15])),
                        "-j",
                        "RETURN",
                    ]
                )
        rules += [["-s", "10.200.73.1/32", "-j", "RETURN"], ["-j", "DROP"]]
        chains["PPUBUNTU_PROXY"] = rules
        for protocol in ["tcp", "udp"]:
            hooks.append(
                [
                    "-d",
                    address,
                    "-p",
                    protocol,
                    "-m",
                    "multiport",
                    "--dports",
                    "3000:29999,32768:50000",
                    "-j",
                    "PPUBUNTU_PROXY",
                ]
            )
    return chains, hooks


def parse(snapshot):
    declarations, rules = set(), {}
    for line in snapshot.splitlines():
        args = shlex.split(line)
        if not args:
            continue
        if args[0] in {"-N", "-P"}:
            declarations.add(args[1])
            rules.setdefault(args[1], [])
        elif args[0] == "-A":
            rules.setdefault(args[1], []).append(args[2:])
        else:
            raise RuntimeError("unparseable filter inspection")
    if "INPUT" not in declarations:
        raise RuntimeError("missing INPUT chain")
    return declarations, rules


def classify(snapshot, chains, hooks):
    declarations, rules = parse(snapshot)
    owned = set(chains)
    present = declarations & owned
    references = [
        (chain, rule)
        for chain, entries in rules.items()
        for rule in entries
        if any(name in rule for name in owned)
    ]
    if not present and not references:
        return "fresh"
    if present != owned or any(
        rules.get(name) != expected for name, expected in chains.items()
    ):
        raise RuntimeError("owned chain drift; operator review required")
    # Check exact position AND uniqueness; an ACCEPT before the jump is a bypass.
    if rules["INPUT"][: len(hooks)] != hooks or references != [
        ("INPUT", h) for h in hooks
    ]:
        raise RuntimeError("owned attachment drift; operator review required")
    return "installed"


def ensure(config, invoke):
    chains, hooks = policy(config)
    before = invoke(["-S"])
    state = classify(before, chains, hooks)
    if state == "installed":
        return False
    for name, rules in chains.items():
        invoke(["-N", name])
        for rule in rules:
            invoke(["-A", name, *rule])
    for hook in reversed(hooks):
        invoke(["-I", "INPUT", "1", *hook])
    after = invoke(["-S"])
    if classify(after, chains, hooks) != "installed":
        raise RuntimeError("guard verification failed")
    before_decl, before_rules = parse(before)
    after_decl, after_rules = parse(after)
    if (
        after_decl != before_decl | set(chains)
        or after_rules["INPUT"][len(hooks) :] != before_rules["INPUT"]
        or any(
            after_rules.get(name) != entries
            for name, entries in before_rules.items()
            if name != "INPUT"
        )
    ):
        raise RuntimeError(
            "incumbent firewall changed concurrently; operator review required"
        )
    return True


def invoke(args):
    try:
        return subprocess.check_output(
            ["iptables", "-w", "5", *args],
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        # In particular, inspection errors are NEVER interpreted as rule absence.
        raise RuntimeError("owned guard inspection/mutation failed") from None


if __name__ == "__main__":
    config = json.loads(Path("/etc/pp-ubuntu/network-guard.json").read_text())
    ensure(config, invoke)
