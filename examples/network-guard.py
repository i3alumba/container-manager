"""Operator-owned INPUT isolation for this service, never called by the API.

Requires root and /etc/pp-ubuntu/network-guard.json. Refuses partial/drifted state;
never flushes, deletes, moves or rewrites incumbent rules. Use under operator
serialization with other firewall writers. No NAT/FORWARD/Docker modifications.
"""

import ipaddress
import json
import re
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
        # Return tracked responses to incumbent INPUT policy; never ACCEPT or
        # exempt original-direction, NEW, RELATED or untracked ingress here.
        rules = [
            [
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED",
                "--ctdir",
                "REPLY",
                "-j",
                "RETURN",
            ]
        ]
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


K3S_PREFIX = [
    "-m",
    "comment",
    "--comment",
    "kube-router netpol - 4IA2OSFRMVNDXBVV",
    "-j",
    "KUBE-ROUTER-INPUT",
]
MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_RECORDS = 65536
MAX_TOKENS = 262144
MAX_TOKEN_BYTES = 4096
MAX_CHAINS = 64
MAX_RULES = 2048
MAX_DEPTH = 32
MAX_CONTEXTS = 4096
BUILTINS = {"INPUT", "FORWARD", "OUTPUT"}
VERDICTS = {"ACCEPT", "DROP", "REJECT", "RETURN", "MARK", "NFLOG"}
STATES = frozenset({"NEW", "ESTABLISHED", "RELATED", "INVALID", "UNTRACKED"})
PROTOCOLS = frozenset({"tcp", "udp", "icmp", "other"})


def refuse():
    raise RuntimeError("unproved filter snapshot drift; operator review required")


def jump(rule):
    """Conservatively scan adjacent target pairs without guessing option arity.

    An option-like operand must never consume a later jump. Opaque comment
    values remain single tokens, not strings to split or search for switches.
    """
    targets = []
    for index, option in enumerate(rule):
        if option in {"-j", "--jump", "-g", "--goto"}:
            if index + 1 >= len(rule):
                refuse()
            targets.append((option, rule[index + 1]))
    if len(targets) > 1:
        refuse()
    return targets[0] if targets else None


def parse_snapshot(snapshot):
    """Full ordered token records, including policy VALUES, for fencing."""
    if not isinstance(snapshot, str):
        refuse()
    try:
        size = len(snapshot.encode())
    except UnicodeError:
        refuse()
    if size > MAX_SNAPSHOT_BYTES:
        refuse()
    records, declarations, policies, rules, references = [], set(), {}, {}, []
    seen, tokens = set(), 0
    for line in snapshot.splitlines():
        if not line.strip():
            continue
        try:
            args = tuple(shlex.split(line))
        except ValueError:
            refuse()
        if not args:
            continue
        tokens += len(args)
        if (
            len(records) >= MAX_RECORDS
            or tokens > MAX_TOKENS
            or any(
                len(token.encode()) > MAX_TOKEN_BYTES
                or any(ord(char) < 32 or ord(char) == 127 for char in token)
                for token in args
            )
            or args in seen
        ):
            refuse()
        seen.add(args)
        records.append(args)
        if len(args) < 2 or not re.fullmatch(
            r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}", args[1]
        ):
            refuse()
        kind, chain = args[:2]
        if kind in {"-N", "-P"}:
            if chain in declarations or chain in VERDICTS:
                refuse()
            if kind == "-P":
                if (
                    len(args) != 3
                    or chain not in BUILTINS
                    or args[2] not in {"ACCEPT", "DROP"}
                ):
                    refuse()
                policies[chain] = args[2]
            elif len(args) != 2 or chain in BUILTINS:
                refuse()
            declarations.add(chain)
            rules[chain] = []
        elif kind == "-A" and chain in declarations and len(args) >= 3:
            rule = list(args[2:])
            rules[chain].append(rule)
            target = jump(rule)
            if target:
                references.append((chain, rule, target))
        else:
            refuse()
    if set(policies) != BUILTINS:
        refuse()
    return {
        "records": tuple(records),
        "declarations": declarations,
        "policies": policies,
        "rules": rules,
        "references": references,
    }


def ordered_records(snapshot):
    """Read-only exact comparison API for a separately fenced one-rule change."""
    return parse_snapshot(snapshot)["records"]


def parse(snapshot):
    parsed = parse_snapshot(snapshot)
    return parsed["declarations"], parsed["rules"]


def number(value, maximum, minimum=0):
    if not re.fullmatch(r"[0-9]+", value) or not minimum <= int(value) <= maximum:
        refuse()
    return int(value)


def mark(value):
    parts = value.split("/")
    if len(parts) > 2 or any(
        not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", part) for part in parts
    ):
        refuse()
    if any(
        int(part, 16 if part.startswith("0x") else 10) > 0xFFFFFFFF for part in parts
    ):
        refuse()


def merge_intervals(intervals):
    merged = []
    for low, high in sorted(intervals):
        if merged and low <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], high))
        else:
            merged.append((low, high))
    return tuple(merged)


def port_intervals(value, multi):
    intervals = []
    weight = 0
    for item in value.split(","):
        bounds = item.split(":")
        if len(bounds) not in {1, 2}:
            refuse()
        low = number(bounds[0], 65535)
        high = number(bounds[-1], 65535)
        if low > high:
            refuse()
        intervals.append((low, high))
        weight += len(bounds)
    if (not multi and len(intervals) != 1) or (multi and weight > 15):
        refuse()
    return merge_intervals(intervals)


def cidr(value):
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        refuse()
    if network.version != 4:
        refuse()
    return int(network.network_address), int(network.broadcast_address)


def prefix_rule(rule, parsed):
    """Strict observed grammar; unknown predicates never narrow the proof."""
    modules, options = set(), {}
    index = 0
    negated_mark = False
    set_directions = set()
    while index < len(rule):
        option = rule[index]
        if option == "!":
            if (
                index + 1 >= len(rule)
                or rule[index + 1] != "--mark"
                or "mark" not in modules
                or negated_mark
            ):
                refuse()
            negated_mark = True
            index += 1
            continue
        if index + 1 >= len(rule):
            refuse()
        value = rule[index + 1]
        if option == "-m" and value == "set":
            # A positive ipset match can only narrow packets. Deliberately do
            # not trust its name or contents as evidence: over-approximate it
            # as always matching, so it can never justify an unsafe ACCEPT.
            if (
                index + 4 >= len(rule)
                or rule[index + 2] != "--match-set"
                or not re.fullmatch(r"KUBE-(?:SRC|DST)-[A-Z0-9]{16}", rule[index + 3])
                or rule[index + 4] not in {"src", "dst"}
                or rule[index + 4] in set_directions
            ):
                refuse()
            set_directions.add(rule[index + 4])
            index += 5
            continue
        if option == "-m":
            if (
                value
                not in {
                    "tcp",
                    "udp",
                    "icmp",
                    "multiport",
                    "conntrack",
                    "comment",
                    "mark",
                    "addrtype",
                    "limit",
                }
                or value in modules
            ):
                refuse()
            modules.add(value)
        else:
            if (
                option
                not in {
                    "-s",
                    "-d",
                    "-p",
                    "--dport",
                    "--dports",
                    "--ctstate",
                    "--comment",
                    "--mark",
                    "--src-type",
                    "--dst-type",
                    "--limit",
                    "--limit-burst",
                    "--icmp-type",
                    "-j",
                    "--set-xmark",
                    "--nflog-group",
                    "--nflog-prefix",
                    "--reject-with",
                }
                or option in options
            ):
                refuse()
            options[option] = value
        index += 2
    requirements = {
        "--dports": "multiport",
        "--ctstate": "conntrack",
        "--comment": "comment",
        "--mark": "mark",
        "--src-type": "addrtype",
        "--dst-type": "addrtype",
        "--limit": "limit",
        "--limit-burst": "limit",
        "--icmp-type": "icmp",
    }
    if any(
        key in options and module not in modules for key, module in requirements.items()
    ):
        refuse()
    if "--dport" in options and (
        options.get("-p") not in {"tcp", "udp"} or options.get("-p") not in modules
    ):
        refuse()
    if "--dports" in options and options.get("-p") not in {"tcp", "udp"}:
        refuse()
    if "--dport" in options and "--dports" in options:
        refuse()
    protocol = options.get("-p")
    if protocol is not None and protocol not in {"tcp", "udp", "icmp"}:
        refuse()
    if any(
        module in modules and protocol != module for module in ("tcp", "udp", "icmp")
    ):
        refuse()
    for key in ("--src-type", "--dst-type"):
        if key in options and options[key] != "LOCAL":
            refuse()
    if "--mark" in options:
        mark(options["--mark"])
    if "--set-xmark" in options:
        mark(options["--set-xmark"])
    if "--limit" in options:
        rate = options["--limit"].split("/")
        if len(rate) != 2 or rate[1] not in {
            "s",
            "sec",
            "second",
            "m",
            "min",
            "minute",
            "h",
            "hour",
            "d",
            "day",
        }:
            refuse()
        number(rate[0], 0xFFFFFFFF, 1)
    if "--limit-burst" in options:
        number(options["--limit-burst"], 0xFFFFFFFF, 1)
    if "--icmp-type" in options:
        parts = options["--icmp-type"].split("/")
        if len(parts) > 2:
            refuse()
        for part in parts:
            number(part, 255)
    states = STATES
    if "--ctstate" in options:
        values = options["--ctstate"].split(",")
        if len(values) != len(set(values)) or not set(values) <= STATES:
            refuse()
        states = frozenset(values)
    target = options.get("-j")
    effects = set(options) & {
        "--set-xmark",
        "--nflog-group",
        "--nflog-prefix",
        "--reject-with",
    }
    allowed = {
        "MARK": {"--set-xmark"},
        "NFLOG": {"--nflog-group", "--nflog-prefix"},
        "REJECT": {"--reject-with"},
    }.get(target, set())
    if not effects <= allowed or (target == "MARK" and "--set-xmark" not in effects):
        refuse()
    if "--nflog-group" in options:
        number(options["--nflog-group"], 65535)
    if "--nflog-prefix" in options and (
        not 1 <= len(options["--nflog-prefix"]) <= 64
        or any(not 32 <= ord(c) <= 126 for c in options["--nflog-prefix"])
    ):
        refuse()
    if (
        "--reject-with" in options
        and options["--reject-with"] != "icmp-port-unreachable"
    ):
        refuse()
    if target not in VERDICTS and (
        target not in parsed["declarations"] or target in BUILTINS
    ):
        refuse()
    src, dst = cidr(options.get("-s", "0.0.0.0/0")), cidr(
        options.get("-d", "0.0.0.0/0")
    )
    ports = port_intervals(
        options.get("--dports", options.get("--dport", "0:65535")),
        "--dports" in options,
    )
    return (
        src,
        dst,
        frozenset({protocol}) if protocol else PROTOCOLS,
        ports,
        states,
    ), target


def intersect(left, right):
    src = max(left[0][0], right[0][0]), min(left[0][1], right[0][1])
    dst = max(left[1][0], right[1][0]), min(left[1][1], right[1][1])
    ports = merge_intervals(
        (max(a, c), min(b, d))
        for a, b in left[3]
        for c, d in right[3]
        if max(a, c) <= min(b, d)
    )
    return src, dst, left[2] & right[2], ports, left[4] & right[4]


def empty(path):
    return (
        path[0][0] > path[0][1]
        or path[1][0] > path[1][1]
        or not path[2]
        or not path[3]
        or not path[4]
    )


def prove_prefix(parsed, config):
    policy(config)  # Validate trusted role/controller topology without changing it.
    gamma = config["role"] == "gamma"
    address = cidr("10.200.73.2/32" if gamma else "10.200.73.1/32")
    local = cidr("10.42.0.0/24" if gamma else "10.42.1.0/24")
    protected = [
        (
            address,
            frozenset({"tcp"}),
            ((9443 if gamma else 9444, 9443 if gamma else 9444),),
        )
    ]
    if gamma:
        exclusions = set(config["reserved_ports"]) | set(range(30000, 32768))
        spans = []
        start = None
        for port in range(3000, 50002):
            available = port <= 50000 and port not in exclusions
            if available and start is None:
                start = port
            if not available and start is not None:
                spans.append((start, port - 1))
                start = None
        protected.append((address, frozenset({"tcp", "udp"}), tuple(spans)))
    compiled, contexts = {}, 0

    def visit(chain, path, stack):
        nonlocal contexts
        contexts += 1
        if contexts > MAX_CONTEXTS or len(stack) >= MAX_DEPTH or chain in stack:
            refuse()
        if chain not in parsed["declarations"] or chain in BUILTINS:
            refuse()
        if chain not in compiled:
            compiled[chain] = [
                prefix_rule(rule, parsed) for rule in parsed["rules"][chain]
            ]
            if (
                len(compiled) > MAX_CHAINS
                or sum(len(rules) for rules in compiled.values()) > MAX_RULES
            ):
                refuse()
        for predicates, target in compiled[chain]:
            contexts += 1
            if contexts > MAX_CONTEXTS:
                refuse()
            possible = intersect(path, predicates)
            if target == "ACCEPT" and not empty(possible):
                overlaps = any(
                    possible[1][0] <= dst[1]
                    and dst[0] <= possible[1][1]
                    and possible[2] & protocols
                    and any(a <= d and c <= b for a, b in possible[3] for c, d in ports)
                    for dst, protocols, ports in protected
                )
                local_state = (
                    local[0] <= possible[0][0] <= possible[0][1] <= local[1]
                    and possible[4]
                    and possible[4] <= {"ESTABLISHED", "RELATED"}
                )
                if overlaps and not local_state:
                    refuse()
            elif target not in VERDICTS:
                visit(target, possible, (*stack, chain))
            # No terminal/RETURN pruning: later rules and caller continuations
            # remain in the over-approximation, including after MARK/NFLOG.

    universe = ((0, 0xFFFFFFFF), (0, 0xFFFFFFFF), PROTOCOLS, ((0, 65535),), STATES)
    visit("KUBE-ROUTER-INPUT", universe, ())


def classify(snapshot, chains, hooks, config=None):
    parsed = parse_snapshot(snapshot)
    declarations, rules = parsed["declarations"], parsed["rules"]
    owned = set(chains)
    present = declarations & owned
    references = [
        (chain, rule)
        for chain, rule, target in parsed["references"]
        if target[1] in owned
    ]
    prefixed = rules["INPUT"][:1] == [K3S_PREFIX]
    if not present and not references:
        if prefixed:
            raise RuntimeError("owned attachment drift; operator review required")
        return "fresh"
    if present != owned or any(
        rules.get(name) != expected for name, expected in chains.items()
    ):
        raise RuntimeError("owned chain drift; operator review required")
    if prefixed and rules["INPUT"].count(K3S_PREFIX) != 1:
        raise RuntimeError("owned attachment drift; operator review required")
    offset = 1 if prefixed else 0
    if rules["INPUT"][offset : offset + len(hooks)] != hooks or references != [
        ("INPUT", h) for h in hooks
    ]:
        raise RuntimeError("owned attachment drift; operator review required")
    if prefixed:
        if config is None:
            refuse()
        expected_chains, expected_hooks = policy(config)
        if set(chains) != set(expected_chains) or hooks != expected_hooks:
            refuse()
        prove_prefix(parsed, config)
    return "installed"


def ensure(config, invoke):
    chains, hooks = policy(config)
    before = invoke(["-S"])
    state = classify(before, chains, hooks, config)
    if state == "installed":
        return False
    for name, rules in chains.items():
        invoke(["-N", name])
        for rule in rules:
            invoke(["-A", name, *rule])
    for hook in reversed(hooks):
        invoke(["-I", "INPUT", "1", *hook])
    after = invoke(["-S"])
    if classify(after, chains, hooks, config) != "installed":
        raise RuntimeError("guard verification failed")
    # Compare ordered policy-bearing records, not just declaration names/rules.
    incumbent = tuple(
        record
        for record in ordered_records(after)
        if not (record[0] == "-N" and record[1] in chains)
        and not (
            record[0] == "-A"
            and (
                record[1] in chains
                or (record[1] == "INPUT" and list(record[2:]) in hooks)
            )
        )
    )
    if incumbent != ordered_records(before):
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
