"""Read-only host inspection. Unsupported relevant forwarding syntax fails closed.

Never execute mutations, infer ownership from a registry, or treat UDP sends as probes.
"""

import ipaddress
import json
import re
import shlex
import socket
import subprocess

from .errors import Failure


def run_read(argv: list[str]) -> str:
    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=5, check=True
        )
        if len(result.stdout) > 16_000_000:
            raise Failure("inspection_too_large")
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        raise Failure("inspection_unavailable") from None


def includes_host(network: str, hosts: list[str]) -> bool:
    try:
        net = ipaddress.ip_network(network, strict=False)
        return any(ipaddress.ip_address(h) in net for h in hosts)
    except ValueError:
        raise Failure("unsupported_destination") from None


def port_match(spec: str, port: int) -> bool:
    for part in spec.split(","):
        try:
            bounds = re.split(r"[:-]", part)
            if len(bounds) == 2 and int(bounds[0]) > int(bounds[1]):
                raise ValueError
            if len(bounds) == 1 and int(bounds[0]) == port:
                return True
            if len(bounds) == 2 and int(bounds[0]) <= port <= int(bounds[1]):
                return True
            if len(bounds) > 2 or any(not 0 <= int(b) <= 65535 for b in bounds):
                raise ValueError
        except ValueError:
            raise Failure("unsupported_port_set") from None
    return False


def iptables_options(tokens: list[str]) -> list[tuple[str, str | None, bool]]:
    """Respect argv value boundaries: a quoted comment is never a match flag."""
    options = []
    index = 0
    while index < len(tokens):
        negate = tokens[index] == "!"
        if negate:
            index += 1
        if index >= len(tokens) or not tokens[index].startswith("-"):
            raise Failure("unsupported_nat_rule")
        flag = tokens[index]
        index += 1
        value = None
        if flag not in {"--random", "--random-fully"}:
            if index >= len(tokens):
                raise Failure("unsupported_nat_rule")
            value = tokens[index]
            index += 1
            if flag != "--comment" and value.startswith(("-", "!")):
                raise Failure("unsupported_nat_rule")
            if flag == "--match-set":
                # Preserve boundaries without interpreting an opaque ipset.
                if index >= len(tokens) or not re.fullmatch(
                    r"(?:src|dst)(?:,(?:src|dst))*", tokens[index]
                ):
                    raise Failure("unsupported_nat_rule")
                value += " " + tokens[index]
                index += 1
        options.append((flag, value, negate))
    if any(
        sum(option[0] == flag for option in options) > 1
        for flag in {option[0] for option in options} - {"-m"}
    ):
        raise Failure("unsupported_nat_rule")
    return options


def iptables_conflict(text: str, protocol: str, port: int, hosts: list[str]) -> bool:
    """Scan reachable NAT chains; ClusterIP-only destination rules are irrelevant.

    Match uncertainty propagates conservatively through user chains. Unknown
    relevant set matches (including ipset) are refused rather than read as free.
    """
    chains: dict[str, list[list[str]]] = {}
    in_nat = False
    for line in text.splitlines():
        if line == "*nat":
            in_nat = True
        elif line == "COMMIT":
            in_nat = False
        elif in_nat and line.startswith(":"):
            declaration = re.fullmatch(r":(\S+) (?:-|ACCEPT|DROP) \[\d+:\d+\]", line)
            if declaration is None:
                raise Failure("unparseable_nat_declaration")
            chains.setdefault(declaration[1], [])
        elif in_nat and line.startswith("-A "):
            try:
                tokens = shlex.split(line)
                chains.setdefault(tokens[1], []).append(tokens[2:])
            except (ValueError, IndexError):
                raise Failure("unsupported_nat_rule") from None
    visiting = set()

    def walk(chain: str) -> bool:
        if chain in visiting:
            raise Failure("cyclic_nat_rule")
        visiting.add(chain)
        try:
            for tokens in chains.get(chain, []):

                options = iptables_options(tokens)

                def argument(flag):
                    return next(
                        (value for option, value, _ in options if option == flag), None
                    )

                proto = argument("-p") or argument("--protocol")
                destination = argument("-d") or argument("--destination")

                # A negated source predicate must not hide an independently
                # excluding positive destination/protocol/port predicate.
                def negated(flag):
                    return any(
                        negate for option, _, negate in options if option == flag
                    )

                if (
                    proto
                    and not any(negated(flag) for flag in ("-p", "--protocol"))
                    and proto
                    not in {protocol, "6" if protocol == "tcp" else "17", "all"}
                ):
                    continue
                if (
                    destination
                    and not any(negated(flag) for flag in ("-d", "--destination"))
                    and not includes_host(destination, hosts)
                ):
                    continue
                port_flags = ("--dport", "--dports", "--destination-port")
                ports = next(
                    (argument(flag) for flag in port_flags if flag in tokens), None
                )
                if (
                    ports
                    and not any(negated(flag) for flag in port_flags)
                    and not port_match(ports, port)
                ):
                    continue
                target = argument("-j") or argument("--jump") or argument("-g")
                if target in {"RETURN", "ACCEPT", "MARK", "CONNMARK"}:
                    continue
                # Postrouting SNAT/MASQUERADE cannot allocate a public destination.
                if target in {"SNAT", "MASQUERADE"}:
                    continue
                # Inspect the complete target branch before rejecting an unknown
                # predicate. A verified empty/mark/SNAT-only (or port-excluded)
                # branch cannot allocate this destination, regardless of its match.
                if target in chains:
                    if not walk(target):
                        continue
                elif target not in {"DNAT", "REDIRECT", "NETMAP"}:
                    raise Failure(
                        "unsupported_nat_target" if target else "unsupported_nat_rule"
                    )
                if any(flag == "--match-set" or negate for flag, _, negate in options):
                    raise Failure("unsupported_relevant_nat_match")
                supported = {
                    "-p",
                    "--protocol",
                    "-d",
                    "--destination",
                    "--dport",
                    "--dports",
                    "--destination-port",
                    "-j",
                    "--jump",
                    "-g",
                    "-m",
                    "--comment",
                    "--to-destination",
                    "--to-ports",
                    "--dst-type",
                    "--src-type",
                    "--random",
                    "--random-fully",
                }
                # Unknown conditions can only narrow the rule, but never imply free.
                if any(flag not in supported for flag, _, _ in options):
                    raise Failure("unsupported_relevant_nat_match")
                return True

            return False
        finally:
            visiting.remove(chain)

    return walk("PREROUTING") or walk("OUTPUT")


def nft_conflict(text: str, protocol: str, port: int, hosts: list[str]) -> bool:
    """Inspect literal native nft NAT with reachable-chain traversal.

    Unknown predicates on allocating branches and unknown effects fail closed.
    Literal port exclusions and verified mark/SNAT-only subtrees can prove an
    opaque compatibility predicate irrelevant without decoding its port set.
    ClusterIP-only branches are excluded before evaluating their unknown details.
    """
    try:
        entries = json.loads(text)["nftables"]
        if not isinstance(entries, list):
            raise ValueError
        chains = {}
        rules = {}
        for entry in entries:
            if "chain" in entry:
                chain = entry["chain"]
                chains[(chain["family"], chain["table"], chain["name"])] = chain
            if "rule" in entry:
                rule = entry["rule"]
                rules.setdefault(
                    (rule["family"], rule["table"], rule["chain"]), []
                ).append(rule)
        roots = {
            key
            for key, chain in chains.items()
            if chain.get("type") == "nat"
            and chain.get("hook") in {"prerouting", "output", "input", "ingress"}
        }
        # Malformed/incomplete snapshots with NAT expressions still must not pass.
        for key, entries_for_chain in rules.items():
            if any(
                any(set(e) & {"dnat", "redirect", "tproxy"} for e in r["expr"])
                for r in entries_for_chain
            ):
                if key not in chains or any(
                    any("tproxy" in e for e in r["expr"]) for r in entries_for_chain
                ):
                    roots.add(key)
        visiting = set()

        def walk(key):
            if key in visiting:
                raise Failure("cyclic_nft_rule")
            visiting.add(key)
            try:
                for rule in rules.get(key, []):
                    expr = rule["expr"]
                    excluded = False
                    unknown_match = False
                    unknown_effect = False
                    destination_nat = False
                    targets = []
                    for e in expr:
                        if "match" not in e:
                            for verb, value in e.items():
                                if verb in {
                                    "counter",
                                    "comment",
                                    "return",
                                    "accept",
                                    "snat",
                                    "masquerade",
                                }:
                                    continue
                                if verb in {"dnat", "redirect"}:
                                    destination_nat = True
                                elif verb in {"jump", "goto"}:
                                    targets.append((*key[:2], value["target"]))
                                elif verb == "xt":
                                    if value.get("type") == "match":
                                        # xt comment cannot filter/rewrite. Other
                                        # opaque xt matches remain unknown predicates.
                                        name = value.get("name")
                                        if name not in {
                                            "comment",
                                            "addrtype",
                                            "multiport",
                                            "statistic",
                                            "nfacct",
                                            "mark",
                                            "tcp",
                                            "udp",
                                        }:
                                            unknown_effect = True
                                        unknown_match |= name != "comment"
                                    elif value.get("type") == "target" and value.get(
                                        "name"
                                    ) in {"DNAT", "REDIRECT", "NETMAP"}:
                                        destination_nat = True
                                    elif value.get("type") != "target" or value.get(
                                        "name"
                                    ) not in {"MARK", "CONNMARK", "SNAT", "MASQUERADE"}:
                                        unknown_effect = True
                                else:
                                    # Unknown effects (maps/verdicts/rewrites) may
                                    # allocate or change dport before a child chain.
                                    unknown_effect = True
                            continue
                        match = e["match"]
                        left, right = match.get("left", {}), match.get("right")
                        if not isinstance(left, dict) or match.get("op") != "==":
                            unknown_match = True
                            continue
                        payload, meta = left.get("payload", {}), left.get("meta", {})
                        if payload.get("field") == "daddr" and payload.get(
                            "protocol"
                        ) in {"ip", "ip6"}:
                            if isinstance(right, str) and not right.startswith("@"):
                                excluded |= not includes_host(right, hosts)
                            elif isinstance(right, dict) and "prefix" in right:
                                prefix = right["prefix"]
                                excluded |= not includes_host(
                                    f"{prefix['addr']}/{prefix['len']}", hosts
                                )
                            else:
                                unknown_match = True
                        elif meta.get("key") == "l4proto" or (
                            payload.get("protocol") == "ip"
                            and payload.get("field") == "protocol"
                        ):
                            if isinstance(right, (str, int)) and right in {
                                "tcp",
                                "udp",
                                6,
                                17,
                            }:
                                excluded |= right not in {
                                    protocol,
                                    6 if protocol == "tcp" else 17,
                                }
                            else:
                                unknown_match = True
                        elif payload.get("field") == "dport":
                            transport = payload.get("protocol")
                            if transport in {"tcp", "udp", "th"}:
                                excluded |= transport not in {protocol, "th"}
                            else:
                                unknown_match = True
                            if type(right) is int and 0 <= right <= 65535:
                                excluded |= right != port
                            elif isinstance(right, dict) and "range" in right:
                                low, high = right["range"]
                                if (
                                    type(low) is not int
                                    or type(high) is not int
                                    or not 0 <= low <= high <= 65535
                                ):
                                    raise Failure("unparseable_nft_port_range")
                                excluded |= not low <= port <= high
                            else:
                                unknown_match = True
                        else:
                            unknown_match = True
                    if excluded:
                        continue
                    if unknown_effect:
                        raise Failure("unsupported_relevant_nft_rule")
                    allocates = destination_nat
                    for child in targets:
                        if child not in chains:
                            raise Failure("unsupported_nft_target")
                        allocates |= walk(child)
                    # Proving the entire reachable branch nonallocating makes an
                    # opaque predicate irrelevant, not trusted or decoded. A set
                    # on a possibly allocating branch still fails closed.
                    if allocates:
                        if unknown_match:
                            raise Failure("unsupported_relevant_nft_rule")
                        return True

                return False
            finally:
                visiting.remove(key)

        return any(walk(key) for key in roots)
    except (KeyError, TypeError, ValueError, AttributeError):
        raise Failure("unparseable_nft_rules") from None


class Inspector:
    def __init__(self, hosts: list[str], reader=run_read, sudo=False):
        self.hosts = hosts

        def read(argv):
            if sudo and argv[0] in {"iptables-save", "ip6tables-save", "nft"}:
                argv = ["sudo", "-n", "/usr/sbin/" + argv[0], *argv[1:]]
            return reader(argv)

        self.reader = read

    def check(self, protocol: str, port: int):
        try:
            # /proc includes v4/v6 wildcard and specific bindings, TCP LISTEN and
            # every bound UDP socket. Occupancy on any local address is conservative.
            for family in ("", "6"):
                text = self.reader(["cat", f"/proc/net/{protocol}{family}"])
                lines = text.splitlines()
                if not lines or "local_address" not in lines[0]:
                    raise Failure("unparseable_socket_table")
                for line in lines[1:]:
                    fields = line.split()
                    if len(fields) < 4:
                        raise Failure("unparseable_socket_table")
                    local_port = int(fields[1].rsplit(":", 1)[1], 16)
                    if local_port == port and (protocol == "udp" or fields[3] == "0A"):
                        raise Failure("host_listener_conflict", 409)
            for command in ("iptables-save", "ip6tables-save"):
                text = self.reader([command, "-t", "nat"])
                if "*nat" not in text or "COMMIT" not in text:
                    raise Failure("unparseable_nat_rules")
                if iptables_conflict(text, protocol, port, self.hosts):
                    raise Failure("host_forwarding_conflict", 409)
            if nft_conflict(
                self.reader(["nft", "-j", "list", "ruleset"]),
                protocol,
                port,
                self.hosts,
            ):
                raise Failure("host_forwarding_conflict", 409)
        except (ValueError, IndexError):
            raise Failure("unparseable_host_inspection") from None


def listener_ready(protocol: str, port: int, address: str) -> bool:
    """Confirm Incus bound the fixed gamma address; this is NOT service reachability."""
    expected = ipaddress.ip_address(address)
    family = "6" if expected.version == 6 else ""
    text = run_read(["cat", f"/proc/net/{protocol}{family}"])
    try:
        for line in text.splitlines()[1:]:
            fields = line.split()
            encoded, encoded_port = fields[1].split(":")
            raw = bytes.fromhex(encoded)
            # Linux prints each 32-bit word in host-endian order in /proc/net.
            import sys

            if sys.byteorder == "little":
                raw = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
            if (
                ipaddress.ip_address(raw) == expected
                and int(encoded_port, 16) == port
                and (protocol == "udp" or fields[3] == "0A")
            ):
                return True
        return False
    except (ValueError, IndexError):
        raise Failure("unparseable_socket_table") from None
