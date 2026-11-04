"""Network ACL evaluation for traffic from the whole internet.

Network ACLs are stateless and ordered: inbound rules are checked lowest RuleNumber
first, and the first rule that matches a packet decides (allow or deny). If no rule
matches, the packet is denied.

"From the whole internet" uses the same meaning as the security group check: only
rules whose source is 0.0.0.0/0 (IPv4) or ::/0 (IPv6) count. A narrower allow does not
open the port to the world, and a narrower deny does not close it to the world.

ICMP rules match the whole protocol; their type and code are not checked yet.

Only inbound rules are used. Outbound rules (return traffic) do not make a port safe:
an attacker's packet still reaches the instance.
"""

from __future__ import annotations

from typing import Any

WORLD = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}
NUMBERS = {v: k for k, v in NAMES.items()}
ICMP = {"1", "58"}
ALL_PORTS = (0, 65535)

Range = tuple[int, int]


def protocol_number(protocol: str | None) -> str:
    """Security groups use names ("tcp") or numbers; network ACLs use numbers ("6")."""
    p = str(protocol).lower()
    return NUMBERS.get(p, p)


def protocol_name(number: str) -> str:
    return NAMES.get(number, number)


def for_subnet(acls: dict[str, dict[str, Any]], subnet_id: str, vpc_id: str) -> dict[str, Any] | None:
    """The ACL associated with the subnet, else the VPC default ACL."""
    default = None
    for a in acls.values():
        if any(x.get("SubnetId") == subnet_id for x in a.get("Associations", [])):
            return a
        if a.get("IsDefault") and a.get("VpcId") == vpc_id:
            default = a
    return default


def allowed(acl: dict[str, Any], protocol: str, ports: Range | None, family: str) -> list[Range | None]:
    """Parts of `ports` that inbound traffic from the whole internet may reach.

    `protocol` is a number string ("6"). `ports` is None for ICMP, where ports do not
    apply; the result is then [None] if allowed, [] if not.
    """
    remaining: list[Range | None] = [ports]
    result: list[Range | None] = []

    rules = sorted((e for e in acl.get("Entries", []) if not e.get("Egress")), key=lambda e: e["RuleNumber"])
    for rule in rules:
        if not remaining:
            break
        cidr = rule.get("CidrBlock") if family == "ipv4" else rule.get("Ipv6CidrBlock")
        if cidr != WORLD[family]:
            continue
        rule_protocol = str(rule.get("Protocol"))
        if rule_protocol not in ("-1", protocol):
            continue

        if ports is None:  # ICMP: the rule matches the whole protocol
            matched, remaining = remaining, []
        else:
            pr = rule.get("PortRange")
            rule_range = (pr["From"], pr["To"]) if pr and rule_protocol != "-1" else ALL_PORTS
            matched, rest = [], []
            for r in remaining:
                inside, outside = _split(r, rule_range)
                matched += inside
                rest += outside
            remaining = rest

        if rule.get("RuleAction") == "allow":
            result += matched

    return result if ports is None else _merge(result)


def _split(r: Range, by: Range) -> tuple[list[Range], list[Range]]:
    lo, hi = max(r[0], by[0]), min(r[1], by[1])
    if lo > hi:
        return [], [r]
    outside = []
    if r[0] < lo:
        outside.append((r[0], lo - 1))
    if hi < r[1]:
        outside.append((hi + 1, r[1]))
    return [(lo, hi)], outside


def _merge(ranges: list[Range]) -> list[Range]:
    merged: list[Range] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged
