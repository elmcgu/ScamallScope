"""Which instance ports are open to the whole internet.

An instance port is "exposed" when all of these are true:

1. The instance is running and has a public address (IPv4 or IPv6).
2. Its subnet's route table (explicit, or the VPC main table) has a default route
   (0.0.0.0/0 or ::/0) to an internet gateway attached to the VPC.
3. One of its security groups allows inbound traffic from 0.0.0.0/0 or ::/0.

Not checked yet: network ACLs, prefix lists that contain 0.0.0.0/0, split default
routes (for example 0.0.0.0/1 + 128.0.0.0/1), load balancers in front of instances.
If a collection unit the check needs failed, the result is "unknown", never "not_exposed".
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

CHECKS = ("security group open to 0.0.0.0/0 or ::/0, public IP, default route to an attached "
          "internet gateway. Not checked: network ACLs, prefix lists, load balancers.")

WORLD = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
NEEDED = ("instance", "subnet", "security-group", "route-table", "internet-gateway")


def analyse(snapshot: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return {instance ARN: {"exposure", "reason", "ports"}} for every EC2 instance."""
    failed = {(u["region"], u["resource_type"]) for u in snapshot["units"] if u["status"] != "ok"}
    index: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for r in snapshot["resources"]:
        index[(r["region"], r["type"])][r["id"]] = r["config"]

    return {
        r["arn"]: _instance(r["region"], r["config"], index, failed)
        for r in snapshot["resources"]
        if r["type"] == "instance"
    }


def _result(exposure: str, reason: str, ports: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"exposure": exposure, "reason": reason, "ports": ports or []}


def interfaces(c: dict[str, Any]) -> list[dict[str, Any]]:
    """The instance's network interfaces as (subnet, public IPv4, has IPv6, security groups).

    Security groups and public addresses belong to network interfaces, and each
    interface can be in a different subnet. Falls back to instance-level fields
    when the API returned no interfaces.
    """
    enis = c.get("NetworkInterfaces") or []
    if not enis:
        return [{
            "subnet_id": c.get("SubnetId"),
            "public_ipv4": c.get("PublicIpAddress"),
            "ipv6": False,
            "groups": [g["GroupId"] for g in c.get("SecurityGroups", [])],
        }]
    return [{
        "subnet_id": n.get("SubnetId") or c.get("SubnetId"),
        "public_ipv4": (n.get("Association") or {}).get("PublicIp")
                       or (c.get("PublicIpAddress") if n.get("Attachment", {}).get("DeviceIndex", 0) == 0 else None),
        "ipv6": bool(n.get("Ipv6Addresses")),
        "groups": [g["GroupId"] for g in n.get("Groups", [])],
    } for n in enis]


def _instance(region: str, c: dict[str, Any], index: dict, failed: set) -> dict[str, Any]:
    if c.get("State", {}).get("Name") != "running":
        return _result("not_exposed", "instance is not running")

    missing = [t for t in NEEDED if (region, t) in failed]
    if missing:
        return _result("unknown", f"collection failed for: {', '.join(missing)}")

    reasons, ports = [], []
    for eni in interfaces(c):
        outcome = _interface(region, eni, index)
        if outcome["exposure"] == "unknown":
            return outcome
        reasons.append(outcome["reason"])
        ports += [p for p in outcome["ports"] if p not in ports]

    if ports:
        return _result("exposed", "public IP, route to internet gateway and inbound rule open to the internet", ports)
    # One interface: its reason. Several: the first, which is the primary interface.
    return _result("not_exposed", reasons[0])


def _interface(region: str, eni: dict[str, Any], index: dict) -> dict[str, Any]:
    families = (["ipv4"] if eni["public_ipv4"] else []) + (["ipv6"] if eni["ipv6"] else [])
    if not families:
        return _result("not_exposed", "no public IP address")

    subnet = index[(region, "subnet")].get(eni["subnet_id"])
    if subnet is None:
        return _result("unknown", "subnet not in snapshot")
    vpc_id = subnet["VpcId"]

    table = _route_table(index[(region, "route-table")], subnet["SubnetId"], vpc_id)
    if table is None:
        return _result("unknown", "no route table found for subnet")

    gateways = {
        gid for gid, g in index[(region, "internet-gateway")].items()
        if any(a.get("VpcId") == vpc_id and a.get("State") in ("available", "attached")
               for a in g.get("Attachments", []))
    }
    routed = [f for f in families if _default_route(table, f, gateways)]
    if not routed:
        return _result("not_exposed", "no default route to an internet gateway")

    ports = []
    for group_id in eni["groups"]:
        sg = index[(region, "security-group")].get(group_id)
        if sg is None:
            return _result("unknown", f"security group {group_id} not in snapshot")
        for perm in sg.get("IpPermissions", []):
            for family in routed:
                if _open_to_world(perm, family):
                    ports.append(_port(perm, family, group_id))
    if not ports:
        return _result("not_exposed", "no inbound rule open to the internet")
    return _result("exposed", "", ports)


def _route_table(tables: dict[str, dict[str, Any]], subnet_id: str, vpc_id: str) -> dict[str, Any] | None:
    main = None
    for t in tables.values():
        for a in t.get("Associations", []):
            if a.get("SubnetId") == subnet_id:
                return t
            if a.get("Main") and t.get("VpcId") == vpc_id:
                main = t
    return main


def _default_route(table: dict[str, Any], family: str, gateways: set[str]) -> bool:
    key = "DestinationCidrBlock" if family == "ipv4" else "DestinationIpv6CidrBlock"
    return any(
        r.get(key) == WORLD[family] and r.get("GatewayId") in gateways and r.get("State", "active") == "active"
        for r in table.get("Routes", [])
    )


def _open_to_world(perm: dict[str, Any], family: str) -> bool:
    if family == "ipv4":
        return any(x.get("CidrIp") == WORLD["ipv4"] for x in perm.get("IpRanges", []))
    return any(x.get("CidrIpv6") == WORLD["ipv6"] for x in perm.get("Ipv6Ranges", []))


def _port(perm: dict[str, Any], family: str, group_id: str) -> dict[str, Any]:
    protocol = perm.get("IpProtocol")
    return {
        "protocol": "all" if protocol == "-1" else protocol,
        "from_port": perm.get("FromPort"),
        "to_port": perm.get("ToPort"),
        "family": family,
        "security_group": group_id,
    }
