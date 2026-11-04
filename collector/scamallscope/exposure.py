"""Which instance ports are open to the whole internet.

An instance port is "exposed" when all of these are true:

1. The instance is running and has a public address (IPv4 or IPv6).
2. Its subnet's route table (explicit, or the VPC main table) has a default route
   (0.0.0.0/0 or ::/0) to an internet gateway attached to the VPC.
3. One of its security groups allows inbound traffic from 0.0.0.0/0 or ::/0.
4. The subnet's network ACL lets that traffic in from 0.0.0.0/0 or ::/0
   (see network_acl.py). Only the allowed part of a port range is reported.

Not checked yet: prefix lists that contain 0.0.0.0/0, split default routes
(for example 0.0.0.0/1 + 128.0.0.0/1), load balancers in front of instances.
If a collection unit the check needs failed, the result is "unknown", never "not_exposed".
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import network_acl
from .model import Snapshot

CHECKS = ("EC2: security group open to 0.0.0.0/0 or ::/0, public IP, default route to an attached "
          "internet gateway, inbound network ACL rules. S3: public bucket policy (AWS policy status) or "
          "public ACL, unless Block Public Access (bucket or account) stops it. Lambda: function URL "
          "with AuthType NONE. Not checked: prefix lists, split default routes, load balancers, "
          "API Gateway, CloudFront, access points.")

PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "everyone",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "any AWS account",
}
BLOCK_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

WORLD = {"ipv4": "0.0.0.0/0", "ipv6": "::/0"}
NEEDED = ("instance", "subnet", "security-group", "route-table", "internet-gateway", "network-acl")


def analyse(snapshot: Snapshot) -> dict[str, dict[str, Any]]:
    """Return {instance ARN: {"exposure", "reason", "ports"}} for every EC2 instance."""
    failed = {(u["region"], u["resource_type"]) for u in snapshot["units"] if u["status"] != "ok"}
    index: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for r in snapshot["resources"]:
        index[(r["region"], r["type"])][r["id"]] = r["config"]

    out: dict[str, dict[str, Any]] = {}
    for r in snapshot["resources"]:
        if r["type"] == "instance":
            out[r["arn"]] = _instance(r["region"], r["config"], index, failed)
        elif r["type"] == "bucket":
            out[r["arn"]] = bucket(r["config"])
        elif r["type"] == "function":
            out[r["arn"]] = function(r["config"])
    return out


def block_public_access(c: dict[str, Any]) -> dict[str, bool]:
    """Effective Block Public Access: a flag is on if the bucket or the account sets it."""
    b, a = c.get("PublicAccessBlock") or {}, c.get("AccountPublicAccessBlock") or {}
    return {f: bool(b.get(f)) or bool(a.get(f)) for f in BLOCK_FLAGS}


def public_acl(c: dict[str, Any]) -> list[str]:
    return sorted({PUBLIC_GRANTEES[g["Grantee"]["URI"]] for g in c.get("Grants") or []
                   if g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES})


def bucket(c: dict[str, Any]) -> dict[str, Any]:
    errors = c.get("DetailErrors") or {}
    missing = [k for k in ("PolicyStatus", "PublicAccessBlock", "AccountPublicAccessBlock", "Acl") if k in errors]
    if missing:
        return _result("unknown", f"could not read: {', '.join(missing)}")
    bpa = block_public_access(c)
    policy_public = (c.get("PolicyStatus") or {}).get("IsPublic") is True
    acl = public_acl(c)
    reasons = []
    if policy_public and not bpa["RestrictPublicBuckets"]:
        reasons.append("bucket policy allows public access")
    if acl and not bpa["IgnorePublicAcls"]:
        reasons.append(f"ACL grants access to {' and '.join(acl)}")
    if reasons:
        return _result("exposed", "; ".join(reasons))
    if policy_public or acl:
        return _result("not_exposed", "public policy or ACL is blocked by Block Public Access")
    return _result("not_exposed", "no public bucket policy or ACL")


def function(c: dict[str, Any]) -> dict[str, Any]:
    if "FunctionUrlConfigs" in (c.get("DetailErrors") or {}):
        return _result("unknown", "could not read function URL configuration")
    urls = c.get("FunctionUrlConfigs") or []
    if any(u.get("AuthType") == "NONE" for u in urls):
        return _result("exposed", "function URL with no authentication (AuthType NONE)")
    if urls:
        return _result("not_exposed", "function URL requires IAM authentication")
    return _result("not_exposed", "no function URL (API Gateway and other triggers not checked)")


def subnet_internet_routes(snapshot: Snapshot) -> dict[str, bool | None]:
    """{subnet ARN: True if its route table sends 0.0.0.0/0 or ::/0 to an attached internet gateway}.

    None means unknown: a unit the answer needs failed, or no route table was found.
    """
    failed = {(u["region"], u["resource_type"]) for u in snapshot["units"] if u["status"] != "ok"}
    index: dict[tuple[str, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    for r in snapshot["resources"]:
        index[(r["region"], r["type"])][r["id"]] = r["config"]

    out: dict[str, bool | None] = {}
    for r in snapshot["resources"]:
        if r["type"] != "subnet":
            continue
        region, subnet = r["region"], r["config"]
        if (region, "route-table") in failed or (region, "internet-gateway") in failed \
                or not subnet.get("SubnetId") or not subnet.get("VpcId"):
            out[r["arn"]] = None
            continue
        table = _route_table(index[(region, "route-table")], subnet["SubnetId"], subnet["VpcId"])
        if table is None:
            out[r["arn"]] = None
            continue
        gateways = _attached_gateways(index[(region, "internet-gateway")], subnet["VpcId"])
        out[r["arn"]] = any(_default_route(table, f, gateways) for f in ("ipv4", "ipv6"))
    return out


def _attached_gateways(gateways: dict[str, dict[str, Any]], vpc_id: str) -> set[str]:
    return {
        gid for gid, g in gateways.items()
        if any(a.get("VpcId") == vpc_id and a.get("State") in ("available", "attached")
               for a in g.get("Attachments", []))
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

    gateways = _attached_gateways(index[(region, "internet-gateway")], vpc_id)
    routed = [f for f in families if _default_route(table, f, gateways)]
    if not routed:
        return _result("not_exposed", "no default route to an internet gateway")

    acl = network_acl.for_subnet(index[(region, "network-acl")], subnet["SubnetId"], vpc_id)
    if acl is None:
        return _result("unknown", "no network ACL found for subnet")

    open_in_sg, ports = False, []
    for group_id in eni["groups"]:
        sg = index[(region, "security-group")].get(group_id)
        if sg is None:
            return _result("unknown", f"security group {group_id} not in snapshot")
        for perm in sg.get("IpPermissions", []):
            for family in routed:
                if not _open_to_world(perm, family):
                    continue
                open_in_sg = True
                for port in _through_acl(perm, family, acl):
                    entry = {**port, "family": family, "security_group": group_id,
                             "network_acl": acl["NetworkAclId"]}
                    if entry not in ports:
                        ports.append(entry)
    if not open_in_sg:
        return _result("not_exposed", "no inbound rule open to the internet")
    if not ports:
        return _result("not_exposed", "network ACL blocks the ports the security group opens")
    return _result("exposed", "", ports)


def _through_acl(perm: dict[str, Any], family: str, acl: dict[str, Any]) -> list[dict[str, Any]]:
    """Parts of a security group rule that the network ACL also lets in."""
    protocol = network_acl.protocol_number(perm.get("IpProtocol"))
    icmp = "1" if family == "ipv4" else "58"
    out: list[dict[str, Any]] = []

    def ranges(proto: str, ports: network_acl.Range) -> None:
        for lo, hi in network_acl.allowed_ports(acl, proto, ports, family):
            out.append({"protocol": network_acl.protocol_name(proto), "from_port": lo, "to_port": hi})

    def whole(proto: str, from_port: int | None, to_port: int | None) -> None:
        if network_acl.allows_protocol(acl, proto, family):
            out.append({"protocol": network_acl.protocol_name(proto), "from_port": from_port, "to_port": to_port})

    if protocol == "-1":  # all protocols: check the common ones one by one
        ranges("6", network_acl.ALL_PORTS)
        ranges("17", network_acl.ALL_PORTS)
        whole(icmp, None, None)
    elif protocol in ("6", "17"):
        ranges(protocol, (perm.get("FromPort", 0), perm.get("ToPort", 65535)))
    else:
        # ICMP keeps the security group's type and code; other protocols (e.g. 50 ESP) have no ports.
        whole(protocol, perm.get("FromPort"), perm.get("ToPort"))
    return out


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
