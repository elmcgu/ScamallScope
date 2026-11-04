"""Convert a snapshot into graph JSON for the frontend (Cytoscape.js elements format).

The graph keeps only what the UI needs. Raw config stays in the snapshot.
"""

from __future__ import annotations

from typing import Any, Callable

from . import exposure

GRAPH_SCHEMA_VERSION = 1


def _rules(perms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten security group permissions to protocol, port range and sources."""
    rules = []
    for p in perms or []:
        sources = [r["CidrIp"] for r in p.get("IpRanges", [])]
        sources += [r["CidrIpv6"] for r in p.get("Ipv6Ranges", [])]
        sources += [g["GroupId"] for g in p.get("UserIdGroupPairs", [])]
        sources += [pl["PrefixListId"] for pl in p.get("PrefixListIds", [])]
        rules.append({
            "protocol": p.get("IpProtocol"),  # "-1" means all protocols
            "from_port": p.get("FromPort"),
            "to_port": p.get("ToPort"),
            "sources": sources,
        })
    return rules


def _vpc(c: dict[str, Any]) -> dict[str, Any]:
    return {"cidr": c.get("CidrBlock"), "is_default": c.get("IsDefault", False)}


def _subnet(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "cidr": c.get("CidrBlock"),
        "availability_zone": c.get("AvailabilityZone"),
        "map_public_ip": c.get("MapPublicIpOnLaunch", False),
    }


def _security_group(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "group_name": c.get("GroupName"),
        "ingress": _rules(c.get("IpPermissions")),
        "egress": _rules(c.get("IpPermissionsEgress")),
    }


def _instance(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "instance_type": c.get("InstanceType"),
        "state": c.get("State", {}).get("Name"),
        # Only whether it has one: the address itself is not needed to draw the map.
        "has_public_ip": bool(c.get("PublicIpAddress")),
    }


def _internet_gateway(c: dict[str, Any]) -> dict[str, Any]:
    return {"attached_vpcs": [a["VpcId"] for a in c.get("Attachments", [])]}


def _route_table(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "main": any(a.get("Main") for a in c.get("Associations", [])),
        "routes": [
            {"destination": r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock")
             or r.get("DestinationPrefixListId"),
             "target": next((r[k] for k in ("GatewayId", "NatGatewayId", "TransitGatewayId",
                                            "VpcPeeringConnectionId", "NetworkInterfaceId") if r.get(k)), None),
             "state": r.get("State")}
            for r in c.get("Routes", [])
        ],
    }


def _network_acl(c: dict[str, Any]) -> dict[str, Any]:
    return {
        "is_default": c.get("IsDefault", False),
        "entries": [
            {"rule_number": e.get("RuleNumber"),
             "direction": "outbound" if e.get("Egress") else "inbound",
             "protocol": e.get("Protocol"),
             "action": e.get("RuleAction"),
             "cidr": e.get("CidrBlock") or e.get("Ipv6CidrBlock"),
             "ports": [e["PortRange"].get("From"), e["PortRange"].get("To")] if e.get("PortRange") else None}
            for e in sorted(c.get("Entries", []), key=lambda e: (bool(e.get("Egress")), e.get("RuleNumber", 0)))
        ],
    }


FIELDS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "vpc": _vpc,
    "subnet": _subnet,
    "security-group": _security_group,
    "instance": _instance,
    "internet-gateway": _internet_gateway,
    "route-table": _route_table,
    "network-acl": _network_acl,
}


def to_graph(snapshot: dict[str, Any]) -> dict[str, Any]:
    exposed = exposure.analyse(snapshot)
    nodes = []
    ids = set()
    for r in snapshot["resources"]:
        data = {
            "id": r["arn"],
            "label": r.get("name") or r["id"],
            "type": r["type"],
            "service": r["service"],
            "region": r["region"],
            "account_id": r["account_id"],
            "tags": r.get("tags", {}),
        }
        data.update(FIELDS.get(r["type"], lambda c: {})(r.get("config", {})))
        if r["arn"] in exposed:
            e = exposed[r["arn"]]
            data.update(exposure=e["exposure"], exposure_reason=e["reason"], exposed_ports=e["ports"])
        nodes.append({"group": "nodes", "data": data})
        ids.add(r["arn"])

    edges, seen, dropped = [], set(), 0
    for link in snapshot["links"]:
        key = (link["source"], link["type"], link["target"])
        if key in seen:
            continue
        seen.add(key)
        # Cytoscape rejects an edge whose end is not a node. That happens when the
        # unit that owns the end failed or the resource is out of scope.
        if link["source"] not in ids or link["target"] not in ids:
            dropped += 1
            continue
        edges.append({"group": "edges", "data": {
            "id": "|".join(key), "source": link["source"], "target": link["target"], "type": link["type"],
        }})

    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "meta": {
            "account_id": snapshot["account_id"],
            "collected_at": snapshot["collected_at"],
            "regions": snapshot["regions"],
            "complete": all(u["status"] == "ok" for u in snapshot["units"]),
            "failed_units": [u for u in snapshot["units"] if u["status"] != "ok"],
            "dropped_edges": dropped,
            "exposure_checks": exposure.CHECKS,
        },
        "elements": nodes + edges,
    }
