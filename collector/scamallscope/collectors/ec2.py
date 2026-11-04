"""EC2 networking and compute: VPCs, subnets, security groups, instances.

Read-only calls only: ec2:DescribeVpcs, ec2:DescribeSubnets,
ec2:DescribeSecurityGroups, ec2:DescribeInstances, ec2:DescribeRouteTables,
ec2:DescribeInternetGateways, ec2:DescribeNetworkAcls.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator, TypedDict

from ..model import Link, Resource, json_safe, link, tags_to_dict


class Context(TypedDict):
    """Where a collector runs: partition, account and region."""

    partition: str
    account_id: str
    region: str


def context(partition: str, account_id: str, region: str) -> Context:
    return {"partition": partition, "account_id": account_id, "region": region}


def arn(ctx: Context, kind: str, resource_id: str) -> str:
    return f"arn:{ctx['partition']}:ec2:{ctx['region']}:{ctx['account_id']}:{kind}/{resource_id}"


Result = tuple[list[Resource], list[Link]]


def _pages(client: Any, operation: str, key: str) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(operation).paginate():
        yield from page.get(key, [])


def _resource(ctx: Context, kind: str, resource_id: str, item: dict[str, Any]) -> Resource:
    tags = tags_to_dict(item.get("Tags"))
    return {
        "arn": arn(ctx, kind, resource_id),
        "account_id": ctx["account_id"],
        "region": ctx["region"],
        "service": "ec2",
        "type": kind,
        "id": resource_id,
        "name": tags.get("Name"),
        "tags": tags,
        "config": json_safe(item),
    }


def collect_vpcs(client: Any, ctx: Context) -> Result:
    resources = [_resource(ctx, "vpc", v["VpcId"], v) for v in _pages(client, "describe_vpcs", "Vpcs")]
    return resources, []


def collect_subnets(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for s in _pages(client, "describe_subnets", "Subnets"):
        r = _resource(ctx, "subnet", s["SubnetId"], s)
        resources.append(r)
        links.append(link(arn(ctx, "vpc", s["VpcId"]), r["arn"], "contains"))
    return resources, links


def collect_security_groups(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for g in _pages(client, "describe_security_groups", "SecurityGroups"):
        r = _resource(ctx, "security-group", g["GroupId"], g)
        resources.append(r)
        if g.get("VpcId"):
            links.append(link(arn(ctx, "vpc", g["VpcId"]), r["arn"], "contains"))
    return resources, links


def collect_instances(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for reservation in _pages(client, "describe_instances", "Reservations"):
        for i in reservation.get("Instances", []):
            # Terminated instances stay visible for about an hour; they no longer exist.
            if i.get("State", {}).get("Name") == "terminated":
                continue
            r = _resource(ctx, "instance", i["InstanceId"], i)
            resources.append(r)
            if i.get("SubnetId"):
                links.append(link(arn(ctx, "subnet", i["SubnetId"]), r["arn"], "contains"))
            # Security groups attach to network interfaces; the instance-level list can be incomplete.
            groups = {g["GroupId"] for g in i.get("SecurityGroups", [])}
            groups |= {g["GroupId"] for n in i.get("NetworkInterfaces", []) for g in n.get("Groups", [])}
            for group_id in sorted(groups):
                links.append(link(r["arn"], arn(ctx, "security-group", group_id), "uses"))
    return resources, links


def collect_internet_gateways(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for g in _pages(client, "describe_internet_gateways", "InternetGateways"):
        r = _resource(ctx, "internet-gateway", g["InternetGatewayId"], g)
        resources.append(r)
        for a in g.get("Attachments", []):
            links.append(link(r["arn"], arn(ctx, "vpc", a["VpcId"]), "attached"))
    return resources, links


def collect_route_tables(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for t in _pages(client, "describe_route_tables", "RouteTables"):
        r = _resource(ctx, "route-table", t["RouteTableId"], t)
        resources.append(r)
        links.append(link(arn(ctx, "vpc", t["VpcId"]), r["arn"], "contains"))
        for a in t.get("Associations", []):
            if a.get("SubnetId"):
                links.append(link(r["arn"], arn(ctx, "subnet", a["SubnetId"]), "routes"))
        gateways = {x["GatewayId"] for x in t.get("Routes", []) if x.get("GatewayId", "").startswith("igw-")}
        for igw in sorted(gateways):
            links.append(link(r["arn"], arn(ctx, "internet-gateway", igw), "routes_to"))
    return resources, links


def collect_network_acls(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for a in _pages(client, "describe_network_acls", "NetworkAcls"):
        r = _resource(ctx, "network-acl", a["NetworkAclId"], a)
        resources.append(r)
        links.append(link(arn(ctx, "vpc", a["VpcId"]), r["arn"], "contains"))
        for assoc in a.get("Associations", []):
            if assoc.get("SubnetId"):
                links.append(link(r["arn"], arn(ctx, "subnet", assoc["SubnetId"]), "filters"))
    return resources, links


# (resource type, collector). Order matters only for readability of the output.
COLLECTORS: list[tuple[str, Callable[[Any, Context], Result]]] = [
    ("vpc", collect_vpcs),
    ("subnet", collect_subnets),
    ("security-group", collect_security_groups),
    ("instance", collect_instances),
    ("internet-gateway", collect_internet_gateways),
    ("route-table", collect_route_tables),
    ("network-acl", collect_network_acls),
]
