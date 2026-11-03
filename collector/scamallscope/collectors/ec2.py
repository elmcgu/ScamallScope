"""EC2 networking and compute: VPCs, subnets, security groups, instances.

Read-only calls only: ec2:DescribeVpcs, ec2:DescribeSubnets,
ec2:DescribeSecurityGroups, ec2:DescribeInstances.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterator

from ..model import Link, Resource, tags_to_dict


@dataclass(frozen=True)
class Context:
    partition: str
    account_id: str
    region: str

    def arn(self, kind: str, resource_id: str) -> str:
        return f"arn:{self.partition}:ec2:{self.region}:{self.account_id}:{kind}/{resource_id}"


Result = tuple[list[Resource], list[Link]]


def _pages(client: Any, operation: str, key: str) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(operation).paginate():
        yield from page.get(key, [])


def _resource(ctx: Context, kind: str, resource_id: str, item: dict[str, Any]) -> Resource:
    tags = tags_to_dict(item.get("Tags"))
    return Resource(
        arn=ctx.arn(kind, resource_id),
        account_id=ctx.account_id,
        region=ctx.region,
        service="ec2",
        type=kind,
        id=resource_id,
        name=tags.get("Name"),
        tags=tags,
        config=item,
    )


def collect_vpcs(client: Any, ctx: Context) -> Result:
    resources = [_resource(ctx, "vpc", v["VpcId"], v) for v in _pages(client, "describe_vpcs", "Vpcs")]
    return resources, []


def collect_subnets(client: Any, ctx: Context) -> Result:
    resources, links = [], []
    for s in _pages(client, "describe_subnets", "Subnets"):
        r = _resource(ctx, "subnet", s["SubnetId"], s)
        resources.append(r)
        links.append(Link(ctx.arn("vpc", s["VpcId"]), r.arn, "contains"))
    return resources, links


def collect_security_groups(client: Any, ctx: Context) -> Result:
    resources, links = [], []
    for g in _pages(client, "describe_security_groups", "SecurityGroups"):
        r = _resource(ctx, "security-group", g["GroupId"], g)
        resources.append(r)
        if g.get("VpcId"):
            links.append(Link(ctx.arn("vpc", g["VpcId"]), r.arn, "contains"))
    return resources, links


def collect_instances(client: Any, ctx: Context) -> Result:
    resources, links = [], []
    for reservation in _pages(client, "describe_instances", "Reservations"):
        for i in reservation.get("Instances", []):
            # Terminated instances stay visible for about an hour; they no longer exist.
            if i.get("State", {}).get("Name") == "terminated":
                continue
            r = _resource(ctx, "instance", i["InstanceId"], i)
            resources.append(r)
            if i.get("SubnetId"):
                links.append(Link(ctx.arn("subnet", i["SubnetId"]), r.arn, "contains"))
            for g in i.get("SecurityGroups", []):
                links.append(Link(r.arn, ctx.arn("security-group", g["GroupId"]), "uses"))
    return resources, links


# (resource type, collector). Order matters only for readability of the output.
COLLECTORS: list[tuple[str, Callable[[Any, Context], Result]]] = [
    ("vpc", collect_vpcs),
    ("subnet", collect_subnets),
    ("security-group", collect_security_groups),
    ("instance", collect_instances),
]
