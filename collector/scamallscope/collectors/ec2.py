"""EC2 networking, compute and storage (specs 10 and earlier).

Read-only calls only: ec2:DescribeVpcs, ec2:DescribeSubnets,
ec2:DescribeSecurityGroups, ec2:DescribeInstances, ec2:DescribeRouteTables,
ec2:DescribeInternetGateways, ec2:DescribeNetworkAcls, ec2:DescribeVolumes,
ec2:DescribeSnapshots, ec2:DescribeAddresses, ec2:DescribeNatGateways,
ec2:DescribeVpcEndpoints, ec2:DescribeFlowLogs, ec2:GetEbsEncryptionByDefault.
"""

from __future__ import annotations

from typing import Any, Callable, Iterator, TypedDict

from ..model import Link, Resource, json_safe, link, make_setting, tags_to_dict


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


def _pages(client: Any, operation: str, key: str, **kwargs: Any) -> Iterator[dict[str, Any]]:
    for page in client.get_paginator(operation).paginate(**kwargs):
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
        for nat in sorted({x["NatGatewayId"] for x in t.get("Routes", []) if x.get("NatGatewayId")}):
            links.append(link(r["arn"], arn(ctx, "nat-gateway", nat), "routes_to"))
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


def collect_volumes(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for v in _pages(client, "describe_volumes", "Volumes"):
        r = _resource(ctx, "volume", v["VolumeId"], v)
        resources.append(r)
        for a in v.get("Attachments", []):
            if a.get("InstanceId"):
                links.append(link(r["arn"], arn(ctx, "instance", a["InstanceId"]), "attached"))
    return resources, links


def collect_snapshots(client: Any, ctx: Context) -> Result:
    """Own snapshots only: public and shared snapshots are not this account's cost or data."""
    resources: list[Resource] = []
    links: list[Link] = []
    for s in _pages(client, "describe_snapshots", "Snapshots", OwnerIds=["self"]):
        if s.get("OwnerId") not in (None, ctx["account_id"]):  # belt and braces (moto ignores the filter)
            continue
        r = _resource(ctx, "snapshot", s["SnapshotId"], s)
        resources.append(r)
        if s.get("VolumeId") and s["VolumeId"] != "vol-ffffffff":  # placeholder used for copied snapshots
            links.append(link(r["arn"], arn(ctx, "volume", s["VolumeId"]), "snapshot_of"))
    return resources, links


def collect_elastic_ips(client: Any, ctx: Context) -> Result:
    """DescribeAddresses has no paginator: one call returns all addresses."""
    resources: list[Resource] = []
    links: list[Link] = []
    for a in client.describe_addresses().get("Addresses", []):
        rid = a.get("AllocationId") or a.get("PublicIp")
        r = _resource(ctx, "elastic-ip", rid, a)
        resources.append(r)
        if a.get("InstanceId"):
            links.append(link(r["arn"], arn(ctx, "instance", a["InstanceId"]), "attached"))
    return resources, links


def collect_nat_gateways(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for n in _pages(client, "describe_nat_gateways", "NatGateways"):
        if n.get("State") in ("deleted", "deleting"):
            continue
        r = _resource(ctx, "nat-gateway", n["NatGatewayId"], n)
        resources.append(r)
        if n.get("SubnetId"):
            links.append(link(arn(ctx, "subnet", n["SubnetId"]), r["arn"], "contains"))
    return resources, links


def collect_vpc_endpoints(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for e in _pages(client, "describe_vpc_endpoints", "VpcEndpoints"):
        r = _resource(ctx, "vpc-endpoint", e["VpcEndpointId"], e)
        resources.append(r)
        links.append(link(arn(ctx, "vpc", e["VpcId"]), r["arn"], "contains"))
    return resources, links


FLOW_LOG_TARGETS = {"vpc": "vpc", "subnet": "subnet", "eni": "network-interface"}


def collect_flow_logs(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for f in _pages(client, "describe_flow_logs", "FlowLogs"):
        r = _resource(ctx, "flow-log", f["FlowLogId"], f)
        resources.append(r)
        target = f.get("ResourceId", "")
        kind = FLOW_LOG_TARGETS.get(target.split("-")[0])
        if kind:
            links.append(link(r["arn"], arn(ctx, kind, target), "logs"))
    return resources, links


def collect_ebs_encryption_default(client: Any, ctx: Context) -> Result:
    enabled = bool(client.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"))
    return [make_setting(ctx["partition"], "ec2", ctx["region"], ctx["account_id"],
                         "ebs-encryption-by-default", {"Enabled": enabled})], []


# (resource type, collector). Order matters only for readability of the output.
COLLECTORS: list[tuple[str, Callable[[Any, Context], Result]]] = [
    ("vpc", collect_vpcs),
    ("subnet", collect_subnets),
    ("security-group", collect_security_groups),
    ("instance", collect_instances),
    ("internet-gateway", collect_internet_gateways),
    ("route-table", collect_route_tables),
    ("network-acl", collect_network_acls),
    ("volume", collect_volumes),
    ("snapshot", collect_snapshots),
    ("elastic-ip", collect_elastic_ips),
    ("nat-gateway", collect_nat_gateways),
    ("vpc-endpoint", collect_vpc_endpoints),
    ("flow-log", collect_flow_logs),
    ("setting", collect_ebs_encryption_default),
]
