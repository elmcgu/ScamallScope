"""RDS DB instances (spec 10). Read-only. Permissions: infra/collector-read-only-policy.json."""

from __future__ import annotations

from typing import Any

from ..model import Link, Resource, link, make_resource, tags_to_dict
from .base import Context, Result
from .ec2 import arn as ec2_arn


def collect_db_instances(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for page in client.get_paginator("describe_db_instances").paginate():
        for db in page.get("DBInstances", []):
            tags = tags_to_dict(db.get("TagList"))
            config = {k: v for k, v in db.items() if k not in ("TagList", "Endpoint", "ListenerEndpoint")}
            config["EndpointPort"] = (db.get("Endpoint") or {}).get("Port")  # the host name is not needed
            r = make_resource(db["DBInstanceArn"], ctx["account_id"], ctx["region"], "rds", "db-instance",
                              db["DBInstanceIdentifier"], tags, config, name=tags.get("Name") or db["DBInstanceIdentifier"])
            resources.append(r)
            vpc = (db.get("DBSubnetGroup") or {}).get("VpcId")
            if vpc:
                links.append(link(ec2_arn(ctx, "vpc", vpc), r["arn"], "contains"))
            for g in db.get("VpcSecurityGroups", []):
                links.append(link(r["arn"], ec2_arn(ctx, "security-group", g["VpcSecurityGroupId"]), "uses"))
    return resources, links
