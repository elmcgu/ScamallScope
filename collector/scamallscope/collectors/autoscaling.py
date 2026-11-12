"""EC2 Auto Scaling groups (spec 10). Read-only. Permissions: infra/collector-read-only-policy.json."""

from __future__ import annotations

from typing import Any

from ..model import Link, Resource, link, make_resource, tags_to_dict
from .base import Context, Result
from .ec2 import arn as ec2_arn


def collect_groups(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for page in client.get_paginator("describe_auto_scaling_groups").paginate():
        for g in page.get("AutoScalingGroups", []):
            tags = tags_to_dict([{"Key": t["Key"], "Value": t.get("Value", "")} for t in g.get("Tags", [])])
            r = make_resource(g["AutoScalingGroupARN"], ctx["account_id"], ctx["region"], "autoscaling",
                              "autoscaling-group", g["AutoScalingGroupName"], tags, g,
                              name=tags.get("Name") or g["AutoScalingGroupName"])
            resources.append(r)
            for i in g.get("Instances", []):
                links.append(link(r["arn"], ec2_arn(ctx, "instance", i["InstanceId"]), "manages"))
            for tg in g.get("TargetGroupARNs", []):
                links.append(link(r["arn"], tg, "registers"))
    return resources, links
