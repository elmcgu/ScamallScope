"""Application, Network and Gateway Load Balancers and their target groups (spec 10).

Read-only: elasticloadbalancing:DescribeLoadBalancers, DescribeListeners, DescribeSSLPolicies,
DescribeTargetGroups, DescribeTargetHealth, DescribeTags.
"""

from __future__ import annotations

from typing import Any

from ..model import Link, Resource, link, make_resource, tags_to_dict
from .ec2 import Context, Result, arn as ec2_arn

TAG_BATCH = 20
TLS_PROTOCOLS = {"HTTPS", "TLS"}  # only these listeners use an SSL policy  # DescribeTags takes up to 20 ARNs


def _tags(client: Any, arns: list[str]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for i in range(0, len(arns), TAG_BATCH):
        for d in client.describe_tags(ResourceArns=arns[i:i + TAG_BATCH]).get("TagDescriptions", []):
            out[d["ResourceArn"]] = tags_to_dict(d.get("Tags"))
    return out


def _pages(client: Any, operation: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    return [x for page in client.get_paginator(operation).paginate(**kwargs) for x in page.get(key, [])]


def _tls(listener: dict[str, Any]) -> bool:
    return listener.get("Protocol") in TLS_PROTOCOLS


def collect_load_balancers(client: Any, ctx: Context) -> Result:
    lbs = _pages(client, "describe_load_balancers", "LoadBalancers")
    listeners = {lb["LoadBalancerArn"]: _pages(client, "describe_listeners", "Listeners",
                                               LoadBalancerArn=lb["LoadBalancerArn"]) for lb in lbs}
    policies = sorted({x["SslPolicy"] for ls in listeners.values() for x in ls if _tls(x) and x.get("SslPolicy")})
    protocols: dict[str, list[str]] = {}
    if policies:  # AWS's own list of protocols per policy, so no policy names are hard-coded here
        for p in client.describe_ssl_policies(Names=policies).get("SslPolicies", []):
            protocols[p["Name"]] = p.get("SslProtocols", [])
    tags = _tags(client, [lb["LoadBalancerArn"] for lb in lbs])
    resources: list[Resource] = []
    links: list[Link] = []
    for lb in lbs:
        lb_arn = lb["LoadBalancerArn"]
        config = {k: v for k, v in lb.items() if k != "DNSName"}
        config["Listeners"] = [{
            "Protocol": x.get("Protocol"), "Port": x.get("Port"), "SslPolicy": x.get("SslPolicy"),
            "SslProtocols": protocols.get(x.get("SslPolicy") or "", []) if _tls(x) else [], "DefaultActions": x.get("DefaultActions", []),
        } for x in listeners[lb_arn]]
        t = tags.get(lb_arn, {})
        r = make_resource(lb_arn, ctx["account_id"], ctx["region"], "elasticloadbalancing", "load-balancer",
                          lb["LoadBalancerName"], t, config, name=t.get("Name") or lb["LoadBalancerName"])
        resources.append(r)
        if lb.get("VpcId"):
            links.append(link(ec2_arn(ctx, "vpc", lb["VpcId"]), lb_arn, "contains"))
        for g in lb.get("SecurityGroups", []):
            links.append(link(lb_arn, ec2_arn(ctx, "security-group", g), "uses"))
    return resources, links


def collect_target_groups(client: Any, ctx: Context) -> Result:
    groups = _pages(client, "describe_target_groups", "TargetGroups")
    tags = _tags(client, [g["TargetGroupArn"] for g in groups])
    resources: list[Resource] = []
    links: list[Link] = []
    for g in groups:
        g_arn = g["TargetGroupArn"]
        config = dict(g)
        config["TargetHealth"] = [{"Id": d["Target"]["Id"], "Port": d["Target"].get("Port"),
                                   "State": (d.get("TargetHealth") or {}).get("State"),
                                   "Reason": (d.get("TargetHealth") or {}).get("Reason")}
                                  for d in client.describe_target_health(TargetGroupArn=g_arn).get("TargetHealthDescriptions", [])]
        t = tags.get(g_arn, {})
        r = make_resource(g_arn, ctx["account_id"], ctx["region"], "elasticloadbalancing", "target-group",
                          g["TargetGroupName"], t, config, name=t.get("Name") or g["TargetGroupName"])
        resources.append(r)
        for lb_arn in g.get("LoadBalancerArns", []):
            links.append(link(lb_arn, g_arn, "routes_to"))
        if g.get("TargetType", "instance") == "instance":
            for target in config["TargetHealth"]:
                links.append(link(g_arn, ec2_arn(ctx, "instance", target["Id"]), "targets"))
    return resources, links
