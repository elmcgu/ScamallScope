"""Run the collectors across regions and build a snapshot dict."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .collectors import account, autoscaling, ec2, elbv2, iam, lambda_, rds, s3
from .collectors.base import Context, Result
from .model import GLOBAL, Link, Snapshot, error_unit, link, new_snapshot, ok_unit

RegionalCollector = Callable[[Any, Context], Result]


def _error_text(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"


def collect(session: boto3.Session, regions: list[str], include_global: bool = True) -> Snapshot:
    """Collect EC2, Lambda, RDS, ELB and Auto Scaling in each region, and IAM and S3 once (region "global")."""
    identity = session.client("sts").get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    snap = new_snapshot(
        account_id=account_id,
        partition=partition,
        collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        regions=regions + ([GLOBAL] if include_global else []),
    )

    for region in regions:
        ctx = ec2.context(partition, account_id, region)
        clients: dict[str, Any] = {}
        for service, resource_type, client_name, fn in regional_collectors():
            if client_name not in clients:
                clients[client_name] = session.client(client_name, region_name=region)  # type: ignore[call-overload]
            _unit(snap, service, [resource_type], region, _one(resource_type, fn, clients[client_name], ctx))

    if include_global:
        iam_client = session.client("iam")
        _unit(snap, "iam", list(iam.TYPES), GLOBAL, lambda: iam.collect(iam_client, account_id))
        s3_client, s3control = session.client("s3"), session.client("s3control")
        _unit(snap, "s3", ["bucket"], GLOBAL,
              lambda: {"bucket": s3.collect_buckets(s3_client, s3control, partition, account_id)})
        _unit(snap, "iam", ["credential-report"], GLOBAL,
              lambda: {"credential-report": account.collect_credential_report(iam_client, partition, account_id)})
        home = regions[0] if regions else (session.region_name or "us-east-1")
        _unit(snap, "cloudtrail", ["trail"], GLOBAL, lambda: {"trail": account.collect_trails(
            lambda r: session.client("cloudtrail", region_name=r), home, partition, account_id)})

    snap["links"].extend(_instance_role_links(snap))
    return snap


def regional_collectors() -> list[tuple[str, str, str, RegionalCollector]]:
    """(service, resource type, boto3 client name, collector), run once per region in this order.

    A new regional collector is one line here (or in ec2.COLLECTORS or account.REGIONAL).
    """
    return [
        *[("ec2", resource_type, "ec2", fn) for resource_type, fn in ec2.COLLECTORS],
        ("lambda", "function", "lambda", lambda_.collect_functions),
        ("rds", "db-instance", "rds", rds.collect_db_instances),
        ("elasticloadbalancing", "load-balancer", "elbv2", elbv2.collect_load_balancers),
        ("elasticloadbalancing", "target-group", "elbv2", elbv2.collect_target_groups),
        ("autoscaling", "autoscaling-group", "autoscaling", autoscaling.collect_groups),
        *account.REGIONAL,
    ]


def _one(resource_type: str, fn: RegionalCollector, client: Any, ctx: Context) -> Callable[[], dict[str, Result]]:
    return lambda: {resource_type: fn(client, ctx)}


def _unit(snap: Snapshot, service: str, types: list[str], region: str,
          run: Callable[[], dict[str, Result]]) -> None:
    """Run one collection unit (one API listing that may return several resource types).

    On failure every type it covers is recorded as an error. Never treat it as "no resources".
    """
    try:
        results = run()
    except (ClientError, BotoCoreError, RuntimeError) as exc:
        for t in types:
            snap["units"].append(error_unit(service, t, region, _error_text(exc)))
        return
    for t in types:
        resources, links = results[t]
        snap["resources"].extend(resources)
        snap["links"].extend(links)
        snap["units"].append(ok_unit(service, t, region, len(resources)))


def _instance_role_links(snap: Snapshot) -> list[Link]:
    """EC2 instance -> IAM role it assumes, through its instance profile."""
    roles = iam.instance_profile_roles(snap["resources"])
    out = []
    for r in snap["resources"]:
        profile = (r["config"].get("IamInstanceProfile") or {}).get("Arn") if r["type"] == "instance" else None
        if profile and profile in roles:
            out.append(link(r["arn"], roles[profile], "assumes"))
    return out


def write_json(obj: Any, path: Path) -> None:
    """Write JSON readable by the owner only (snapshots and graphs map an AWS estate)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, sort_keys=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data + "\n")
