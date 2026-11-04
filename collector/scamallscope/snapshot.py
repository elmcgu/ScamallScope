"""Run the collectors across regions and build a snapshot dict."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .collectors import ec2
from .model import Snapshot, error_unit, new_snapshot, ok_unit


def _error_text(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"


def collect(session: boto3.Session, regions: list[str]) -> Snapshot:
    identity = session.client("sts").get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    snap = new_snapshot(
        account_id=account_id,
        partition=partition,
        collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        regions=regions,
    )

    for region in regions:
        ctx = ec2.context(partition, account_id, region)
        client = session.client("ec2", region_name=region)
        for resource_type, fn in ec2.COLLECTORS:
            try:
                resources, links = fn(client, ctx)
            except (ClientError, BotoCoreError) as exc:
                # Record the failure. Never treat it as "no resources".
                snap["units"].append(error_unit("ec2", resource_type, region, _error_text(exc)))
                continue
            snap["resources"].extend(resources)
            snap["links"].extend(links)
            snap["units"].append(ok_unit("ec2", resource_type, region, len(resources)))

    return snap


def write_json(obj: Any, path: Path) -> None:
    """Write JSON readable by the owner only (snapshots and graphs map an AWS estate)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, indent=2, sort_keys=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data + "\n")
