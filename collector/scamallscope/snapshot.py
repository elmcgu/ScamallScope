"""Run the collectors across regions and build a Snapshot."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .collectors import ec2
from .model import Snapshot, UnitResult


def _error_text(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        err = exc.response.get("Error", {})
        return f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    return f"{type(exc).__name__}: {exc}"


def collect(session: boto3.Session, regions: list[str]) -> Snapshot:
    identity = session.client("sts").get_caller_identity()
    account_id = identity["Account"]
    partition = identity["Arn"].split(":")[1]

    snap = Snapshot(
        account_id=account_id,
        partition=partition,
        collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        regions=regions,
    )

    for region in regions:
        ctx = ec2.Context(partition=partition, account_id=account_id, region=region)
        client = session.client("ec2", region_name=region)
        for resource_type, fn in ec2.COLLECTORS:
            try:
                resources, links = fn(client, ctx)
            except (ClientError, BotoCoreError) as exc:
                # Record the failure. Never treat it as "no resources".
                snap.units.append(UnitResult("ec2", resource_type, region, "error", error=_error_text(exc)))
                continue
            snap.resources.extend(resources)
            snap.links.extend(links)
            snap.units.append(UnitResult("ec2", resource_type, region, "ok", count=len(resources)))

    return snap


def write(snap: Snapshot, path: Path) -> None:
    """Write the snapshot as JSON, readable by the owner only (it maps an AWS estate)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(snap.to_dict(), indent=2, sort_keys=True, default=_json_default)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(data + "\n")


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Cannot serialise {type(value).__name__}")
