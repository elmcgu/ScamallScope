"""Shapes of the data, as plain dicts that match the snapshot JSON exactly.

TypedDict only describes the keys for type checking (pyright). At runtime these are
ordinary dicts: no classes, no methods. Functions that work on them live beside them.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any, Literal, TypedDict

SCHEMA_VERSION = 1


class Resource(TypedDict):
    arn: str
    account_id: str
    region: str
    service: str
    type: str
    id: str
    name: str | None
    tags: dict[str, str]
    config: dict[str, Any]  # raw API item, JSON-safe (dates as ISO strings)


class Link(TypedDict):
    source: str  # ARN
    target: str  # ARN
    type: str  # "contains", "uses", "attached", "routes", "routes_to", "filters"


class Unit(TypedDict):
    """Outcome of collecting one resource type in one region.

    Later runs must only mark resources "deleted" when the unit that owns them
    has status "ok" (decision 0001). A failed unit is never an empty list.
    """

    service: str
    resource_type: str
    region: str
    status: Literal["ok", "error"]
    count: int
    error: str | None


class Snapshot(TypedDict):
    schema_version: int
    account_id: str
    partition: str
    collected_at: str
    regions: list[str]
    units: list[Unit]
    resources: list[Resource]
    links: list[Link]


def new_snapshot(account_id: str, partition: str, collected_at: str, regions: list[str]) -> Snapshot:
    return {
        "schema_version": SCHEMA_VERSION, "account_id": account_id, "partition": partition,
        "collected_at": collected_at, "regions": regions, "units": [], "resources": [], "links": [],
    }


def ok_unit(service: str, resource_type: str, region: str, count: int) -> Unit:
    return {"service": service, "resource_type": resource_type, "region": region,
            "status": "ok", "count": count, "error": None}


def error_unit(service: str, resource_type: str, region: str, error: str) -> Unit:
    return {"service": service, "resource_type": resource_type, "region": region,
            "status": "error", "count": 0, "error": error}


def is_complete(snapshot: Snapshot) -> bool:
    return all(u["status"] == "ok" for u in snapshot["units"])


GLOBAL = "global"  # region name for global services (IAM, S3 bucket list)


def make_resource(arn: str, account_id: str, region: str, service: str, type: str, id: str,
                  tags: dict[str, str], config: dict[str, Any], name: str | None = None) -> Resource:
    return {"arn": arn, "account_id": account_id, "region": region, "service": service, "type": type,
            "id": id, "name": name if name is not None else tags.get("Name"), "tags": tags,
            "config": json_safe(config)}


def setting_arn(partition: str, service: str, region: str, account_id: str, setting_id: str) -> str:
    """Stable key for a Region-level setting. Not a real AWS ARN (spec 10)."""
    return f"arn:{partition}:{service}:{region}:{account_id}:scamallscope-setting/{setting_id}"


def make_setting(partition: str, service: str, region: str, account_id: str, setting_id: str,
                 config: dict[str, Any]) -> Resource:
    return make_resource(setting_arn(partition, service, region, account_id, setting_id), account_id, region,
                         service, "setting", setting_id, {}, config, name=f"{setting_id} ({region})")


def link(source: str, target: str, type: str) -> Link:
    return {"source": source, "target": target, "type": type}


def tags_to_dict(tags: list[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags or []}


def json_safe(value: Any) -> Any:
    """Copy of an API response with dates as ISO strings, so it is plain JSON data."""
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return value
