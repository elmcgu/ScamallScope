"""Daily inventory in DynamoDB: current state plus a change log (decision 0001).

One table (infra/inventory-table.yaml):

| Item          | pk                          | sk                 | Notes                                  |
|---------------|-----------------------------|--------------------|----------------------------------------|
| Current       | CUR#<account>#<region>      | <arn>                      | one per resource; Query per region     |
| Change event  | DAY#<account>#<YYYY-MM-DD>  | <collected_at>#<arn>#<kind> | gsi1pk ARN#<arn>, gsi1sk <time>#<kind> |
| Run record    | RUN#<account>#<YYYY-MM-DD>  | <collected_at>             | counts and units                       |

Rules:
- Write a current item only when its hash changes. Unchanged resources cost no writes.
- Mark "deleted" only when the unit (region + service + resource type) collected without errors.
- Hash a normalised config: volatile fields removed, lists sorted, so the same state
  always gives the same hash.
- Writes are ordered events -> current -> run record, and keys are deterministic, so a
  run that fails part way can simply be run again.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Literal, TypedDict

from boto3.dynamodb.conditions import Key

from .model import Resource, Snapshot

INDEX_BY_ARN = "by-arn"
CHANGE_TTL_DAYS = 365
# DynamoDB items are limited to 400 KB. Keep room for the other attributes.
MAX_CONFIG_BYTES = 350_000
# Fields that change without a real change to the resource.
VOLATILE_KEYS = frozenset({
    "LaunchTime", "AttachTime", "UsageOperationUpdateTime",
    "LatestRestorableTime",  # RDS: moves every few minutes
    "RoleLastUsed",  # IAM roles: moves whenever the role is used
    "LastBackupTime",  # AWS Backup protected resources: moves with every backup
    "access_key_1_last_used_date", "access_key_2_last_used_date",  # credential report
})

Kind = Literal["created", "changed", "deleted"]


class Change(TypedDict):
    arn: str
    kind: Kind
    type: str
    region: str
    name: str | None
    old_hash: str | None
    new_hash: str | None
    changed_fields: list[str]


# ---- pure functions: no AWS calls ---------------------------------------------------


def normalise(value: Any) -> Any:
    """Drop volatile keys and sort lists, recursively."""
    if isinstance(value, dict):
        return {k: normalise(v) for k, v in value.items() if k not in VOLATILE_KEYS}
    if isinstance(value, list):
        return sorted((normalise(v) for v in value), key=_canonical)
    return value


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def fingerprint(name: str | None, tags: dict[str, str], config: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "tags": tags, "config": normalise(config)}


def resource_hash(resource: Resource) -> str:
    fp = fingerprint(resource["name"], resource["tags"], resource["config"])
    return hashlib.sha256(_canonical(fp).encode()).hexdigest()


def changed_fields(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Names of what differs between two fingerprints: "name", "tags", or top-level config keys."""
    fields = [k for k in ("name", "tags") if old.get(k) != new.get(k)]
    oc, nc = old.get("config") or {}, new.get("config") or {}
    fields += sorted(k for k in set(oc) | set(nc) if oc.get(k) != nc.get(k))
    return fields


def plan(current: dict[str, dict[str, Any]], snapshot: Snapshot) -> tuple[list[Resource], list[dict[str, Any]], list[Change]]:
    """What to write. Returns (resources to put, current items to delete, change events).

    `current` holds the stored current items (by ARN) for the regions in this snapshot.
    """
    # Service is part of the key: several services share the type "setting" (spec 10).
    ok_units = {(u["region"], u["service"], u["resource_type"]) for u in snapshot["units"] if u["status"] == "ok"}
    puts: list[Resource] = []
    changes: list[Change] = []
    seen: set[str] = set()

    for r in snapshot["resources"]:
        seen.add(r["arn"])
        new_hash = resource_hash(r)
        old = current.get(r["arn"])
        if old is None:
            puts.append(r)
            changes.append(_change(r["arn"], "created", r["type"], r["region"], r["name"], None, new_hash, []))
        elif old["hash"] != new_hash:
            puts.append(r)
            new_fp = fingerprint(r["name"], r["tags"], r["config"])
            fields = changed_fields(_stored_fingerprint(old), new_fp) if "config_json" in old else ["config"]
            changes.append(_change(r["arn"], "changed", r["type"], r["region"], r["name"], old["hash"], new_hash, fields))

    deletes = []
    for arn, old in current.items():
        if arn not in seen and (old["region"], old.get("service") or arn.split(":")[2], old["type"]) in ok_units:
            deletes.append(old)
            changes.append(_change(arn, "deleted", old["type"], old["region"], old.get("name"), old["hash"], None, []))
    return puts, deletes, changes


def _change(arn: str, kind: Kind, type_: str, region: str, name: str | None,
            old_hash: str | None, new_hash: str | None, fields: list[str]) -> Change:
    return {"arn": arn, "kind": kind, "type": type_, "region": region, "name": name,
            "old_hash": old_hash, "new_hash": new_hash, "changed_fields": fields}


def _stored_fingerprint(item: dict[str, Any]) -> dict[str, Any]:
    return fingerprint(item.get("name"), dict(item.get("tags") or {}), json.loads(item["config_json"]))


def current_pk(account_id: str, region: str) -> str:
    return f"CUR#{account_id}#{region}"


def current_item(r: Resource, first_seen: str, collected_at: str) -> dict[str, Any]:
    item: dict[str, Any] = {
        "pk": current_pk(r["account_id"], r["region"]), "sk": r["arn"],
        "arn": r["arn"], "type": r["type"], "region": r["region"], "service": r["service"],
        "id": r["id"], "name": r["name"], "tags": r["tags"], "hash": resource_hash(r),
        "first_seen": first_seen, "last_changed": collected_at,
    }
    # Stored as one JSON string: always read or hashed whole, and no float/Decimal issues.
    config_json = _canonical(r["config"])
    if len(config_json.encode()) <= MAX_CONFIG_BYTES:
        item["config_json"] = config_json
    else:
        item["config_truncated"] = True  # hash still detects changes; fields are not listed
    return item


def day_pk(account_id: str, day: str) -> str:
    return f"DAY#{account_id}#{day}"


def run_pk(account_id: str, day: str) -> str:
    return f"RUN#{account_id}#{day}"


def change_item(c: Change, account_id: str, collected_at: str) -> dict[str, Any]:
    # collected_at in the sort key: two runs on one day keep both events, and the same
    # snapshot run twice writes the same keys.
    expires = datetime.fromisoformat(collected_at) + timedelta(days=CHANGE_TTL_DAYS)
    return {
        "pk": day_pk(account_id, collected_at[:10]), "sk": f"{collected_at}#{c['arn']}#{c['kind']}",
        "gsi1pk": f"ARN#{c['arn']}", "gsi1sk": f"{collected_at}#{c['kind']}",
        "at": collected_at, "expires_at": int(expires.timestamp()), **c,
    }


def run_item(snapshot: Snapshot, changes: list[Change]) -> dict[str, Any]:
    counts = {k: sum(1 for c in changes if c["kind"] == k) for k in ("created", "changed", "deleted")}
    return {
        "pk": run_pk(snapshot["account_id"], snapshot["collected_at"][:10]), "sk": snapshot["collected_at"],
        "account_id": snapshot["account_id"], "regions": snapshot["regions"],
        "resources": len(snapshot["resources"]),
        "unchanged": len(snapshot["resources"]) - counts["created"] - counts["changed"],
        **counts, "units": snapshot["units"],
    }


def plain(value: Any) -> Any:
    """DynamoDB returns numbers as Decimal; turn them back into int or float."""
    if isinstance(value, dict):
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


# ---- DynamoDB calls -------------------------------------------------------------------


def _query_all(table: Any, **kwargs: Any) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    while True:
        page = table.query(**kwargs)
        items += page.get("Items", [])
        if "LastEvaluatedKey" not in page:
            return items
        kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def load_current(table: Any, account_id: str, regions: list[str]) -> dict[str, dict[str, Any]]:
    current: dict[str, dict[str, Any]] = {}
    for region in regions:
        for item in _query_all(table, KeyConditionExpression=Key("pk").eq(current_pk(account_id, region))):
            current[item["arn"]] = item
    return current


def apply(table: Any, snapshot: Snapshot) -> dict[str, Any]:
    """Update the inventory from one snapshot. Returns the run record."""
    at = snapshot["collected_at"]
    current = load_current(table, snapshot["account_id"], snapshot["regions"])
    puts, deletes, changes = plan(current, snapshot)

    with table.batch_writer() as batch:
        for c in changes:
            batch.put_item(Item=change_item(c, snapshot["account_id"], at))
    with table.batch_writer() as batch:
        for r in puts:
            old = current.get(r["arn"])
            batch.put_item(Item=current_item(r, old["first_seen"] if old else at, at))
        for old in deletes:
            batch.delete_item(Key={"pk": old["pk"], "sk": old["sk"]})

    run = run_item(snapshot, changes)
    table.put_item(Item=run)
    return run


def changes_on(table: Any, account_id: str, day: str) -> list[dict[str, Any]]:
    """Change events for one account on one UTC day, in time order."""
    return [plain(i) for i in _query_all(table, KeyConditionExpression=Key("pk").eq(day_pk(account_id, day)))]


def history(table: Any, arn: str) -> list[dict[str, Any]]:
    """Change events for one resource, oldest first."""
    items = _query_all(table, IndexName=INDEX_BY_ARN, KeyConditionExpression=Key("gsi1pk").eq(f"ARN#{arn}"))
    return [plain(i) for i in items]
