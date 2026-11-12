"""CloudWatch EC2 CPU and alarms (spec 06). Read-only. Permissions: infra/collector-read-only-policy.json."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .. import hosts
from ..findings import Parsed, empty_parsed
from ..model import Snapshot, json_safe

SOURCE = "cloudwatch"
DAYS = 14
PERIOD_S = 3600
MAX_QUERIES = 500  # GetMetricData limit per call


def running_instances(snapshot: Snapshot) -> dict[str, list[str]]:
    """region -> running instance ids."""
    out: dict[str, list[str]] = {}
    for r in snapshot["resources"]:
        if r["type"] == "instance" and (r["config"].get("State") or {}).get("Name") == "running":
            out.setdefault(r["region"], []).append(r["id"])
    return out


def query_ids(instance_ids: list[str]) -> dict[str, str]:
    """CloudWatch query ids must start with a lower-case letter and use [a-zA-Z0-9_]."""
    ids = {}
    for n, iid in enumerate(sorted(instance_ids)):
        ids[f"q{n}_avg"] = f"{iid}|avg"
        ids[f"q{n}_max"] = f"{iid}|max"
    return ids


def _queries(ids: dict[str, str]) -> list[dict[str, Any]]:
    out = []
    for qid, target in ids.items():
        iid, stat = target.split("|")
        out.append({"Id": qid, "ReturnData": True, "MetricStat": {
            "Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization",
                       "Dimensions": [{"Name": "InstanceId", "Value": iid}]},
            "Period": PERIOD_S, "Stat": "Average" if stat == "avg" else "Maximum"}})
    return out


def fetch(session: Any, snapshot: Snapshot, now: datetime | None = None) -> dict[str, Any]:
    end = (now or datetime.now(timezone.utc)).replace(minute=0, second=0, microsecond=0)
    start = end - timedelta(days=DAYS)
    regions: dict[str, Any] = {}
    for region, instance_ids in running_instances(snapshot).items():
        cw = session.client("cloudwatch", region_name=region)
        ids = query_ids(instance_ids)
        queries = _queries(ids)
        results: list[dict[str, Any]] = []
        for i in range(0, len(queries), MAX_QUERIES):
            for page in cw.get_paginator("get_metric_data").paginate(
                    MetricDataQueries=queries[i:i + MAX_QUERIES], StartTime=start, EndTime=end):
                results.extend(page.get("MetricDataResults", []))
        alarms: list[dict[str, Any]] = []
        for page in cw.get_paginator("describe_alarms").paginate(AlarmTypes=["MetricAlarm"]):
            alarms.extend({"AlarmName": a.get("AlarmName"), "Dimensions": a.get("Dimensions", []),
                           # Only EC2 recover actions are kept (REL-HEAL-001); other actions name SNS topics.
                           "RecoverAction": any(":ec2:recover" in x for x in a.get("AlarmActions", []))}
                          for a in page.get("MetricAlarms", []))
        regions[region] = {"queries": ids, "results": json_safe(results), "alarms": alarms}
    return {"fetched_at": end.isoformat(), "days": DAYS, "regions": regions}


def parse(raw: dict[str, Any], index: hosts.Index) -> Parsed:
    regions = raw.get("regions")
    if not isinstance(regions, dict):
        raise ValueError("cloudwatch.json: no regions object")
    out = empty_parsed()
    for data in regions.values():
        ids = data.get("queries") or {}
        values: dict[str, dict[str, list[float]]] = {}
        for res in data.get("results") or []:
            target = ids.get(res.get("Id"))
            if not target:
                continue
            iid, stat = target.split("|")
            values.setdefault(iid, {}).setdefault(stat, []).extend(float(v) for v in res.get("Values") or [])
        alarm_count: dict[str, int] = {}
        recover: set[str] = set()
        for a in data.get("alarms") or []:
            for d in a.get("Dimensions") or []:
                if d.get("Name") == "InstanceId":
                    alarm_count[d.get("Value")] = alarm_count.get(d.get("Value"), 0) + 1
                    if a.get("RecoverAction"):
                        recover.add(d.get("Value"))
        for iid in {t.split("|")[0] for t in ids.values()}:
            arn = hosts.by_instance_id(index, iid)
            if not arn:
                out["unmatched"].append(iid)
                continue
            avg, mx = values.get(iid, {}).get("avg", []), values.get(iid, {}).get("max", [])
            out["resources"][arn] = {
                "cpu_avg": round(sum(avg) / len(avg), 1) if avg else None,
                "cpu_max": round(max(mx), 1) if mx else None,
                "days": raw.get("days", DAYS),
                "alarms": alarm_count.get(iid, 0),
                "recover_alarm": iid in recover,
            }
    return out
