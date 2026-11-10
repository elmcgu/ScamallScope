"""Workloads for the Availability view (spec 14): AZ spread, healing, backup and monitoring per workload."""

from __future__ import annotations

from datetime import date
from typing import Any

from .findings import Finding
from .hygiene import Ctx, backed_up, is_prod, needs_backup
from .model import Resource, Snapshot


def _az(r: Resource) -> str | None:
    return (r["config"].get("Placement") or {}).get("AvailabilityZone") or r["config"].get("AvailabilityZone")


def _running(r: Resource) -> bool:
    return r["type"] == "instance" and (r["config"].get("State") or {}).get("Name") == "running"


def _name(r: Resource) -> str:
    return r.get("name") or r["id"]


def _groups(ctx: Ctx) -> list[dict[str, Any]]:
    """Each running instance belongs to one workload: its app tag, else its ASG, else its target group, else itself."""
    taken: set[str] = set()
    out: list[dict[str, Any]] = []
    running = [i for i in ctx.by_type["instance"] if _running(i)]

    apps: dict[tuple[str, str, str], list[Resource]] = {}
    for i in running:
        if i["tags"].get("app"):
            apps.setdefault((i["region"], ctx.vpc_of(i) or "", i["tags"]["app"]), []).append(i)
    for (region, vpc, app), members in sorted(apps.items()):
        out.append({"kind": "app", "name": f"app {app}", "region": region, "vpc": vpc, "members": members, "anchor": None})
        taken |= {m["arn"] for m in members}
    for kind, rtype, link_type in (("asg", "autoscaling-group", "manages"), ("target-group", "target-group", "targets")):
        for g in ctx.by_type[rtype]:
            members = [ctx.res[a] for a in sorted(ctx.linked(link_type, g["arn"])) if a in ctx.res and _running(ctx.res[a])
                       and a not in taken]
            if members:
                out.append({"kind": kind, "name": _name(g), "region": g["region"], "vpc": ctx.vpc_of(members[0]) or "",
                            "members": members, "anchor": g})
                taken |= {m["arn"] for m in members}
    for i in running:
        if i["arn"] not in taken:
            out.append({"kind": "instance", "name": _name(i), "region": i["region"], "vpc": ctx.vpc_of(i) or "",
                        "members": [i], "anchor": i})
    for db in ctx.by_type["db-instance"]:
        out.append({"kind": "database", "name": _name(db), "region": db["region"], "vpc": ctx.vpc_of(db) or "",
                    "members": [db], "anchor": db})
    return out


def _healing(ctx: Ctx, w: dict[str, Any]) -> str:
    members = w["members"]
    if w["kind"] == "database":
        c = members[0]["config"]
        return "multi-az" if c.get("MultiAZ") or c.get("DBClusterIdentifier") else "none"
    if any(ctx.in_asg(m["arn"]) for m in members):
        return "asg"
    if all((ctx.src["cloudwatch"].get(m["arn"]) or {}).get("recover_alarm") for m in members):
        return "recover-alarm"
    if all((m["config"].get("MaintenanceOptions") or {}).get("AutoRecovery", "default") != "disabled" for m in members):
        return "auto-recovery"
    return "none"


def _backup(ctx: Ctx, w: dict[str, Any]) -> str:
    targets: list[Resource] = list(w["members"]) if w["kind"] == "database" else [
        ctx.res[v] for m in w["members"] for v in sorted(ctx.linking("attached", m["arn"])) if v in ctx.res]
    targets = [t for t in targets if needs_backup(t, ctx)]
    if not targets:
        return "n/a"
    region = w["region"]
    if not ctx.unit_ok("backup", "setting", region) or (w["kind"] != "database" and not ctx.unit_ok("ec2", "snapshot", region)):
        return "unknown"
    return "ok" if all(backed_up(t, ctx) for t in targets) else "missing"


def _monitoring(ctx: Ctx, w: dict[str, Any]) -> str:
    if w["kind"] == "database":
        return "n/a"
    cw, prom = "cloudwatch" in ctx.loaded, "prometheus" in ctx.loaded
    if not cw and not prom:
        return "unknown"
    members = w["members"]
    has = []
    if cw and all((ctx.src["cloudwatch"].get(m["arn"]) or {}).get("alarms") for m in members):
        has.append("alarm")
    if prom and all((ctx.src["prometheus"].get(m["arn"]) or {}).get("prom_up") == 1 for m in members):
        has.append("prometheus")
    return ", ".join(has) or "none"


def workloads(snapshot: Snapshot, nodes: dict[str, dict[str, Any]], sources: dict[str, dict[str, dict[str, Any]]],
              findings: list[Finding], today: date | None = None) -> list[dict[str, Any]]:
    src = {k: sources.get(k, {}) for k in ("wazuh", "prometheus", "cloudwatch", "ansible")}
    ctx = Ctx(snapshot, nodes, src, {"inventory", *sources}, {}, today or date.fromisoformat(snapshot["collected_at"][:10]))
    rel = [f for f in findings if f["pillar"] == "reliability" and not f["duplicate_of"]]
    rows = []
    for w in _groups(ctx):
        arns = {m["arn"] for m in w["members"]} | ({w["anchor"]["arn"]} if w["anchor"] else set())
        arns |= {v for m in w["members"] for v in ctx.linking("attached", m["arn"])}
        vpc_name = _name(ctx.res[w["vpc"]]) if w["vpc"] in ctx.res else ""
        group_label = f"{w['name']} ({vpc_name or 'no VPC'})"
        count = sum(1 for f in rel if f["resource"] in arns or (w["kind"] == "app" and f["resource_name"] == group_label))
        rows.append({
            "id": w["anchor"]["arn"] if w["anchor"] else f"{w['region']}|{w['vpc']}|{w['name']}",
            "name": w["name"], "kind": w["kind"], "region": w["region"], "vpc": vpc_name,
            "azs": sorted({a for m in w["members"] if (a := _az(m))}),
            "members": [m["arn"] for m in w["members"]], "prod": any(is_prod(m) for m in w["members"]),
            "healing": _healing(ctx, w), "backup": _backup(ctx, w), "monitoring": _monitoring(ctx, w), "findings": count,
        })
    rows.sort(key=lambda r: (-r["findings"], not r["prod"], r["name"]))
    return rows
