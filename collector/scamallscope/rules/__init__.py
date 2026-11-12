"""Rules over the inventory, often joined with another source (specs 08 and 12).

engine.py holds the context, rule types and helpers; each other module holds one group of rules.
The order of all_rules() is the order findings are made in.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from ..findings import Finding, Parsed, cover, empty_parsed, make
from ..model import GLOBAL, Snapshot
from . import availability, cost, security, spec08
from .availability import BACKUP_RECENT_DAYS, backed_up, needs_backup
from .engine import (
    DEFAULT_APP_TAG,
    DEFAULT_ENV_TAG,
    DEFAULT_REQUIRED_TAGS,
    NA,
    Ctx,
    GroupRule,
    Hit,
    Rule,
    Sources,
    az_of,
    is_running,
    name_of,
    prod_tags,
    state_of,
)

__all__ = ["BACKUP_RECENT_DAYS", "DEFAULT_APP_TAG", "DEFAULT_ENV_TAG", "DEFAULT_REQUIRED_TAGS", "NA", "Ctx", "GroupRule",
           "Rule", "all_rules", "az_of", "backed_up", "is_running", "name_of", "needs_backup", "prod_tags", "run", "state_of"]


def all_rules(required_tags: tuple[str, ...] = DEFAULT_REQUIRED_TAGS) -> list[Rule | GroupRule]:
    return [*spec08.rules(required_tags), *security.rules(), *cost.rules(), *availability.rules()]


def run(snapshot: Snapshot, nodes: dict[str, dict[str, Any]], sources: Sources,
        required_tags: tuple[str, ...] = DEFAULT_REQUIRED_TAGS, extras: dict[str, Any] | None = None,
        today: date | None = None, env_tag: str = DEFAULT_ENV_TAG, app_tag: str = DEFAULT_APP_TAG) -> Parsed:
    """sources: data per loaded source (ARN -> data). 'inventory' is always loaded.
    extras: cost_coverage (from the cost summary). today: defaults to the snapshot's date."""
    loaded = {"inventory", *sources}
    src: Sources = {k: sources.get(k, {}) for k in ("wazuh", "prometheus", "cloudwatch", "ansible")}
    day = today or date.fromisoformat(snapshot["collected_at"][:10])
    ctx = Ctx(snapshot, nodes, src, loaded, extras or {}, day, env_tag, app_tag)
    out = empty_parsed()
    for rule in all_rules(required_tags):
        if not set(rule.needs) <= loaded:
            continue
        source = "inventory" if rule.needs == ("inventory",) else "hygiene"
        found: list[Hit] = []
        if isinstance(rule, GroupRule):
            checked, found = rule.run(ctx)
        else:
            if rule.when and not rule.when(ctx):
                continue
            checked = 0
            for r in snapshot["resources"]:
                if r["type"] not in rule.types:
                    continue
                if any(not ctx.unit_ok(svc, t, r["region"]) for svc, t in rule.units):
                    continue
                hit = rule.check(r, nodes.get(r["arn"], {}), src, ctx)
                if hit == NA:
                    continue
                checked += 1
                if hit is not None:
                    found.append({**hit, "resource": r["arn"], "resource_name": name_of(r), "region": r["region"]})  # type: ignore[typeddict-item]
        for h in found:
            f: Finding = make(source, rule.id, h["title"], h["severity"], [rule.bp], h.get("resource"),
                              h.get("resource_name", "?"), h.get("region", GLOBAL), h.get("detail", ""),
                              h.get("remediation") or rule.remediation, savings_usd=h.get("savings_usd"))
            out["findings"].append(f)
        if checked:
            if found:
                cover(out["coverage"], [rule.bp], failed=True, n=len(found))
            if checked > len(found):
                cover(out["coverage"], [rule.bp], n=checked - len(found))
    return out
