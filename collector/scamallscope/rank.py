"""Duplicates, priority and totals over all findings (spec 13). Pure functions."""

from __future__ import annotations

from typing import Any

from .findings import Finding
from .hygiene import DEFAULT_ENV_TAG, prod_tags

WEIGHT = {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}
OWN_RULES = ("inventory", "hygiene")


def _preference(f: Finding) -> tuple[int, int, str]:
    """Lower is kept as primary: costhub for cost, then our rules, then other tools; then worse severity."""
    if f["source"] == "costhub" and f["pillar"] == "cost":
        rank = 0
    elif f["source"] in OWN_RULES:
        rank = 1
    else:
        rank = 2
    return rank, -WEIGHT[f["severity"]], f["id"]


def _family(f: Finding) -> str:
    """Our own rules count as one source: two of them on one resource are two issues."""
    return "own" if f["source"] in OWN_RULES else f["source"]


def mark_duplicates(findings: list[Finding]) -> None:
    """Same resource, same pillar, a shared best practice, reported by another source: one issue (spec 13)."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        f["duplicate_of"], f["also_reported_by"] = None, []
        if f["resource"]:
            groups.setdefault((f["resource"], f["pillar"]), []).append(f)
    for group in groups.values():
        primaries: list[Finding] = []
        for f in sorted(group, key=_preference):
            primary = next((p for p in primaries if _family(p) != _family(f)
                            and set(p["best_practices"]) & set(f["best_practices"])), None)
            if primary is None:
                primaries.append(f)
                continue
            f["duplicate_of"] = primary["id"]
            if f["source"] != primary["source"] and f["source"] not in primary["also_reported_by"]:
                primary["also_reported_by"].append(f["source"])
    for f in findings:
        f["also_reported_by"].sort()


def priority(f: Finding, node: dict[str, Any] | None, env_tag: str = DEFAULT_ENV_TAG) -> float:
    w = WEIGHT[f["severity"]]
    prod = prod_tags((node or {}).get("tags") or {}, env_tag) if node else True  # account-level findings count as prod
    if f["pillar"] == "security":
        return w + (20 if (node or {}).get("exposure") == "exposed" else 0) + (10 if prod else 0)
    if f["pillar"] == "cost":
        return (f["savings_usd"] or 0) * 10 + w / 10
    return w + (20 if prod else 0)


def summary(findings: list[Finding]) -> dict[str, Any]:
    primary = [f for f in findings if not f["duplicate_of"]]
    return {
        "open": {s: sum(1 for f in primary if f["severity"] == s) for s in WEIGHT},
        "by_pillar": {p: sum(1 for f in primary if f["pillar"] == p) for p in ("security", "cost", "reliability")},
        "savings_usd": round(sum(f["savings_usd"] or 0 for f in primary if f["pillar"] == "cost"), 2),
        "savings_estimated": any(f["savings_usd"] and f["source"] != "costhub" for f in primary if f["pillar"] == "cost"),
        "single_points_of_failure": sum(1 for f in primary if f["check_id"].startswith("REL-AZ-")),
    }


def apply(findings: list[Finding], nodes: dict[str, dict[str, Any]], env_tag: str = DEFAULT_ENV_TAG) -> dict[str, Any]:
    mark_duplicates(findings)
    for f in findings:
        f["priority"] = round(priority(f, nodes.get(f["resource"] or ""), env_tag), 2)
    return summary(findings)
