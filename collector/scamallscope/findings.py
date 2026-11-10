"""One shape for every issue from every source, and the Well-Architected catalogue (spec 01)."""

from __future__ import annotations

import json
import re
from functools import cache
from importlib import resources
from typing import Any, Literal, TypedDict

Severity = Literal["critical", "high", "medium", "low", "info"]
Pillar = Literal["security", "reliability", "cost"]

SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low", "info")
PILLARS: tuple[Pillar, ...] = ("security", "reliability", "cost")
BP_PATTERN = re.compile(r"^(SEC|REL|COST)\d{2}-BP\d{2}$")
PILLAR_BY_PREFIX: dict[str, Pillar] = {"SEC": "security", "REL": "reliability", "COST": "cost"}


class Finding(TypedDict):
    id: str
    source: str
    check_id: str
    title: str
    severity: Severity
    pillar: Pillar
    best_practices: list[str]
    resource: str | None
    resource_name: str
    region: str
    detail: str
    remediation: str | None
    savings_usd: float | None  # estimated saving a month (cost findings); null otherwise
    priority: float  # set by rank.apply; higher first, compared within a pillar (spec 13)
    duplicate_of: str | None  # id of the primary finding for the same issue
    also_reported_by: list[str]  # other sources that found the same issue


class Coverage(TypedDict):
    """What one source checked for one best practice."""

    passed: int
    failed: int


class Parsed(TypedDict):
    """What every integration parse() returns."""

    findings: list[Finding]
    resources: dict[str, dict[str, Any]]  # ARN -> this source's data for the node
    coverage: dict[str, Coverage]  # BP ID -> counts
    unmatched: list[str]
    notes: list[str]


def empty_parsed() -> Parsed:
    return {"findings": [], "resources": {}, "coverage": {}, "unmatched": [], "notes": []}


@cache
def catalogue() -> dict[str, Any]:
    """Well-Architected questions and best practices for security, reliability and cost (R6)."""
    text = resources.files("scamallscope").joinpath("data/well_architected.json").read_text(encoding="utf-8")
    return json.loads(text)


def best_practices() -> dict[str, dict[str, str]]:
    return catalogue()["best_practices"]


def severity(value: Any) -> Severity:
    """Prowler and Wazuh severities (any case) to ours; anything else is info."""
    v = str(value or "").strip().lower()
    if v == "informational":
        return "info"
    return v if v in SEVERITIES else "info"  # type: ignore[return-value]


def known_bps(ids: list[str] | tuple[str, ...]) -> list[str]:
    """Keep only IDs in the catalogue, sorted and unique."""
    cat = best_practices()
    return sorted({i for i in ids if BP_PATTERN.match(i) and i in cat})


def pillar_of(bps: list[str], default: Pillar = "security") -> Pillar:
    return PILLAR_BY_PREFIX[bps[0].split("-")[0].rstrip("0123456789")] if bps else default


def clip(text: Any, limit: int = 300) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def make(source: str, check_id: str, title: str, severity_: Severity, bps: list[str],
         resource: str | None, resource_name: str, region: str, detail: str = "",
         remediation: str | None = None, pillar: Pillar | None = None,
         savings_usd: float | None = None) -> Finding:
    kept = known_bps(bps)
    return {
        "id": f"{source}:{check_id}:{resource or resource_name}",
        "source": source,
        "check_id": check_id,
        "title": clip(title, 200),
        "severity": severity_,
        "pillar": pillar or pillar_of(kept),
        "best_practices": kept,
        "resource": resource,
        "resource_name": resource_name,
        "region": region,
        "detail": clip(detail),
        "remediation": clip(remediation) if remediation else None,
        "savings_usd": round(float(savings_usd), 2) if savings_usd is not None else None,
        "priority": 0.0,
        "duplicate_of": None,
        "also_reported_by": [],
    }


def severity_for_saving(usd: float | None) -> Severity:
    """Cost findings: severity by estimated saving a month (spec 11)."""
    v = usd or 0
    return "high" if v >= 100 else "medium" if v >= 20 else "low" if v >= 1 else "info"


def cover(coverage: dict[str, Coverage], bps: list[str] | tuple[str, ...], failed: bool = False, n: int = 1) -> None:
    """Record that a source checked these best practices (passed or failed)."""
    for bp in known_bps(list(bps)):
        c = coverage.setdefault(bp, {"passed": 0, "failed": 0})
        c["failed" if failed else "passed"] += n


def worst(severities: list[Severity]) -> Severity | None:
    for s in SEVERITIES:
        if s in severities:
            return s
    return None


def counts(findings: list[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITIES}
    for f in findings:
        out[f["severity"]] += 1
    return out
