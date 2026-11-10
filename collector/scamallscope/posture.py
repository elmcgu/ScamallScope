"""Well-Architected scorecard: issues, clear or not checked, per best practice (spec 01)."""

from __future__ import annotations

from typing import Any

from .findings import PILLARS, Coverage, Finding, best_practices


def scorecard(findings: list[Finding], coverage_by_source: dict[str, dict[str, Coverage]]) -> dict[str, Any]:
    by_bp: dict[str, int] = {}
    for f in findings:
        for bp in f["best_practices"]:
            by_bp[bp] = by_bp.get(bp, 0) + 1
    checked_by: dict[str, set[str]] = {}
    for source, cov in coverage_by_source.items():
        for bp in cov:
            checked_by.setdefault(bp, set()).add(source)
    for f in findings:  # a finding is evidence that its source checks that BP
        for bp in f["best_practices"]:
            checked_by.setdefault(bp, set()).add(f["source"])

    out: dict[str, Any] = {}
    for pillar in PILLARS:
        rows = []
        for bp, info in best_practices().items():
            if info["pillar"] != pillar:
                continue
            n = by_bp.get(bp, 0)
            status = "issues" if n else "clear" if bp in checked_by else "not_checked"
            rows.append({"id": bp, "title": info["title"], "url": info["url"], "status": status,
                         "findings": n, "checked_by": sorted(checked_by.get(bp, set()))})
        summary = {s: sum(1 for r in rows if r["status"] == s) for s in ("issues", "clear", "not_checked")}
        out[pillar] = {"best_practices": rows, "summary": summary}
    return out
