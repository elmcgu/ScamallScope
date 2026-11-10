"""Prowler JSON-OCSF findings (spec 02). Prowler writes the file; there is no fetch step."""

from __future__ import annotations

from typing import Any

from ..findings import Parsed, cover, empty_parsed, known_bps, make, severity

SOURCE = "prowler"
WA_PREFIX = "AWS-Well-Architected-Framework-"


def well_architected_bps(item: dict[str, Any]) -> list[str]:
    compliance = (item.get("unmapped") or {}).get("compliance") or {}
    ids: list[str] = []
    for framework, requirements in compliance.items():
        if str(framework).startswith(WA_PREFIX):
            ids.extend(str(r) for r in requirements or [])
    return known_bps(ids)


def _check(items: Any, name: str) -> list[dict[str, Any]]:
    if not isinstance(items, list) or not all(isinstance(i, dict) and "status_code" in i for i in items):
        raise ValueError(f"{name}: not a Prowler JSON-OCSF file (expected a list of findings with status_code)")
    return items


def parse(files: dict[str, Any], account_id: str, known_arns: set[str]) -> Parsed:
    """files: file name -> parsed JSON list. Only FAIL becomes a finding; PASS counts as coverage."""
    out = empty_parsed()
    seen: set[str] = set()
    other_account = 0
    for name, items in sorted(files.items()):
        for item in _check(items, name):
            uid = (item.get("finding_info") or {}).get("uid") or ""
            if uid and uid in seen:
                continue
            seen.add(uid)
            account = ((item.get("cloud") or {}).get("account") or {}).get("uid")
            if account and account != account_id:
                other_account += 1
                continue
            status = item.get("status_code")
            bps = well_architected_bps(item)
            if status == "PASS":
                cover(out["coverage"], bps)
                continue
            if status != "FAIL":
                continue
            cover(out["coverage"], bps, failed=True)
            res = (item.get("resources") or [{}])[0]
            arn = res.get("uid") or ""
            check = (item.get("metadata") or {}).get("event_code") or "unknown"
            out["findings"].append(make(
                SOURCE, check, (item.get("finding_info") or {}).get("title") or check,
                severity(item.get("severity")), bps,
                resource=arn if arn in known_arns else None,
                resource_name=res.get("name") or arn or check,
                region=res.get("region") or (item.get("cloud") or {}).get("region") or "global",
                detail=item.get("status_detail") or "",
                remediation=(item.get("remediation") or {}).get("desc"),
            ))
    if other_account:
        out["notes"].append(f"skipped_other_account: {other_account}")
    return out
