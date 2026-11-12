"""Cost Optimization Hub recommendations and Compute Optimizer status (spec 11, decision 0003).

Read-only: cost-optimization-hub:ListEnrollmentStatuses, cost-optimization-hub:ListRecommendations,
compute-optimizer:GetEnrollmentStatus.

State: "enabled", "not_enabled" (the account's enrollment status is not Active) or "access_denied"
(a missing IAM permission). Any other error, ValidationException included, fails the fetch.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from ..findings import Parsed, cover, empty_parsed, make, severity_for_saving
from ..model import json_safe

SOURCE = "costhub"
CONSOLE = "https://console.aws.amazon.com/costmanagement/home#/cost-optimization-hub"
DENIED = {"AccessDeniedException"}
BP_BY_ACTION = {
    "Delete": "COST04-BP03", "Stop": "COST04-BP03",
    "Rightsize": "COST06-BP02", "Upgrade": "COST06-BP02", "MigrateToGraviton": "COST06-BP02", "ScaleIn": "COST06-BP02",
    "PurchaseSavingsPlans": "COST07-BP04", "PurchaseReservedInstances": "COST07-BP04",
}
CHECKED_BPS = ("COST04-BP03", "COST06-BP02", "COST07-BP04")


def _denied(raw: dict[str, Any], exc: ClientError) -> None:
    err = exc.response.get("Error", {})
    if err.get("Code") not in DENIED:
        raise exc
    raw.update(state="access_denied", enabled=False, recommendations=[],
               reason=f"{err.get('Code')}: {err.get('Message', '')}"[:200])


def fetch(session: Any, now: datetime | None = None) -> dict[str, Any]:
    hub = session.client("cost-optimization-hub", region_name="us-east-1")
    raw: dict[str, Any] = {"fetched_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
                           "state": "enabled", "enabled": True, "reason": None, "recommendations": []}
    try:
        statuses = [i for page in hub.get_paginator("list_enrollment_statuses").paginate() for i in page.get("items", [])]
        if not any(i.get("status") == "Active" for i in statuses):
            raw.update(state="not_enabled", enabled=False,
                       reason="enrollment status: " + (", ".join(sorted({str(i.get("status")) for i in statuses})) or "none"))
        else:
            for page in hub.get_paginator("list_recommendations").paginate(includeAllRecommendations=False):
                raw["recommendations"].extend(page.get("items", []))
    except ClientError as exc:
        _denied(raw, exc)
    try:
        optimizer = session.client("compute-optimizer", region_name="us-east-1")
        raw["compute_optimizer"] = optimizer.get_enrollment_status().get("status")
    except ClientError as exc:
        raw["compute_optimizer"] = f"unknown ({exc.response.get('Error', {}).get('Code')})"
    return json_safe(raw)


def _title(action: str, rec: dict[str, Any]) -> str:
    rtype, rid = rec.get("currentResourceType") or "resource", rec.get("resourceId") or "?"
    if action == "Delete":
        return f"Delete unused {rtype} {rid}"
    if action == "Stop":
        return f"Stop idle {rtype} {rid}"
    if action in ("Rightsize", "Upgrade", "MigrateToGraviton"):
        target = rec.get("recommendedResourceSummary") or rec.get("recommendedResourceType") or "?"
        return f"{action} {rid}: {rec.get('currentResourceSummary') or rtype} to {target}"
    if action.startswith("Purchase"):
        return f"Buy {rec.get('recommendedResourceType') or 'commitment'}: {rec.get('recommendedResourceSummary') or ''}".strip()
    return f"{action} {rtype} {rid}"


def parse(raw: dict[str, Any], known: set[str]) -> Parsed:
    if not isinstance(raw.get("recommendations"), list) or "enabled" not in raw:
        raise ValueError("costhub.json: no enabled flag or recommendations list")
    out = empty_parsed()
    if not raw["enabled"]:
        state = raw.get("state") or "not_enabled"
        what = "could not be read (check the IAM policy)" if state == "access_denied" else "is not enabled"
        out["notes"].append(f"{state}: Cost Optimization Hub {what}. {raw.get('reason') or ''}".strip())
        return out
    for rec in raw["recommendations"]:
        action = rec.get("actionType") or "Other"
        saving = float(rec.get("estimatedMonthlySavings") or 0)
        arn = rec.get("resourceArn")
        detail = (f"effort {rec.get('implementationEffort', '?')}, restart needed {rec.get('restartNeeded')}, "
                  f"rollback possible {rec.get('rollbackPossible')}, "
                  f"lookback {rec.get('recommendationLookbackPeriodInDays', '?')} days")
        out["findings"].append(make(
            SOURCE, f"COST-HUB-{action}", _title(action, rec), severity_for_saving(saving),
            [BP_BY_ACTION.get(action, "COST06-BP02")], arn if arn in known else None,
            rec.get("resourceId") or arn or rec.get("recommendationId", "?"), rec.get("region") or "global",
            detail, f"Review in Cost Optimization Hub: {CONSOLE}", pillar="cost", savings_usd=saving))
    cover(out["coverage"], CHECKED_BPS)
    co = raw.get("compute_optimizer")
    if co != "Active":
        out["notes"].append(f"Compute Optimizer status {co}: no rightsizing or idle recommendations until it is Active "
                            "with 14 days of metrics")
    return out
