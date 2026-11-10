"""Cost Optimization Hub recommendations and Compute Optimizer status (spec 11, decision 0003).

Read-only: cost-optimization-hub:ListRecommendations, compute-optimizer:GetEnrollmentStatus.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from ..findings import Parsed, cover, empty_parsed, make, severity_for_saving
from ..model import json_safe

SOURCE = "costhub"
CONSOLE = "https://console.aws.amazon.com/costmanagement/home#/cost-optimization-hub"
NOT_ENABLED = {"AccessDeniedException", "ValidationException", "OptInRequiredException"}
BP_BY_ACTION = {
    "Delete": "COST04-BP03", "Stop": "COST04-BP03",
    "Rightsize": "COST06-BP02", "Upgrade": "COST06-BP02", "MigrateToGraviton": "COST06-BP02", "ScaleIn": "COST06-BP02",
    "PurchaseSavingsPlans": "COST07-BP04", "PurchaseReservedInstances": "COST07-BP04",
}
CHECKED_BPS = ("COST04-BP03", "COST06-BP02", "COST07-BP04")


def fetch(session: Any, now: datetime | None = None) -> dict[str, Any]:
    hub = session.client("cost-optimization-hub", region_name="us-east-1")
    raw: dict[str, Any] = {"fetched_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
                           "enabled": True, "reason": None, "recommendations": []}
    try:
        for page in hub.get_paginator("list_recommendations").paginate(includeAllRecommendations=False):
            raw["recommendations"].extend(page.get("items", []))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in NOT_ENABLED:
            raise
        raw.update(enabled=False, reason=f"{err.get('Code')}: {err.get('Message', '')}"[:200], recommendations=[])
    try:
        raw["compute_optimizer"] = session.client("compute-optimizer", region_name="us-east-1").get_enrollment_status().get("status")
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
        return f"{action} {rid}: {rec.get('currentResourceSummary') or rtype} to {rec.get('recommendedResourceSummary') or rec.get('recommendedResourceType') or '?'}"
    if action.startswith("Purchase"):
        return f"Buy {rec.get('recommendedResourceType') or 'commitment'}: {rec.get('recommendedResourceSummary') or ''}".strip()
    return f"{action} {rtype} {rid}"


def parse(raw: dict[str, Any], known: set[str]) -> Parsed:
    if not isinstance(raw.get("recommendations"), list) or "enabled" not in raw:
        raise ValueError("costhub.json: no enabled flag or recommendations list")
    out = empty_parsed()
    if not raw["enabled"]:
        out["notes"].append(f"Cost Optimization Hub not enabled: {raw.get('reason') or ''}".strip())
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
