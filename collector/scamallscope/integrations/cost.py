"""Cost Explorer: cost by service, by tag, and by EC2 instance (spec 07)."""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from botocore.exceptions import ClientError

from .. import hosts
from ..findings import Parsed, cover, empty_parsed, make

SOURCE = "cost"
METRIC = "UnblendedCost"
EC2_COMPUTE = "Amazon Elastic Compute Cloud - Compute"
RESOURCE_DAYS = 14
COVERAGE_DAYS = 30
UNTAGGED_SHARE = 0.10
OPTIONAL_ERRORS = {"DataUnavailableException", "AccessDeniedException", "ValidationException"}


def periods(today: date) -> tuple[dict[str, str], dict[str, str]]:
    """(months, resources), end dates exclusive (R32), so both end today (data up to yesterday).
    Months: from the first day 3 full months ago. Resources: the last 14 days, the most allowed (R33)."""
    start = today.replace(day=1)
    for _ in range(3):
        start = (start - timedelta(days=1)).replace(day=1)
    return ({"Start": start.isoformat(), "End": today.isoformat()},
            {"Start": (today - timedelta(days=RESOURCE_DAYS)).isoformat(), "End": today.isoformat()})


def _all_pages(call: Any, **kwargs: Any) -> list[dict[str, Any]]:
    results, token = [], None
    while True:
        resp = call(**kwargs, **({"NextPageToken": token} if token else {}))
        results.extend(resp.get("ResultsByTime", []))
        token = resp.get("NextPageToken")  # pragma: allowlist secret
        if not token:
            return results


def fetch(session: Any, tag_key: str = "env", today: date | None = None) -> dict[str, Any]:
    ce = session.client("ce", region_name="us-east-1")
    months, recent = periods(today or date.today())
    by_service = _all_pages(ce.get_cost_and_usage, TimePeriod=months, Granularity="MONTHLY", Metrics=[METRIC],
                            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}])
    by_tag = _all_pages(ce.get_cost_and_usage, TimePeriod=months, Granularity="MONTHLY", Metrics=[METRIC],
                        GroupBy=[{"Type": "TAG", "Key": tag_key}])
    try:
        by_resource: list[dict[str, Any]] | None = _all_pages(
            ce.get_cost_and_usage_with_resources, TimePeriod=recent, Granularity="DAILY", Metrics=[METRIC],
            Filter={"Dimensions": {"Key": "SERVICE", "Values": [EC2_COMPUTE]}},
            GroupBy=[{"Type": "DIMENSION", "Key": "RESOURCE_ID"}])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in OPTIONAL_ERRORS:
            raise
        by_resource = None  # resource-level data is opt-in (R35)
    window = {"Start": ((today or date.today()) - timedelta(days=COVERAGE_DAYS)).isoformat(),
              "End": (today or date.today()).isoformat()}
    sp = _optional(lambda: _pages(ce.get_savings_plans_coverage, "SavingsPlansCoverages", "NextToken",
                                  TimePeriod=window, Granularity="MONTHLY"))
    ri = _optional(lambda: _pages(ce.get_reservation_coverage, "CoveragesByTime", "NextPageToken",
                                  TimePeriod=window, Granularity="MONTHLY"))
    return {"fetched_at": (today or date.today()).isoformat(), "tag_key": tag_key,
            "by_service": by_service, "by_tag": by_tag, "by_resource": by_resource,
            "coverage_window": window, "sp_coverage": sp, "ri_coverage": ri}


def _pages(call: Any, key: str, token_name: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Savings Plans coverage pages with NextToken, reservation coverage with NextPageToken."""
    items, token = [], None
    while True:
        resp = call(**kwargs, **({token_name: token} if token else {}))
        items.extend(resp.get(key, []))
        token = resp.get(token_name)  # pragma: allowlist secret
        if not token:
            return items


def _optional(run: Any) -> Any:
    try:
        return run()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in OPTIONAL_ERRORS:
            raise
        return None


def coverage(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Savings Plans coverage by spend, RI coverage by hours, over the coverage window (spec 11)."""
    sp, ri = raw.get("sp_coverage"), raw.get("ri_coverage")
    if sp is None and ri is None:
        return None
    out: dict[str, Any] = {"savings_plans_pct": None, "reservations_pct": None, "on_demand_usd": None,
                           "days": COVERAGE_DAYS}
    if sp is not None:
        covered = sum(float((c.get("Coverage") or {}).get("SpendCoveredBySavingsPlans") or 0) for c in sp)
        total = sum(float((c.get("Coverage") or {}).get("TotalCost") or 0) for c in sp)
        out["on_demand_usd"] = round(sum(float((c.get("Coverage") or {}).get("OnDemandCost") or 0) for c in sp), 2)
        out["savings_plans_pct"] = round(100 * covered / total, 1) if total else None
    if ri is not None:
        hours = [(c.get("Total") or {}).get("CoverageHours") or {} for c in ri]
        reserved = sum(float(h.get("ReservedHours") or 0) for h in hours)
        running = sum(float(h.get("TotalRunningHours") or 0) for h in hours)
        out["reservations_pct"] = round(100 * reserved / running, 1) if running else None
    return out


def _amount(group: dict[str, Any]) -> float:
    return float(((group.get("Metrics") or {}).get(METRIC) or {}).get("Amount") or 0)


def summary(raw: dict[str, Any]) -> dict[str, Any]:
    months = []
    for m in raw.get("by_service") or []:
        services = {g["Keys"][0]: round(_amount(g), 2) for g in m.get("Groups", [])}
        months.append({"start": m["TimePeriod"]["Start"], "end": m["TimePeriod"]["End"],
                       "estimated": bool(m.get("Estimated")), "total": round(sum(services.values()), 2),
                       "by_service": dict(sorted(services.items(), key=lambda kv: -kv[1]))})
    key = raw.get("tag_key") or "env"
    tags: list[dict[str, Any]] = []
    for m in raw.get("by_tag") or []:
        values = {}
        for g in m.get("Groups", []):
            k = g["Keys"][0]
            values[k.split("$", 1)[1] if "$" in k else k] = round(_amount(g), 2)
        tags.append({"start": m["TimePeriod"]["Start"], "values": values})
    return {"currency": "USD", "months": months, "by_tag": {"key": key, "months": tags},
            "estimated": any(m["estimated"] for m in months), "coverage": coverage(raw)}


def last_full_month(items: list[dict[str, Any]], today: date) -> dict[str, Any] | None:
    current = today.replace(day=1).isoformat()
    full = [m for m in items if m["start"] < current]
    return full[-1] if full else None


def parse(raw: dict[str, Any], index: hosts.Index, today: date | None = None) -> tuple[Parsed, dict[str, Any]]:
    if not isinstance(raw.get("by_service"), list):
        raise ValueError("cost.json: no by_service list (GetCostAndUsage ResultsByTime)")
    today = today or date.fromisoformat(str(raw.get("fetched_at", date.today().isoformat()))[:10])
    out = empty_parsed()
    totals: dict[str, float] = {}
    days: set[str] = set()
    for day in raw.get("by_resource") or []:
        days.add(day["TimePeriod"]["Start"])
        for g in day.get("Groups", []):
            totals[g["Keys"][0]] = totals.get(g["Keys"][0], 0.0) + _amount(g)
    for rid, total in totals.items():
        arn = hosts.by_instance_id(index, rid)
        if not arn:
            continue  # other EC2 resources, or instances not collected
        out["resources"][arn] = {"monthly_usd": round(total * 30 / max(len(days), 1), 2),
                                 "basis": f"last {len(days)} days x 30/{len(days)}"}
    summ = summary(raw)
    cover(out["coverage"], ["COST03-BP05"])
    month = last_full_month(summ["by_tag"]["months"], today)
    if month and sum(month["values"].values()) > 0:
        untagged = month["values"].get("", 0.0)
        share = untagged / sum(month["values"].values())
        failed = share > UNTAGGED_SHARE
        if failed:
            out["findings"].append(make(
                SOURCE, "cost-untagged-spend", f"{share:.0%} of spend has no '{summ['by_tag']['key']}' tag",
                "low", ["COST03-BP02"], None, f"account ({month['start'][:7]})", "global",
                f"${untagged:,.2f} untagged of ${sum(month['values'].values()):,.2f}",
                "Tag resources and activate the tag as a cost allocation tag."))
        cover(out["coverage"], ["COST03-BP02"], failed=failed)
    return out, summ
