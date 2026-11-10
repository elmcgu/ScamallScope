"""Spec 11: Cost Optimization Hub (botocore Stubber; moto 5.2.5 has neither service)."""

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from scamallscope.integrations import costhub

ACCOUNT = "123456789012"
VOL = f"arn:aws:ec2:eu-west-1:{ACCOUNT}:volume/vol-0old"
WEB = f"arn:aws:ec2:eu-west-1:{ACCOUNT}:instance/i-0web1"


class FakeSession:
    def __init__(self, hub, co):
        self.clients = {"cost-optimization-hub": hub, "compute-optimizer": co}

    def client(self, name, region_name=None):
        return self.clients[name]


def rec(rid, arn, action, saving, rtype="EbsVolume", **extra):
    return {"recommendationId": f"r-{rid}", "accountId": ACCOUNT, "region": "eu-west-1", "resourceId": rid,
            "resourceArn": arn, "currentResourceType": rtype, "actionType": action,
            "estimatedMonthlySavings": saving, "estimatedMonthlyCost": saving * 2, "currencyCode": "USD",
            "implementationEffort": "Low", "restartNeeded": False, "rollbackPossible": True,
            "recommendationLookbackPeriodInDays": 14, **extra}


def stubbed(pages=None, hub_error=None, co_status="Active"):
    hub = boto3.client("cost-optimization-hub", region_name="us-east-1")
    co = boto3.client("compute-optimizer", region_name="us-east-1")
    hs, cs = Stubber(hub), Stubber(co)
    if hub_error:
        hs.add_client_error("list_recommendations", service_error_code=hub_error, service_message="not enrolled")
    else:
        for n, items in enumerate(pages or [[]]):
            resp: dict = {"items": items}
            if n < len(pages or [[]]) - 1:
                resp["nextToken"] = f"t{n}"  # pragma: allowlist secret
            params: dict = {"includeAllRecommendations": False}
            if n:
                params["nextToken"] = f"t{n - 1}"  # pragma: allowlist secret
            hs.add_response("list_recommendations", resp, params)
    cs.add_response("get_enrollment_status", {"status": co_status})
    hs.activate()
    cs.activate()
    return FakeSession(hub, co)


def test_COH_1_all_pages():
    raw = costhub.fetch(stubbed([[rec("vol-0old", VOL, "Delete", 12.5)], [rec("i-0web1", WEB, "Rightsize", 150, "Ec2Instance")]]))
    assert raw["enabled"] is True and [r["resourceId"] for r in raw["recommendations"]] == ["vol-0old", "i-0web1"]
    assert raw["compute_optimizer"] == "Active"


def test_COH_2_not_enabled_is_not_an_error():
    raw = costhub.fetch(stubbed(hub_error="AccessDeniedException"))
    assert raw["enabled"] is False and raw["recommendations"] == [] and "AccessDeniedException" in raw["reason"]


def test_COH_3_other_errors_raise():
    with pytest.raises(ClientError):
        costhub.fetch(stubbed(hub_error="ThrottlingException"))


def parsed(*recs, enabled=True, co="Active"):
    raw = {"fetched_at": "2026-11-10T06:00:00+00:00", "enabled": enabled, "compute_optimizer": co,
           "recommendations": list(recs)}
    return costhub.parse(raw, {VOL, WEB})


def test_COH_4_delete_volume():
    (f,) = parsed(rec("vol-0old", VOL, "Delete", 12.5))["findings"]
    assert (f["check_id"], f["best_practices"], f["savings_usd"], f["severity"], f["pillar"]) == \
        ("COST-HUB-Delete", ["COST04-BP03"], 12.5, "low", "cost")
    assert f["resource"] == VOL and str(f["remediation"]).startswith("Review in Cost Optimization Hub")


def test_COH_5_rightsize_instance():
    (f,) = parsed(rec("i-0web1", WEB, "Rightsize", 150, "Ec2Instance", currentResourceSummary="m5.xlarge",
                      recommendedResourceSummary="m5.large"))["findings"]
    assert f["best_practices"] == ["COST06-BP02"] and f["severity"] == "high"
    assert "m5.xlarge to m5.large" in f["title"] and "effort Low" in f["detail"]


def test_COH_6_savings_plan_has_no_resource():
    (f,) = parsed(rec("sp", None, "PurchaseSavingsPlans", 40, "ComputeSavingsPlans",
                      recommendedResourceType="ComputeSavingsPlans"))["findings"]
    assert f["best_practices"] == ["COST07-BP04"] and f["resource"] is None and f["severity"] == "medium"


def test_COH_7_not_enabled_checks_nothing():
    out = parsed(enabled=False)
    assert out["findings"] == [] and out["coverage"] == {} and "not enabled" in out["notes"][0]


def test_compute_optimizer_inactive_is_noted():
    out = parsed(rec("vol-0old", VOL, "Delete", 1), co="Inactive")
    assert any("Compute Optimizer status Inactive" in n for n in out["notes"])
    assert set(out["coverage"]) == set(costhub.CHECKED_BPS)


def test_unknown_resource_is_not_linked():
    (f,) = parsed(rec("vol-0gone", VOL.replace("old", "gone"), "Delete", 3))["findings"]
    assert f["resource"] is None and f["resource_name"] == "vol-0gone"
