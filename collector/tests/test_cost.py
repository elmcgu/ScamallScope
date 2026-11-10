from datetime import date

from botocore.stub import Stubber
import boto3

from scamallscope import hosts
from scamallscope.integrations import cost

import estate
from helpers import fixture

WEB = estate.iarn("i-0web1")
TODAY = date(2026, 11, 4)


def parse(raw=None):
    return cost.parse(raw or fixture("cost.json"), hosts.build(estate.snapshot()), TODAY)


def test_CST_1_months_and_services():
    _, s = parse()
    oct_ = next(m for m in s["months"] if m["start"] == "2026-10-01")
    assert oct_["total"] == 72.0
    assert list(oct_["by_service"])[0] == "Amazon Elastic Compute Cloud - Compute"
    assert s["estimated"] is True


def test_CST_2_tag_values():
    _, s = parse()
    oct_ = next(m for m in s["by_tag"]["months"] if m["start"] == "2026-10-01")
    assert oct_["values"] == {"prod": 52.0, "dev": 5.0, "": 15.0}


def test_CST_3_monthly_estimate_per_instance():
    p, _ = parse()
    assert p["resources"][WEB]["monthly_usd"] == 30.0
    assert all("notcollected" not in a for a in p["resources"])


def test_CST_4_no_resource_data():
    raw = fixture("cost.json")
    raw["by_resource"] = None
    p, s = parse(raw)
    assert p["resources"] == {} and s["months"]


def test_CST_5_untagged_share():
    p, _ = parse()
    f = next(f for f in p["findings"] if f["check_id"] == "cost-untagged-spend")
    assert f["best_practices"] == ["COST03-BP02"] and "21%" in f["title"]


def test_CST_6_fetch_when_resource_data_not_enabled():
    session = boto3.Session(region_name="us-east-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    ce = session.client("ce", region_name="us-east-1")
    page = {"ResultsByTime": [{"TimePeriod": {"Start": "2026-10-01", "End": "2026-11-01"}, "Groups": [], "Total": {}, "Estimated": False}]}
    with Stubber(ce) as stub:
        stub.add_response("get_cost_and_usage", {**page, "NextPageToken": "p2"})
        stub.add_response("get_cost_and_usage", page)
        stub.add_response("get_cost_and_usage", page)
        stub.add_client_error("get_cost_and_usage_with_resources", "DataUnavailableException", "not enabled")

        class S:
            def client(self, *a, **k):
                return ce

        raw = cost.fetch(S(), "env", TODAY)
    assert len(raw["by_service"]) == 2 and len(raw["by_tag"]) == 1
    assert raw["by_resource"] is None


def test_CST_7_periods():
    months, recent = cost.periods(TODAY)
    assert months == {"Start": "2026-08-01", "End": "2026-11-04"}
    assert recent == {"Start": "2026-10-21", "End": "2026-11-04"}
