import re
from datetime import datetime, timezone

import boto3
from moto import mock_aws

from scamallscope import hosts, snapshot
from scamallscope.integrations import cloudwatch

import estate
from helpers import fixture
from test_snapshot import REGION, build_estate

WEB, APP, DUP = estate.iarn("i-0web1"), estate.iarn("i-0app1"), estate.iarn("i-0dup1")


def parse():
    return cloudwatch.parse(fixture("cloudwatch.json"), hosts.build(estate.snapshot()))


def test_CWM_1_average_and_peak():
    m = parse()["resources"][APP]
    assert m == {"cpu_avg": 1.9, "cpu_max": 9.0, "days": 14, "alarms": 0, "recover_alarm": False}


def test_CWM_2_no_data_is_not_idle():
    assert parse()["resources"][DUP]["cpu_avg"] is None


def test_CWM_3_alarms_by_instance_dimension():
    r = parse()["resources"]
    assert r[WEB]["alarms"] == 1 and r[APP]["alarms"] == 0


def test_CWM_4_fetch_with_moto(session):
    *_, instance = build_estate(session)
    ec2 = session.client("ec2", region_name=REGION)
    second = ec2.run_instances(ImageId=ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"],
                               MinCount=1, MaxCount=1)["Instances"][0]["InstanceId"]
    session.client("cloudwatch", region_name=REGION).put_metric_alarm(
        AlarmName="cpu", MetricName="CPUUtilization", Namespace="AWS/EC2", Statistic="Average", Period=300,
        EvaluationPeriods=1, Threshold=90, ComparisonOperator="GreaterThanThreshold",
        Dimensions=[{"Name": "InstanceId", "Value": instance}])
    snap = snapshot.collect(session, [REGION], include_global=False)
    raw = cloudwatch.fetch(session, snap, now=datetime(2026, 11, 4, 6, tzinfo=timezone.utc))
    data = raw["regions"][REGION]
    assert {t.split("|")[0] for t in data["queries"].values()} == {instance, second}
    assert [a["AlarmName"] for a in data["alarms"]] == ["cpu"]
    out = cloudwatch.parse(raw, hosts.build(snap))
    arn = next(a for a in out["resources"] if a.endswith(instance))
    assert out["resources"][arn]["alarms"] == 1


def test_CWM_5_query_ids_valid_and_unique():
    ids = cloudwatch.query_ids(["i-0b", "i-0a", "i-0c"])
    assert len(ids) == 6 and all(re.fullmatch(r"[a-z][a-zA-Z0-9_]*", i) for i in ids)


def test_recover_alarm_is_seen():
    import estate
    from scamallscope import hosts
    raw = {"days": 14, "regions": {"eu-west-1": {
        "queries": {"q0_avg": "i-0web1|avg", "q0_max": "i-0web1|max"}, "results": [],
        "alarms": [{"AlarmName": "recover", "Dimensions": [{"Name": "InstanceId", "Value": "i-0web1"}], "RecoverAction": True}]}}}
    m = cloudwatch.parse(raw, hosts.build(estate.snapshot()))["resources"][estate.iarn("i-0web1")]
    assert m["recover_alarm"] is True and m["alarms"] == 1
