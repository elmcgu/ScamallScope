import json
import stat

from botocore.exceptions import ClientError

from scamallscope import snapshot
from scamallscope.cli import main
from scamallscope.model import is_complete

REGION = "eu-west-1"


def build_estate(session):
    ec2 = session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(
        CidrBlock="10.0.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": "main"}]}],
    )["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(
        ImageId=image, MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[sg]
    )["Instances"][0]["InstanceId"]
    return vpc, subnet, sg, instance


def arn(kind, rid):
    return f"arn:aws:ec2:{REGION}:123456789012:{kind}/{rid}"


def test_collects_resources_and_links(session):
    vpc, subnet, sg, instance = build_estate(session)

    snap = snapshot.collect(session, [REGION])

    assert is_complete(snap)
    assert snap["account_id"] == "123456789012"
    by_arn = {r["arn"]: r for r in snap["resources"]}
    for kind, rid in [("vpc", vpc), ("subnet", subnet), ("security-group", sg), ("instance", instance)]:
        assert arn(kind, rid) in by_arn
        assert by_arn[arn(kind, rid)]["account_id"] == "123456789012"
    assert by_arn[arn("vpc", vpc)]["name"] == "main"

    links = {(l["source"], l["target"], l["type"]) for l in snap["links"]}
    assert (arn("vpc", vpc), arn("subnet", subnet), "contains") in links
    assert (arn("vpc", vpc), arn("security-group", sg), "contains") in links
    assert (arn("subnet", subnet), arn("instance", instance), "contains") in links
    assert (arn("instance", instance), arn("security-group", sg), "uses") in links


def test_skips_terminated_instances(session):
    *_, instance = build_estate(session)
    session.client("ec2", region_name=REGION).terminate_instances(InstanceIds=[instance])

    snap = snapshot.collect(session, [REGION])

    assert arn("instance", instance) not in {r["arn"] for r in snap["resources"]}


def test_failed_call_is_an_error_not_an_empty_list(session):
    build_estate(session)

    def deny(**kwargs):
        raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}, "DescribeInstances")

    # Clients made from this session inherit the handler; it fires before the API call.
    session.events.register("before-call.ec2.DescribeInstances", deny)

    snap = snapshot.collect(session, [REGION])

    assert not is_complete(snap)
    units = {u["resource_type"]: u for u in snap["units"]}
    assert units["instance"]["status"] == "error"
    assert (units["instance"]["error"] or "").startswith("UnauthorizedOperation")
    assert units["vpc"]["status"] == "ok"  # other units still collected
    assert not [r for r in snap["resources"] if r["type"] == "instance"]


def test_cli_writes_private_json(session, tmp_path, monkeypatch, capsys):
    build_estate(session)
    monkeypatch.setattr("scamallscope.cli.boto3.Session", lambda **kw: session)
    out = tmp_path / "s.snapshot.json"

    code = main(["collect", "--region", REGION, "--output", str(out)])

    assert code == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    data = json.loads(out.read_text())
    assert data["schema_version"] == 1
    assert {r["type"] for r in data["resources"]} >= {"vpc", "subnet", "security-group", "instance"}


def test_snapshot_is_plain_json_data(session):
    """The snapshot dict is already JSON: dates are strings, no custom encoder needed."""
    build_estate(session)

    snap = snapshot.collect(session, [REGION])

    assert json.loads(json.dumps(snap)) == snap
    instance = next(r for r in snap["resources"] if r["type"] == "instance")
    assert isinstance(instance["config"]["LaunchTime"], str)
