"""S3, IAM and Lambda collectors, exposure and admin checks (moto)."""

import io
import json
import zipfile
from urllib.parse import unquote

import pytest
from botocore.exceptions import ClientError

from scamallscope import exposure, graph, iam_analysis, snapshot
from scamallscope.model import is_complete

REGION = "eu-west-1"
ACCT = "123456789012"
PUBLIC_READ = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::{b}/*"}]}
ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
LAMBDA_TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}


def by_name(snap, type_):
    return {r["name"]: r for r in snap["resources"] if r["type"] == type_}


def nodes(snap):
    return {e["data"]["label"]: e["data"] for e in graph.to_graph(snap)["elements"] if e["group"] == "nodes"}


# ---- S3 -------------------------------------------------------------------------------

def make_bucket(s3, name, policy=False, acl=None, block=None):
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    if block is not None:
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=block)
    if policy:
        s3.put_bucket_policy(Bucket=name, Policy=json.dumps(PUBLIC_READ).replace("{b}", name))
    if acl:
        s3.put_bucket_acl(Bucket=name, ACL=acl)


NO_BLOCK = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}


def test_buckets_are_global_with_their_location(session):
    make_bucket(session.client("s3", region_name=REGION), "private-data")

    snap = snapshot.collect(session, [REGION])

    b = by_name(snap, "bucket")["private-data"]
    assert b["region"] == "global" and b["arn"] == "arn:aws:s3:::private-data"
    assert b["config"]["Region"] == REGION
    assert "global" in snap["regions"] and is_complete(snap)


def test_bucket_exposure(session):
    s3 = session.client("s3", region_name=REGION)
    make_bucket(s3, "public-policy", policy=True, block=NO_BLOCK)
    make_bucket(s3, "public-acl", acl="public-read", block=NO_BLOCK)
    make_bucket(s3, "private")
    snap = snapshot.collect(session, [REGION])
    result = exposure.analyse(snap)
    b = by_name(snap, "bucket")

    assert result[b["public-policy"]["arn"]] == {"exposure": "exposed", "reason": "bucket policy allows public access", "ports": []}
    assert result[b["public-acl"]["arn"]]["reason"] == "ACL grants access to everyone"
    assert result[b["private"]["arn"]]["exposure"] == "not_exposed"


def test_account_block_public_access_stops_a_public_policy(session):
    s3 = session.client("s3", region_name=REGION)
    make_bucket(s3, "public-policy", policy=True, block=NO_BLOCK)
    session.client("s3control", region_name=REGION).put_public_access_block(
        AccountId=ACCT, PublicAccessBlockConfiguration={**NO_BLOCK, "RestrictPublicBuckets": True})

    snap = snapshot.collect(session, [REGION])

    r = exposure.analyse(snap)[by_name(snap, "bucket")["public-policy"]["arn"]]
    assert r["exposure"] == "not_exposed" and "Block Public Access" in r["reason"]


def test_bucket_detail_error_makes_exposure_unknown(session):
    make_bucket(session.client("s3", region_name=REGION), "locked")

    def deny(**kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetBucketPolicyStatus")

    session.events.register("before-call.s3.GetBucketPolicyStatus", deny)
    snap = snapshot.collect(session, [REGION])

    b = by_name(snap, "bucket")["locked"]
    assert b["config"]["DetailErrors"]["PolicyStatus"].startswith("AccessDenied")
    assert exposure.analyse(snap)[b["arn"]]["exposure"] == "unknown"


# ---- IAM ------------------------------------------------------------------------------

@pytest.fixture
def managed_policies(monkeypatch):
    """moto only knows AWS managed policies (AdministratorAccess) when asked to load them."""
    monkeypatch.setenv("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")


def make_iam(session):
    iam = session.client("iam")
    iam.create_role(RoleName="web-role", AssumeRolePolicyDocument=json.dumps(
        {**LAMBDA_TRUST, "Statement": [{**LAMBDA_TRUST["Statement"][0], "Principal": {"Service": "ec2.amazonaws.com"}}]}))
    iam.create_instance_profile(InstanceProfileName="web-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="web-profile", RoleName="web-role")
    iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=json.dumps(LAMBDA_TRUST))
    policy_arn = iam.create_policy(PolicyName="everything", PolicyDocument=json.dumps(ADMIN_DOC))["Policy"]["Arn"]
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=policy_arn)
    iam.create_user(UserName="alice")
    iam.add_user_to_group(GroupName="admins", UserName="alice")
    iam.create_user(UserName="bob")
    iam.put_user_policy(UserName="bob", PolicyName="readonly", PolicyDocument=json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}))
    iam.create_role(RoleName="ops", AssumeRolePolicyDocument=json.dumps(LAMBDA_TRUST))
    iam.attach_role_policy(RoleName="ops", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    return iam


def test_iam_resources_links_and_admins(managed_policies, session):
    make_iam(session)

    snap = snapshot.collect(session, [REGION])

    users, groups, roles, policies = (by_name(snap, t) for t in ("user", "group", "role", "policy"))
    assert {"alice", "bob"} <= set(users) and "admins" in groups and {"web-role", "ops"} <= set(roles)
    assert "AdministratorAccess" in policies and policies["AdministratorAccess"]["config"]["AwsManaged"] is True
    links = {(l["source"], l["target"], l["type"]) for l in snap["links"]}
    assert (users["alice"]["arn"], groups["admins"]["arn"], "member_of") in links
    assert (groups["admins"]["arn"], policies["everything"]["arn"], "attached") in links

    admins = iam_analysis.admin_principals(snap)
    assert admins[groups["admins"]["arn"]] == "policy everything allows * on *"
    assert admins[users["alice"]["arn"]] == "member of admin group admins"
    assert admins[roles["ops"]["arn"]] == "AdministratorAccess attached"
    assert users["bob"]["arn"] not in admins

    n = nodes(snap)
    assert n["alice"]["admin"] is True and n["bob"]["admin"] is False
    assert n["web-role"]["trusted_principals"] == ["ec2.amazonaws.com"]
    assert n["everything"]["admin"] is True


def test_instance_assumes_role_through_instance_profile(managed_policies, session):
    make_iam(session)
    ec2 = session.client("ec2", region_name=REGION)
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1,
                                 IamInstanceProfile={"Name": "web-profile"})["Instances"][0]["InstanceId"]

    snap = snapshot.collect(session, [REGION])

    role = by_name(snap, "role")["web-role"]["arn"]
    inst = f"arn:aws:ec2:{REGION}:{ACCT}:instance/{instance}"
    assert (inst, role, "assumes") in {(l["source"], l["target"], l["type"]) for l in snap["links"]}


def test_iam_failure_marks_all_iam_units_failed(session):
    def deny(**kwargs):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetAccountAuthorizationDetails")

    session.events.register("before-call.iam.GetAccountAuthorizationDetails", deny)
    snap = snapshot.collect(session, [REGION])

    failed = {u["resource_type"] for u in snap["units"] if u["status"] == "error"}
    assert failed == {"user", "group", "role", "policy"}


def test_include_global_false_skips_iam_and_s3(session):
    snap = snapshot.collect(session, [REGION], include_global=False)

    assert "global" not in snap["regions"]
    assert not [u for u in snap["units"] if u["service"] in ("iam", "s3")]


@pytest.mark.parametrize("doc, admin", [
    (ADMIN_DOC, True),
    ({"Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}}, True),
    ({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}, False),
    ({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}, False),
    ({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}, False),
    ("%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22%2A%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D", True),
])
def test_grants_admin(doc, admin):
    assert iam_analysis.grants_admin(doc) is admin


# ---- Lambda ---------------------------------------------------------------------------

def zipped():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(event, context):\n    return 'ok'\n")
    return buf.getvalue()


def make_function(session, name, url_auth=None, vpc=None, env=None):
    role = session.client("iam").get_role(RoleName="lambda-role")["Role"]["Arn"]
    lam = session.client("lambda", region_name=REGION)
    kwargs = {"VpcConfig": vpc} if vpc else {}
    if env:
        kwargs["Environment"] = {"Variables": env}
    lam.create_function(FunctionName=name, Runtime="python3.12", Role=role, Handler="index.handler",
                        Code={"ZipFile": zipped()}, Tags={"team": "ops"}, **kwargs)
    if url_auth:
        lam.create_function_url_config(FunctionName=name, AuthType=url_auth)
    return role


def test_lambda_environment_values_are_never_stored(managed_policies, session):
    make_iam(session)
    make_function(session, "app", env={"DB_PASSWORD": "hunter2-not-real", "STAGE": "prod"})

    snap = snapshot.collect(session, [REGION])

    fn = by_name(snap, "function")["app"]
    assert fn["config"]["EnvironmentVariableNames"] == ["DB_PASSWORD", "STAGE"]
    assert "Environment" not in fn["config"]
    assert "hunter2-not-real" not in json.dumps(snap)
    assert fn["tags"] == {"team": "ops"}


def stand_in_for_list_function_url_configs(session):
    """moto does not implement ListFunctionUrlConfigs (it returns "404: Not yet implemented").

    Answer it from GetFunctionUrlConfig, which moto has. A before-call handler that returns
    (http response, parsed body) replaces the API call.
    """
    lam = session.client("lambda", region_name=REGION)

    class Ok:
        status_code = 200

    def handler(params, **kwargs):
        # params is the serialised request; the name is in the path /2021-10-31/functions/<name>/urls
        name = unquote(params["url_path"].split("/functions/", 1)[1].split("/", 1)[0])
        try:
            url = lam.get_function_url_config(FunctionName=name)
            configs = [{k: url[k] for k in ("FunctionUrl", "FunctionArn", "AuthType")}]
        except lam.exceptions.ResourceNotFoundException:
            configs = []
        return Ok(), {"FunctionUrlConfigs": configs}

    session.events.register("before-call.lambda.ListFunctionUrlConfigs", handler)


def test_lambda_url_error_makes_exposure_unknown(managed_policies, session):
    make_iam(session)
    make_function(session, "app", url_auth="NONE")

    snap = snapshot.collect(session, [REGION])  # no stand-in: moto's 404 acts as a failed call

    fn = by_name(snap, "function")["app"]
    assert "FunctionUrlConfigs" in fn["config"]["DetailErrors"]
    assert exposure.analyse(snap)[fn["arn"]]["exposure"] == "unknown"


def test_lambda_links_and_url_exposure(managed_policies, session):
    make_iam(session)
    stand_in_for_list_function_url_configs(session)
    ec2 = session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    sg = ec2.create_security_group(GroupName="fn", Description="fn", VpcId=vpc)["GroupId"]
    role = make_function(session, "public-url", url_auth="NONE")
    make_function(session, "iam-url", url_auth="AWS_IAM")
    make_function(session, "in-vpc", vpc={"SubnetIds": [subnet], "SecurityGroupIds": [sg]})

    snap = snapshot.collect(session, [REGION])

    fns = by_name(snap, "function")
    result = exposure.analyse(snap)
    assert result[fns["public-url"]["arn"]]["exposure"] == "exposed"
    assert result[fns["iam-url"]["arn"]]["reason"] == "function URL requires IAM authentication"
    assert result[fns["in-vpc"]["arn"]]["exposure"] == "not_exposed"
    links = {(l["source"], l["target"], l["type"]) for l in snap["links"]}
    assert (fns["public-url"]["arn"], role, "assumes") in links
    assert (fns["in-vpc"]["arn"], f"arn:aws:ec2:{REGION}:{ACCT}:subnet/{subnet}", "attached") in links
    assert (fns["in-vpc"]["arn"], f"arn:aws:ec2:{REGION}:{ACCT}:security-group/{sg}", "uses") in links
    n = nodes(snap)
    assert n["public-url"]["exposure"] == "exposed" and n["in-vpc"]["in_vpc"] is True
