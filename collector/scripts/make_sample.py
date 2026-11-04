"""Build samples/demo.graph.json from a made-up estate in moto (no real AWS).

Run from collector/:  uv run python scripts/make_sample.py
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path
from urllib.parse import unquote

for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"):
    os.environ.pop(key, None)
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
                  AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
                  MOTO_IAM_LOAD_MANAGED_POLICIES="true")

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from scamallscope import graph, snapshot  # noqa: E402

REGIONS = ["eu-west-1", "us-east-1"]
OUT = Path(__file__).resolve().parents[2] / "samples" / "demo.graph.json"


def tag(kind: str, name: str, **extra: str) -> list[dict]:
    tags = [{"Key": "Name", "Value": name}] + [{"Key": k, "Value": v} for k, v in extra.items()]
    return [{"ResourceType": kind, "Tags": tags}]


def vpc_with_public_and_private(ec2, name: str, cidr: str, env: str) -> dict:
    vpc = ec2.create_vpc(CidrBlock=f"{cidr}.0.0/16", TagSpecifications=tag("vpc", name, env=env))["Vpc"]["VpcId"]
    public = ec2.create_subnet(VpcId=vpc, CidrBlock=f"{cidr}.1.0/24",
                               TagSpecifications=tag("subnet", f"{name}-public"))["Subnet"]["SubnetId"]
    private = ec2.create_subnet(VpcId=vpc, CidrBlock=f"{cidr}.2.0/24",
                                TagSpecifications=tag("subnet", f"{name}-private"))["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway(TagSpecifications=tag("internet-gateway", f"{name}-igw"))
    igw = igw["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)
    rt = ec2.create_route_table(VpcId=vpc, TagSpecifications=tag("route-table", f"{name}-public-rt"))
    rt = rt["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)
    ec2.associate_route_table(RouteTableId=rt, SubnetId=public)
    return {"vpc": vpc, "public": public, "private": private}


def sg(ec2, vpc: str, name: str, rules: list[tuple[str, int, int, str]]) -> str:
    group = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc,
                                      TagSpecifications=tag("security-group", name))["GroupId"]
    if rules:
        ec2.authorize_security_group_ingress(GroupId=group, IpPermissions=[
            {"IpProtocol": p, "FromPort": f, "ToPort": t, "IpRanges": [{"CidrIp": c}]} for p, f, t, c in rules])
    return group


def instance(ec2, image: str, subnet: str, groups: list[str], name: str, public: bool, role: str,
             profile: str | None = None) -> None:
    extra = {"IamInstanceProfile": {"Name": profile}} if profile else {}
    ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, InstanceType="t3.micro", **extra,
                      TagSpecifications=tag("instance", name, role=role),
                      NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": groups,
                                          "AssociatePublicIpAddress": public}])


def trust(service: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]})


def build_iam(session: boto3.Session) -> dict[str, str]:
    iam = session.client("iam")
    iam.create_role(RoleName="prod-web-role", AssumeRolePolicyDocument=trust("ec2.amazonaws.com"))
    iam.attach_role_policy(RoleName="prod-web-role", PolicyArn="arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
    iam.create_instance_profile(InstanceProfileName="prod-web-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="prod-web-profile", RoleName="prod-web-role")
    fn_role = iam.create_role(RoleName="orders-api-role", AssumeRolePolicyDocument=trust("lambda.amazonaws.com"))
    iam.create_group(GroupName="platform-admins")
    iam.attach_group_policy(GroupName="platform-admins", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_user(UserName="alex.admin")
    iam.add_user_to_group(GroupName="platform-admins", UserName="alex.admin")
    deploy = iam.create_policy(PolicyName="deploy-site", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:DeleteObject"], "Resource": "arn:aws:s3:::demo-site-public/*"}]}))
    iam.create_user(UserName="ci-deployer")
    iam.attach_user_policy(UserName="ci-deployer", PolicyArn=deploy["Policy"]["Arn"])
    return {"lambda_role": fn_role["Role"]["Arn"]}


def build_s3(session: boto3.Session) -> None:
    s3 = session.client("s3", region_name="eu-west-1")
    off = {"BlockPublicAcls": False, "IgnorePublicAcls": False, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
    public_read = lambda b: json.dumps({"Version": "2012-10-17", "Statement": [  # noqa: E731
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{b}/*"}]})
    for name, policy, block in [("demo-site-public", True, off),                       # exposed
                                ("demo-reports", True, {**off, "RestrictPublicBuckets": True}),  # blocked
                                ("demo-backups", False, None)]:                         # private
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "env", "Value": "prod"}]})
        if block:
            s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=block)
        if policy:
            s3.put_bucket_policy(Bucket=name, Policy=public_read(name))
    s3.put_bucket_versioning(Bucket="demo-backups", VersioningConfiguration={"Status": "Enabled"})


def zipped() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("index.py", "def handler(event, context):\n    return 'ok'\n")
    return buf.getvalue()


def build_lambda(session: boto3.Session, role: str, subnet: str, sg: str) -> None:
    lam = session.client("lambda", region_name="eu-west-1")
    lam.create_function(FunctionName="orders-webhook", Runtime="python3.12", Role=role, Handler="index.handler",
                        Code={"ZipFile": zipped()}, Tags={"team": "orders"},
                        Environment={"Variables": {"STAGE": "prod", "WEBHOOK_SECRET": "made-up-not-stored"}})
    lam.create_function_url_config(FunctionName="orders-webhook", AuthType="NONE")      # exposed
    lam.create_function(FunctionName="orders-worker", Runtime="python3.12", Role=role, Handler="index.handler",
                        Code={"ZipFile": zipped()}, Tags={"team": "orders"},
                        VpcConfig={"SubnetIds": [subnet], "SecurityGroupIds": [sg]})     # private, in VPC


def stand_in_for_list_function_url_configs(session: boto3.Session) -> None:
    """moto does not implement ListFunctionUrlConfigs; answer it from GetFunctionUrlConfig."""
    lam = session.client("lambda", region_name="eu-west-1")

    class Ok:
        status_code = 200

    def handler(params, **kwargs):
        name = unquote(params["url_path"].split("/functions/", 1)[1].split("/", 1)[0])
        try:
            url = lam.get_function_url_config(FunctionName=name)
            return Ok(), {"FunctionUrlConfigs": [{k: url[k] for k in ("FunctionUrl", "FunctionArn", "AuthType")}]}
        except lam.exceptions.ResourceNotFoundException:
            return Ok(), {"FunctionUrlConfigs": []}

    session.events.register("before-call.lambda.ListFunctionUrlConfigs", handler)


def build(session: boto3.Session) -> None:
    ec2 = session.client("ec2", region_name="eu-west-1")
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    iam_ids = build_iam(session)
    build_s3(session)

    prod = vpc_with_public_and_private(ec2, "prod", "10.10", "prod")
    web = sg(ec2, prod["vpc"], "prod-web", [("tcp", 443, 443, "0.0.0.0/0"), ("tcp", 22, 22, "0.0.0.0/0")])
    app = sg(ec2, prod["vpc"], "prod-app", [("tcp", 8080, 8080, "10.10.0.0/16")])
    db = sg(ec2, prod["vpc"], "prod-db", [("tcp", 5432, 5432, "10.10.2.0/24")])
    instance(ec2, image, prod["public"], [web], "prod-web-1", True, "web", "prod-web-profile")  # exposed: 443, 22
    instance(ec2, image, prod["private"], [app], "prod-app-1", False, "app")   # private
    instance(ec2, image, prod["private"], [db], "prod-db-1", False, "db")      # private
    build_lambda(session, iam_ids["lambda_role"], prod["private"], app)

    stg = vpc_with_public_and_private(ec2, "staging", "10.20", "staging")
    stg_web = sg(ec2, stg["vpc"], "staging-web", [("tcp", 22, 22, "0.0.0.0/0"), ("tcp", 80, 80, "0.0.0.0/0")])
    # The staging public subnet's network ACL denies SSH from the internet: only port 80 is exposed.
    acl = ec2.create_network_acl(VpcId=stg["vpc"], TagSpecifications=tag("network-acl", "staging-public-acl"))
    acl = acl["NetworkAcl"]["NetworkAclId"]
    ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=90, Protocol="6", RuleAction="deny", Egress=False,
                                 CidrBlock="0.0.0.0/0", PortRange={"From": 22, "To": 22})
    ec2.create_network_acl_entry(NetworkAclId=acl, RuleNumber=100, Protocol="-1", RuleAction="allow",
                                 Egress=False, CidrBlock="0.0.0.0/0")
    current = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [stg["public"]]}])["NetworkAcls"][0]
    assoc = next(a["NetworkAclAssociationId"] for a in current["Associations"] if a["SubnetId"] == stg["public"])
    ec2.replace_network_acl_association(AssociationId=assoc, NetworkAclId=acl)
    instance(ec2, image, stg["public"], [stg_web], "staging-web-1", True, "web")

    # Second region: a public instance whose security group is open only to one office range.
    use1 = session.client("ec2", region_name="us-east-1")
    image1 = use1.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    tools = vpc_with_public_and_private(use1, "tools", "10.30", "shared")
    bastion = sg(use1, tools["vpc"], "tools-bastion", [("tcp", 22, 22, "203.0.113.0/24")])
    instance(use1, image1, tools["public"], [bastion], "tools-bastion-1", True, "bastion")


def main() -> None:
    with mock_aws():
        session = boto3.Session(region_name="eu-west-1")
        build(session)
        stand_in_for_list_function_url_configs(session)
        snap = snapshot.collect(session, REGIONS)
    result = graph.to_graph(snap)
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    nodes = [e["data"] for e in result["elements"] if e["group"] == "nodes"]
    for n in nodes:
        if "exposure" in n:
            ports = [f"{p['protocol']}/{p['from_port']}" for p in n["exposed_ports"]]
            print(f"{n['region']:<10} {n['label']:<16} {n['exposure']:<12} {n['exposure_reason']} {ports}")
    for n in nodes:
        if n.get("admin"):
            print(f"admin: {n['type']} {n['label']} ({n.get('admin_reason') or 'policy'})")
    print(f"{len(nodes)} nodes, {len(result['elements']) - len(nodes)} edges -> {OUT}")


if __name__ == "__main__":
    main()
