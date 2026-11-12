"""Build the demo from a made-up estate in moto (no real AWS) and made-up integration data.

Writes samples/demo.snapshot.json, samples/integrations/*.json (fake raw files in the real
response shapes) and samples/demo.graph.json (graph v2, built by enrich).

moto cannot set creation times and has no SSM or AWS Backup, so a few values are set on the
snapshot after collect (see phase_b_after_collect): old snapshot and key dates, the root row of
the credential report, a certificate that expires soon, and the SSM-managed instances.

Run from collector/:  uv run python scripts/make_sample.py
"""

from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import date
from pathlib import Path
from urllib.parse import unquote

for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"):
    os.environ.pop(key, None)
os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing",
                  AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
                  MOTO_IAM_LOAD_MANAGED_POLICIES="true")

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from scamallscope import enrich, snapshot  # noqa: E402
from scamallscope.collectors import account  # noqa: E402
from scamallscope.model import Snapshot, make_setting  # noqa: E402

REGIONS = ["eu-west-1", "us-east-1"]
SAMPLES = Path(__file__).resolve().parents[2] / "samples"
OUT = SAMPLES / "demo.graph.json"
RAW = SAMPLES / "integrations"


def tag(kind: str, name: str, **extra: str) -> list[dict]:
    tags = [{"Key": "Name", "Value": name}] + [{"Key": k, "Value": v} for k, v in extra.items()]
    return [{"ResourceType": kind, "Tags": tags}]


def vpc_with_public_and_private(ec2, name: str, cidr: str, env: str) -> dict:
    vpc = ec2.create_vpc(CidrBlock=f"{cidr}.0.0/16", TagSpecifications=tag("vpc", name, env=env))["Vpc"]["VpcId"]
    az = f"{ec2.meta.region_name}a"  # fixed, so the availability rules give the same answer every run
    public = ec2.create_subnet(VpcId=vpc, CidrBlock=f"{cidr}.1.0/24", AvailabilityZone=az,
                               TagSpecifications=tag("subnet", f"{name}-public"))["Subnet"]["SubnetId"]
    private = ec2.create_subnet(VpcId=vpc, CidrBlock=f"{cidr}.2.0/24", AvailabilityZone=az,
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
             profile: str | None = None, **tags: str) -> str:
    extra = {"IamInstanceProfile": {"Name": profile}} if profile else {}
    return ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, InstanceType="t3.micro", **extra,
                             TagSpecifications=tag("instance", name, role=role, **tags),
                             NetworkInterfaces=[{"DeviceIndex": 0, "SubnetId": subnet, "Groups": groups,
                                                 "AssociatePublicIpAddress": public}])["Instances"][0]["InstanceId"]


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
        # Real S3 applies SSE-S3 to every bucket since January 2023 (R39); moto does not, so set it.
        s3.put_bucket_encryption(Bucket=name, ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
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
                        Code={"ZipFile": zipped()}, Tags={"team": "orders", "owner": "orders", "env": "prod"},
                        VpcConfig={"SubnetIds": [subnet], "SecurityGroupIds": [sg]})     # private, in VPC
    lam.create_function(FunctionName="legacy-report", Runtime="python3.9", Role=role, Handler="index.handler",
                        Code={"ZipFile": zipped()}, Tags={"owner": "finance", "env": "prod"})  # deprecated runtime


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
    web_tags = {"owner": "web", "env": "prod", "scamallscope:repo": "example-org/shop-web"}
    instance(ec2, image, prod["public"], [web], "prod-web-1", True, "web", "prod-web-profile", **web_tags)  # exposed
    instance(ec2, image, prod["private"], [app], "prod-app-1", False, "app",
             owner="orders", env="prod", **{"scamallscope:repo": "example-org/orders-api"})   # private
    instance(ec2, image, prod["private"], [db], "prod-db-1", False, "db", owner="data")      # private, no env tag
    old = instance(ec2, image, prod["private"], [app], "prod-batch-old", False, "batch", owner="data", env="prod")
    ec2.stop_instances(InstanceIds=[old])                                                   # stopped
    build_lambda(session, iam_ids["lambda_role"], prod["private"], app)
    build_phase_b(session, ec2, image, prod, web, app)

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
    instance(ec2, image, stg["public"], [stg_web], "staging-web-1", True, "web", owner="web", env="staging",
             **{"scamallscope:repo": "example-org/shop-web", "scamallscope:environment": "staging"})

    # Second region: a public instance whose security group is open only to one office range.
    use1 = session.client("ec2", region_name="us-east-1")
    image1 = use1.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    tools = vpc_with_public_and_private(use1, "tools", "10.30", "shared")
    bastion = sg(use1, tools["vpc"], "tools-bastion", [("tcp", 22, 22, "203.0.113.0/24")])
    instance(use1, image1, tools["public"], [bastion], "tools-bastion-1", True, "bastion", owner="platform", env="shared")


def subnet(ec2, vpc: str, cidr: str, az: str, name: str) -> str:
    return ec2.create_subnet(VpcId=vpc, CidrBlock=cidr, AvailabilityZone=az,
                             TagSpecifications=tag("subnet", name))["Subnet"]["SubnetId"]


def build_phase_b(session: boto3.Session, ec2, image: str, prod: dict, web_sg: str, app_sg: str) -> None:
    """Availability, cost and account-control examples (spec 12): at least one hit per rule."""
    for sid, az in ((prod["public"], "eu-west-1a"), (prod["private"], "eu-west-1a")):
        assert ec2.describe_subnets(SubnetIds=[sid])["Subnets"][0]["AvailabilityZone"] == az
    public_b = subnet(ec2, prod["vpc"], "10.10.3.0/24", "eu-west-1b", "prod-public-b")
    private_b = subnet(ec2, prod["vpc"], "10.10.4.0/24", "eu-west-1b", "prod-private-b")
    public_rt = ec2.describe_route_tables(Filters=[{"Name": "association.subnet-id", "Values": [prod["public"]]}])
    ec2.associate_route_table(RouteTableId=public_rt["RouteTables"][0]["RouteTableId"], SubnetId=public_b)

    # One NAT gateway for private subnets in two AZs, and no S3 gateway endpoint (REL-AZ-004, COST-NAT-001).
    eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat = ec2.create_nat_gateway(SubnetId=prod["public"], AllocationId=eip,
                                 TagSpecifications=tag("natgateway", "prod-nat"))["NatGateway"]["NatGatewayId"]
    rt = ec2.create_route_table(VpcId=prod["vpc"], TagSpecifications=tag("route-table", "prod-private-rt"))
    rt = rt["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat)
    for sid in (prod["private"], private_b):
        ec2.associate_route_table(RouteTableId=rt, SubnetId=sid)
    ec2.allocate_address(Domain="vpc", TagSpecifications=tag("elastic-ip", "old-office-vpn"))  # idle (COST-EIP-001)

    # A second web instance in the same AZ: the "shop-web" app runs in one AZ (REL-AZ-001).
    web2 = instance(ec2, image, prod["public"], [web_sg], "prod-web-2", True, "web", owner="web", env="prod",
                    app="shop-web")
    web1 = ec2.describe_instances(Filters=[{"Name": "tag:Name", "Values": ["prod-web-1"]}])
    web1 = web1["Reservations"][0]["Instances"][0]["InstanceId"]
    ec2.create_tags(Resources=[web1], Tags=[{"Key": "app", "Value": "shop-web"}])

    # Volumes: a data volume on the database host with no backup, and an unattached gp2 volume.
    db_host = ec2.describe_instances(Filters=[{"Name": "tag:Name", "Values": ["prod-db-1"]}])
    db_host = db_host["Reservations"][0]["Instances"][0]["InstanceId"]
    data = ec2.create_volume(AvailabilityZone="eu-west-1a", Size=200, VolumeType="gp2",
                             TagSpecifications=tag("volume", "prod-db-data", owner="data"))["VolumeId"]
    ec2.attach_volume(VolumeId=data, InstanceId=db_host, Device="/dev/sdf")
    loose = ec2.create_volume(AvailabilityZone="eu-west-1a", Size=100, VolumeType="gp2", Encrypted=True,
                              TagSpecifications=tag("volume", "old-export", owner="data", env="prod"))["VolumeId"]
    ec2.create_snapshot(VolumeId=loose, Description="export before migration",
                        TagSpecifications=tag("snapshot", "old-export-2026-03"))
    ec2.create_snapshot(VolumeId=data, Description="before upgrade",   # unencrypted (REL-BAK-003), old
                        TagSpecifications=tag("snapshot", "prod-db-data-2026-03"))

    # Load balancer: plain HTTP listener and an old TLS policy; targets in one AZ, one unhealthy.
    elb = session.client("elbv2", region_name="eu-west-1")
    lb = elb.create_load_balancer(Name="prod-web", Subnets=[prod["public"], public_b], SecurityGroups=[web_sg],
                                  Scheme="internet-facing",
                                  Tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "web"}])["LoadBalancers"][0]
    tg = elb.create_target_group(Name="prod-web", Protocol="HTTP", Port=80, VpcId=prod["vpc"], TargetType="instance",
                                 Tags=[{"Key": "env", "Value": "prod"}])["TargetGroups"][0]
    elb.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": web1}, {"Id": web2}])
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
    acm = session.client("acm", region_name="eu-west-1")
    cert = acm.request_certificate(DomainName="shop.example.com")["CertificateArn"]
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
                        SslPolicy="ELBSecurityPolicy-2016-08", Certificates=[{"CertificateArn": cert}],
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])

    # Workers in an Auto Scaling group in one AZ, with EC2 health checks behind a target group.
    workers_tg = elb.create_target_group(Name="orders-workers", Protocol="HTTP", Port=8080, VpcId=prod["vpc"],
                                         TargetType="instance")["TargetGroups"][0]
    asg = session.client("autoscaling", region_name="eu-west-1")
    asg.create_launch_configuration(LaunchConfigurationName="orders-workers", ImageId=image, InstanceType="t3.small")
    asg.create_auto_scaling_group(AutoScalingGroupName="orders-workers", LaunchConfigurationName="orders-workers",
                                  MinSize=2, MaxSize=4, DesiredCapacity=2, VPCZoneIdentifier=prod["private"],
                                  TargetGroupARNs=[workers_tg["TargetGroupArn"]], HealthCheckType="EC2",
                                  Tags=[{"Key": "env", "Value": "prod", "PropagateAtLaunch": True},
                                        {"Key": "owner", "Value": "orders", "PropagateAtLaunch": True},
                                        {"Key": "Name", "Value": "orders-worker", "PropagateAtLaunch": True}])

    # Database: single AZ, not encrypted, no automated backups.
    rds = session.client("rds", region_name="eu-west-1")
    rds.create_db_subnet_group(DBSubnetGroupName="prod-db", DBSubnetGroupDescription="prod",
                               SubnetIds=[prod["private"], private_b])
    rds.create_db_instance(DBInstanceIdentifier="orders-db", Engine="postgres", DBInstanceClass="db.t3.medium",
                           MasterUsername="orders", MasterUserPassword="made-up-not-real",  # pragma: allowlist secret
                           AllocatedStorage=50, DBSubnetGroupName="prod-db", VpcSecurityGroupIds=[app_sg],
                           MultiAZ=False, StorageEncrypted=False, PubliclyAccessible=False, BackupRetentionPeriod=0,
                           Tags=[{"Key": "env", "Value": "prod"}, {"Key": "owner", "Value": "orders"}])

    # A reporting copy in the public subnets, publicly accessible (SEC-RDS-002 critical).
    rds.create_db_subnet_group(DBSubnetGroupName="reporting", DBSubnetGroupDescription="reporting",
                               SubnetIds=[prod["public"], public_b])
    rds.create_db_instance(DBInstanceIdentifier="reporting-db", Engine="mysql", DBInstanceClass="db.t3.small",
                           MasterUsername="report", MasterUserPassword="made-up-not-real",  # pragma: allowlist secret
                           AllocatedStorage=20, DBSubnetGroupName="reporting", VpcSecurityGroupIds=[web_sg],
                           MultiAZ=False, StorageEncrypted=True, PubliclyAccessible=True, BackupRetentionPeriod=7,
                           Tags=[{"Key": "env", "Value": "staging"}, {"Key": "owner", "Value": "finance"}])

    # Account controls: a trail in one Region only, GuardDuty only in eu-west-1, a console user without MFA.
    s3 = session.client("s3", region_name="eu-west-1")
    s3.create_bucket(Bucket="demo-cloudtrail", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
    ct = session.client("cloudtrail", region_name="eu-west-1")
    ct.create_trail(Name="main", S3BucketName="demo-cloudtrail", IsMultiRegionTrail=False)  # SEC-LOG-001
    ct.start_logging(Name="main")
    session.client("guardduty", region_name="eu-west-1").create_detector(Enable=True)
    iam = session.client("iam")
    iam.create_login_profile(UserName="alex.admin", Password="made-up-not-real-1!")  # pragma: allowlist secret
    iam.create_access_key(UserName="ci-deployer")


def no_ssm_or_backup_in_moto() -> None:
    """moto 5.2.5 has neither ssm:DescribeInstanceInformation nor backup:ListProtectedResources."""
    def empty(service, setting_id, key):
        return lambda client, ctx: ([make_setting(ctx["partition"], service, ctx["region"], ctx["account_id"],
                                                  setting_id, {key: []})], [])
    fake = {"backup": empty("backup", "backup-protected", "Resources"), "ssm": empty("ssm", "ssm-managed", "Instances")}
    account.REGIONAL = [(s, t, c, fake.get(s, fn)) for s, t, c, fn in account.REGIONAL]
    account.REPORT_WAIT_S = 0


def phase_b_after_collect(snap: Snapshot) -> None:
    """Values moto cannot produce (see the module docstring). All made up."""
    by_name = {r["name"]: r for r in snap["resources"]}
    ids = {r["name"]: r["id"] for r in snap["resources"] if r["type"] == "instance"}
    for r in snap["resources"]:
        if r["type"] == "snapshot":
            r["config"]["StartTime"] = "2026-03-02T09:00:00+00:00"   # 247 days before the demo date
        if r["type"] == "certificate":
            r["config"]["NotAfter"] = "2026-11-24T00:00:00+00:00"    # 20 days after the demo date
        if r["type"] == "setting" and r["id"] == "ssm-managed" and r["region"] == "eu-west-1":
            r["config"]["Instances"] = [{"InstanceId": ids[n], "PingStatus": "Online"} for n in ("prod-app-1", "prod-web-2")]
        if r["type"] == "credential-report":
            rows = r["config"]["Rows"]
            for row in rows:
                if row["user"] == "ci-deployer":
                    row["access_key_1_last_rotated"] = "2026-01-15T10:00:00+00:00"
                    row["access_key_1_last_used_date"] = "2026-11-03T22:00:00+00:00"
            rows.insert(0, {"user": "<root_account>", "arn": f"arn:aws:iam::{snap['account_id']}:root",
                            "password_enabled": "not_supported", "mfa_active": "false",
                            "access_key_1_active": "false", "access_key_1_last_rotated": "N/A",
                            "access_key_1_last_used_date": "N/A", "access_key_2_active": "false",
                            "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A"})
        if r["type"] == "target-group" and r["name"] == "prod-web":
            for t in r["config"]["TargetHealth"]:
                if t["Id"] == ids["prod-web-2"]:
                    t.update(State="unhealthy", Reason="Target.FailedHealthChecks")  # REL-HEAL-003
    # The instance that runs alone has automatic recovery turned off (REL-HEAL-001).
    by_name["prod-db-1"]["config"].setdefault("MaintenanceOptions", {})["AutoRecovery"] = "disabled"


def fake_integrations(snap: Snapshot) -> dict[str, object]:
    """Made-up raw files, in the shapes of the real responses (see docs/specs), for this estate."""
    ids = {r["tags"].get("Name"): r["id"] for r in snap["resources"] if r["type"] == "instance"}
    acct = snap["account_id"]
    web, app, db, stg, bastion = (ids[n] for n in ("prod-web-1", "prod-app-1", "prod-db-1", "staging-web-1", "tools-bastion-1"))
    at = "2026-11-04T06:00:00+00:00"

    def ocsf(status, sev, check, title, arn, region, bps, pillar="Security", detail="", fix=""):
        return {"status_code": status, "severity": sev, "status_detail": detail,
                "metadata": {"event_code": check}, "remediation": {"desc": fix},
                "finding_info": {"uid": f"prowler-aws-{check}-{acct}-{region}-{arn.split(':')[-1]}", "title": title},
                "resources": [{"uid": arn, "name": arn.split(":")[-1].split("/")[-1], "region": region}],
                "cloud": {"provider": "aws", "account": {"uid": acct}},
                "unmapped": {"compliance": {f"AWS-Well-Architected-Framework-{pillar}-Pillar": bps}}}

    i_arn = lambda iid, r="eu-west-1": f"arn:aws:ec2:{r}:{acct}:instance/{iid}"  # noqa: E731
    # Check IDs and best-practice IDs as in Prowler's own Well-Architected mapping (references R12, R13).
    prowler = [
        ocsf("FAIL", "Critical", "iam_root_mfa_enabled", "Ensure MFA is enabled for the root account",
             f"arn:aws:iam::{acct}:root", "us-east-1", ["SEC01-BP02"], detail="MFA is not enabled for root account.",
             fix="Enable a hardware or virtual MFA device for the root user."),
        ocsf("PASS", "High", "iam_no_root_access_key", "Ensure no root account access key exists",
             f"arn:aws:iam::{acct}:root", "us-east-1", ["SEC01-BP02"]),
        ocsf("FAIL", "High", "ec2_instance_imdsv2_enabled", "Ensure EC2 instances use IMDSv2", i_arn(web), "eu-west-1",
             ["SEC03-BP01", "SEC06-BP01"], detail="IMDSv2 is not required.", fix="Set HttpTokens to required."),
        ocsf("FAIL", "High", "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
             "Ensure no security groups allow ingress from 0.0.0.0/0 to SSH port 22",
             i_arn(web), "eu-west-1", ["SEC05-BP03"], detail="Security group prod-web allows SSH from the internet.",
             fix="Remove the rule; use Session Manager instead of SSH."),
        ocsf("FAIL", "Medium", "ec2_instance_managed_by_ssm", "Check if EC2 instances are managed by Systems Manager",
             i_arn(db), "eu-west-1", ["SEC01-BP06", "SEC06-BP04", "SEC06-BP05"], detail="Instance is not managed by SSM."),
        ocsf("FAIL", "Medium", "cloudtrail_multi_region_enabled", "Ensure CloudTrail is enabled in all regions",
             f"arn:aws:cloudtrail:eu-west-1:{acct}:trail/main", "eu-west-1", ["SEC04-BP02", "SEC04-BP03"],
             detail="Trail main logs eu-west-1 only."),
        ocsf("FAIL", "Medium", "guardduty_is_enabled", "Check if GuardDuty is enabled",
             f"arn:aws:guardduty:us-east-1:{acct}:detector/unknown", "us-east-1", ["SEC04-BP04", "SEC05-BP04"],
             detail="GuardDuty is not enabled in us-east-1."),
        ocsf("PASS", "Medium", "ec2_ebs_volume_encryption", "Ensure there are no EBS volumes unencrypted",
             f"arn:aws:ec2:eu-west-1:{acct}:volume/vol-made-up", "eu-west-1", ["SEC08-BP02"]),
        ocsf("FAIL", "Medium", "s3_bucket_object_versioning", "Check if S3 buckets have object versioning enabled",
             "arn:aws:s3:::demo-site-public", "eu-west-1", ["SEC08-BP04"], detail="Versioning is not enabled."),
        ocsf("FAIL", "Medium", "rds_instance_backup_enabled", "Check if RDS instances have backups enabled",
             f"arn:aws:rds:eu-west-1:{acct}:db:orders-db", "eu-west-1", ["REL09-BP03"], "Reliability",
             detail="RDS instance orders-db has a backup retention period of 0."),
    ]

    def agent(n, name, status, os_name, ver, platform):
        return {"id": f"{n:03d}", "name": name, "status": status, "lastKeepAlive": at if status == "active" else "2026-10-29T08:00:00+00:00",
                "os": {"name": os_name, "version": ver, "platform": platform}}

    def vuln_aggregation(rows):
        """The indexer's answer to wazuh.vulnerability_query for these made-up rows (spec 03)."""
        by_agent: dict[str, list] = {}
        for r in rows:
            by_agent.setdefault(r["_source"]["agent"]["id"], []).append(r["_source"])
        buckets = []
        for aid, docs in sorted(by_agent.items()):
            sev: dict[str, int] = {}
            pkg: dict[tuple[str, str], int] = {}
            for d in docs:
                sev[d["vulnerability"]["severity"]] = sev.get(d["vulnerability"]["severity"], 0) + 1
                k = (d["package"]["name"], d["package"]["version"])
                pkg[k] = pkg.get(k, 0) + 1
            buckets.append({"key": aid, "doc_count": len(docs),
                            "severity": {"buckets": [{"key": k, "doc_count": v} for k, v in sorted(sev.items())]},
                            "packages": {"buckets": [{"key": [n, v], "doc_count": c}
                                                     for (n, v), c in sorted(pkg.items(), key=lambda kv: (-kv[1], kv[0]))[:5]]}})
        return {"hits": {"total": {"value": len(rows), "relation": "eq"}, "hits": []},
                "aggregations": {"by_agent.id": {"sum_other_doc_count": 0, "buckets": buckets},
                                 "by_wazuh.agent.id": {"sum_other_doc_count": 0, "buckets": []}}}

    def vuln(agent_id, name, pkg, ver, cve, sev):
        return {"_source": {"agent": {"id": agent_id, "name": name}, "package": {"name": pkg, "version": ver},
                            "vulnerability": {"id": cve, "severity": sev}}}

    # CVE ids are made up (CVE-2099-...), so nobody mistakes the sample for a real scan.
    vulns = [vuln("001", "prod-web-1", "openssl", "3.0.2-0ubuntu1.15", "CVE-2099-1001", "Critical"),
             vuln("001", "prod-web-1", "openssl", "3.0.2-0ubuntu1.15", "CVE-2099-1002", "High"),
             vuln("001", "prod-web-1", "nginx", "1.18.0-6ubuntu14.4", "CVE-2099-1003", "High"),
             vuln("001", "prod-web-1", "curl", "7.81.0-1ubuntu1.16", "CVE-2099-1004", "Medium"),
             vuln("002", "prod-app-1", "glibc", "2.34-100.amzn2023", "CVE-2099-1005", "Medium"),
             vuln("004", "staging-web-1", "openssh-server", "1:8.2p1-4ubuntu0.11", "CVE-2099-1006", "High"),
             vuln("004", "staging-web-1", "sudo", "1.8.31-1ubuntu1.5", "CVE-2099-1007", "Low")]
    wazuh = {"fetched_at": at,
             "agents": {"data": {"total_affected_items": 6, "affected_items": [
                 agent(0, "wazuh-manager", "active", "Amazon Linux", "2023", "amzn"),
                 agent(1, "prod-web-1", "active", "Ubuntu", "22.04.4 LTS", "ubuntu"),
                 agent(2, app, "active", "Amazon Linux", "2023", "amzn"),
                 agent(4, "staging-web-1", "disconnected", "Ubuntu", "20.04.6 LTS", "ubuntu"),
                 agent(5, bastion, "active", "Amazon Linux", "2023", "amzn"),
                 agent(6, "old-laptop", "never_connected", "", "", "")]}},
             "vulnerabilities": vuln_aggregation(vulns)}

    def dep(n, sha, env, when):
        return {"id": n, "sha": sha * 5, "ref": "main", "environment": env, "created_at": when}
    github = {"fetched_at": at, "repos": {
        "example-org/shop-web": {
            "deployments": [dep(31, "c0ffee12", "production", "2026-11-03T16:20:00Z"),
                            dep(30, "b4dc0de1", "production", "2026-10-28T10:00:00Z"),
                            dep(29, "5ca1ab1e", "staging", "2026-11-03T15:00:00Z")],
            "statuses": {"31": [{"state": "success"}], "29": [{"state": "success"}]}},
        "example-org/orders-api": {
            "deployments": [dep(12, "f00dfeed", "production", "2026-11-02T11:00:00Z")],
            "statuses": {"12": [{"state": "failure"}]}}}}

    def stats(ok, changed=0, failures=0, unreachable=0):
        return {"ok": ok, "changed": changed, "failures": failures, "unreachable": unreachable,
                "skipped": 1, "rescued": 0, "ignored": 0}
    ansible = {"custom_stats": {}, "global_custom_stats": {},
               "plays": [{"play": {"name": "base", "id": "made-up", "duration": {"start": "2026-11-04T05:30:00Z"}}, "tasks": []}],
               "stats": {"prod-web-1": stats(18), "prod-app-1": stats(15, changed=2), "prod-db-1": stats(4, unreachable=1),
                         "staging-web-1": stats(18)}}

    def series(qid, values):
        return {"Id": qid, "Label": "CPUUtilization", "StatusCode": "Complete", "Timestamps": [], "Values": values}
    eu = sorted([web, app, db, stg])
    queries = {}
    results = []
    cpu = {web: ([31.0, 42.5, 38.0], [92.0, 77.0]), app: ([2.1, 1.4, 2.6], [8.0, 11.5]),
           db: ([12.0, 15.5], [40.0, 55.0]), stg: ([0.9, 1.1], [3.0, 4.2]), bastion: ([0.4, 0.3], [2.0, 1.0])}
    for n, iid in enumerate(eu):
        queries[f"q{n}_avg"], queries[f"q{n}_max"] = f"{iid}|avg", f"{iid}|max"
        results += [series(f"q{n}_avg", cpu[iid][0]), series(f"q{n}_max", cpu[iid][1])]
    cloudwatch = {"fetched_at": at, "days": 14, "regions": {
        "eu-west-1": {"queries": queries, "results": results,
                      "alarms": [{"AlarmName": "prod-web-1-cpu", "Dimensions": [{"Name": "InstanceId", "Value": web}]},
                                 {"AlarmName": "prod-db-1-status", "Dimensions": [{"Name": "InstanceId", "Value": db}]}]},
        "us-east-1": {"queries": {"q0_avg": f"{bastion}|avg", "q0_max": f"{bastion}|max"},
                      "results": [series("q0_avg", cpu[bastion][0]), series("q0_max", cpu[bastion][1])], "alarms": []}}}

    def up(labels, value):
        return {"metric": {"__name__": "up", **labels}, "value": [1793772000, value]}
    prometheus = {"fetched_at": at, "query": "up", "response": {"status": "success", "data": {"resultType": "vector", "result": [
        up({"job": "node", "instance_id": web, "instance": "prod-web-1:9100"}, "1"),
        up({"job": "node", "instance_id": app, "instance": "prod-app-1:9100"}, "1"),
        up({"job": "orders", "instance": "prod-app-1:8080"}, "0"),
        up({"job": "node", "instance_id": db, "instance": "prod-db-1:9100"}, "1")]}}}

    def month(start, end, groups, est=False):
        return {"TimePeriod": {"Start": start, "End": end}, "Estimated": est, "Total": {},
                "Groups": [{"Keys": [k], "Metrics": {"UnblendedCost": {"Amount": f"{v:.4f}", "Unit": "USD"}}} for k, v in groups.items()]}
    svc = lambda ec2, s3, lam, cw, nat: {"Amazon Elastic Compute Cloud - Compute": ec2, "Amazon Simple Storage Service": s3,  # noqa: E731
                                         "AWS Lambda": lam, "AmazonCloudWatch": cw, "EC2 - Other": nat}
    by_service = [month("2026-08-01", "2026-09-01", svc(58.4, 3.9, 0.6, 2.1, 33.0)),
                  month("2026-09-01", "2026-10-01", svc(61.5, 4.2, 0.8, 2.2, 33.4)),
                  month("2026-10-01", "2026-11-01", svc(64.0, 4.5, 1.1, 2.4, 34.1)),
                  month("2026-11-01", "2026-11-04", svc(6.3, 0.5, 0.1, 0.2, 3.3), True)]
    by_tag = [month("2026-08-01", "2026-09-01", {"env$prod": 70.0, "env$staging": 9.0, "env$shared": 6.0, "env$": 13.0}),
              month("2026-09-01", "2026-10-01", {"env$prod": 72.0, "env$staging": 9.1, "env$shared": 6.0, "env$": 15.0}),
              month("2026-10-01", "2026-11-01", {"env$prod": 74.5, "env$staging": 9.4, "env$shared": 6.2, "env$": 16.0}),
              month("2026-11-01", "2026-11-04", {"env$prod": 7.6, "env$staging": 0.9, "env$shared": 0.6, "env$": 1.3}, True)]
    daily = {web: 0.75, app: 0.55, db: 0.62, stg: 0.25, bastion: 0.18}
    by_resource = []
    for d in range(14):
        start = f"2026-10-{21 + d:02d}" if 21 + d <= 31 else f"2026-11-{d - 10:02d}"
        end = f"2026-10-{22 + d:02d}" if 22 + d <= 31 else f"2026-11-{d - 9:02d}"
        by_resource.append(month(start, end, daily, True))
    window = {"Start": "2026-10-05", "End": "2026-11-04"}
    sp_coverage = [{"TimePeriod": window, "Coverage": {"SpendCoveredBySavingsPlans": "0", "OnDemandCost": "68.40",
                                                       "TotalCost": "68.40", "CoveragePercentage": "0"}}]
    ri_coverage = [{"TimePeriod": window, "Total": {"CoverageHours": {"OnDemandHours": "3600", "ReservedHours": "0",
                                                                      "TotalRunningHours": "3600"}}}]
    cost = {"fetched_at": "2026-11-04", "tag_key": "env", "by_service": by_service, "by_tag": by_tag,
            "by_resource": by_resource, "coverage_window": window, "sp_coverage": sp_coverage, "ri_coverage": ri_coverage}
    # Inflate on-demand so the coverage rule's 100 USD floor is passed in the demo.
    sp_coverage[0]["Coverage"].update(OnDemandCost="168.40", TotalCost="168.40")

    vol = {r["name"]: r["arn"] for r in snap["resources"] if r["type"] == "volume"}

    def hub(rid, arn, action, saving, rtype, **extra):
        return {"recommendationId": f"made-up-{rid}", "accountId": acct, "region": "eu-west-1", "resourceId": rid,
                "resourceArn": arn, "currentResourceType": rtype, "actionType": action,
                "estimatedMonthlySavings": saving, "estimatedMonthlyCost": round(saving * 1.6, 2), "currencyCode": "USD",
                "implementationEffort": "Low", "restartNeeded": action in ("Rightsize", "Stop"),
                "rollbackPossible": action != "Delete", "recommendationLookbackPeriodInDays": 14, **extra}
    costhub = {"fetched_at": at, "enabled": True, "reason": None, "compute_optimizer": "Active", "recommendations": [
        hub(web, i_arn(web), "Rightsize", 14.6, "Ec2Instance", currentResourceSummary="t3.large",
            recommendedResourceSummary="t3.medium"),
        hub(stg, i_arn(stg), "Stop", 7.3, "Ec2Instance"),
        hub(vol["old-export"].split("/")[-1], vol["old-export"], "Delete", 10.0, "EbsVolume"),
        hub("compute-sp", None, "PurchaseSavingsPlans", 22.8, "ComputeSavingsPlans",
            recommendedResourceType="ComputeSavingsPlans", recommendedResourceSummary="$0.08/hour, 1 year, no upfront",
            recommendationLookbackPeriodInDays=30)]}
    return {"prowler.ocsf.json": prowler, "wazuh.json": wazuh, "github.json": github, "ansible.json": ansible,
            "cloudwatch.json": cloudwatch, "prometheus.json": prometheus, "cost.json": cost, "costhub.json": costhub}


def write(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    no_ssm_or_backup_in_moto()
    with mock_aws():
        session = boto3.Session(region_name="eu-west-1")
        build(session)
        stand_in_for_list_function_url_configs(session)
        snap = snapshot.collect(session, REGIONS)
    snap["collected_at"] = "2026-11-04T06:00:00+00:00"
    phase_b_after_collect(snap)
    write(SAMPLES / "demo.snapshot.json", snap)
    for name, data in fake_integrations(snap).items():
        write(RAW / name, data)
    result = enrich.build(snap, enrich.load_raw(RAW), today=date(2026, 11, 4))
    write(OUT, result)

    for source, m in result["meta"]["integrations"].items():
        print(f"{source:<11} loaded={m['loaded']} findings={m.get('findings')} unmatched={m.get('unmatched')} {m.get('error', '')}")
    sev: dict[str, int] = {}
    for f in result["findings"]:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    print(f"{len(result['findings'])} findings {sev}")
    print(f"summary {result['summary']}")
    from scamallscope import hygiene
    rule_ids = {r.id for r in hygiene.rules(hygiene.DEFAULT_REQUIRED_TAGS)}
    missing = sorted(rule_ids - {f["check_id"] for f in result["findings"]} - {"HYG-EC2-002"})
    print(f"rules with no example in the demo: {missing or 'none'} (HYG-EC2-002 is off: the hub is loaded)")
    for pillar, p in result["posture"].items():
        print(f"  {pillar:<12} {p['summary']}")
    nodes = [e for e in result["elements"] if e["group"] == "nodes"]
    print(f"{len(nodes)} nodes, {len(result['elements']) - len(nodes)} edges -> {OUT}")


if __name__ == "__main__":
    main()
