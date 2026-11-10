"""A made-up estate, built by hand, with at least one hit and one clean example for each spec 12 rule.

Account 123456789012 and every name here are made up.
"""

from __future__ import annotations

from datetime import date, timedelta

from scamallscope.model import GLOBAL, Snapshot, link, make_resource, make_setting, new_snapshot, ok_unit

A, R = "123456789012", "eu-west-1"
TODAY = date(2026, 11, 10)


def ago(days: int) -> str:
    return f"{(TODAY - timedelta(days=days)).isoformat()}T00:00:00+00:00"


def ec2arn(kind: str, rid: str) -> str:
    return f"arn:aws:ec2:{R}:{A}:{kind}/{rid}"


def ec2(kind: str, rid: str, config: dict, tags: dict | None = None):
    return make_resource(ec2arn(kind, rid), A, R, "ec2", kind, rid, tags or {}, config)


def instance(iid: str, subnet_az: str, tags: dict, tokens: str = "required", recovery: str = "default"):
    return ec2("instance", iid, {"InstanceId": iid, "State": {"Name": "running"},
                                 "Placement": {"AvailabilityZone": subnet_az},
                                 "MetadataOptions": {"HttpTokens": tokens},
                                 "MaintenanceOptions": {"AutoRecovery": recovery}}, {"Name": iid, **tags})


LB = f"arn:aws:elasticloadbalancing:{R}:{A}:loadbalancer/app/web/1"
TG = f"arn:aws:elasticloadbalancing:{R}:{A}:targetgroup/web/1"
ASG = f"arn:aws:autoscaling:{R}:{A}:autoScalingGroup:1:autoScalingGroupName/web"
DB = f"arn:aws:rds:{R}:{A}:db:orders"
AURORA = f"arn:aws:rds:{R}:{A}:db:aurora-1"
CERT = f"arn:aws:acm:{R}:{A}:certificate/abc"
ALICE = f"arn:aws:iam::{A}:user/alice"


def snapshot() -> Snapshot:
    s = new_snapshot(A, "aws", "2026-11-10T06:00:00+00:00", [R, GLOBAL])
    res = s["resources"]
    res += [
        ec2("vpc", "vpc-1", {"VpcId": "vpc-1"}, {"Name": "main"}),
        ec2("subnet", "s-a", {"AvailabilityZone": "eu-west-1a"}),
        ec2("subnet", "s-b", {"AvailabilityZone": "eu-west-1b"}),
        ec2("subnet", "s-pa", {"AvailabilityZone": "eu-west-1a"}),
        ec2("subnet", "s-pb", {"AvailabilityZone": "eu-west-1b"}),
        ec2("security-group", "sg-open", {"IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}),
        ec2("security-group", "sg-web", {"IpPermissions": [
            {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}),
        instance("i-bastion", "eu-west-1a", {"env": "prod"}, tokens="optional", recovery="disabled"),
        instance("i-web1", "eu-west-1a", {"app": "web", "env": "prod"}),
        instance("i-web2", "eu-west-1a", {"app": "web", "env": "prod"}),
        instance("i-api1", "eu-west-1a", {"app": "api", "env": "dev"}),
        instance("i-api2", "eu-west-1b", {"app": "api", "env": "dev"}),
        ec2("volume", "vol-bastion", {"State": "in-use", "VolumeType": "gp2", "Size": 20, "Encrypted": False,
                                      "AvailabilityZone": "eu-west-1a"}, {"env": "prod"}),
        ec2("volume", "vol-web1", {"State": "in-use", "VolumeType": "gp3", "Size": 8, "Encrypted": True}),
        ec2("volume", "vol-api1", {"State": "in-use", "VolumeType": "gp3", "Size": 8, "Encrypted": True}, {"env": "dev"}),
        ec2("volume", "vol-loose", {"State": "available", "VolumeType": "gp3", "Size": 100, "Encrypted": True}),
        ec2("snapshot", "snap-old", {"StartTime": ago(400), "VolumeSize": 50, "Encrypted": False, "VolumeId": "vol-gone"}),
        ec2("snapshot", "snap-backup", {"StartTime": ago(400), "VolumeSize": 50, "Encrypted": True, "VolumeId": "vol-gone",
                                        "Description": "This snapshot is created by the AWS Backup service"}),
        ec2("snapshot", "snap-api1", {"StartTime": ago(1), "VolumeSize": 8, "Encrypted": True, "VolumeId": "vol-api1"}),
        ec2("elastic-ip", "eipalloc-idle", {"AllocationId": "eipalloc-idle"}),
        ec2("elastic-ip", "eipalloc-used", {"AllocationId": "eipalloc-used", "AssociationId": "eipassoc-1"}),
        ec2("nat-gateway", "nat-1", {"NatGatewayId": "nat-1", "State": "available"}),
        ec2("route-table", "rt-private", {"Associations": [{"SubnetId": "s-pa"}, {"SubnetId": "s-pb"}],
                                          "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}]}),
        make_setting("aws", "ec2", R, A, "ebs-encryption-by-default", {"Enabled": False}),
        make_setting("aws", "guardduty", R, A, "guardduty", {"Detectors": []}),
        make_setting("aws", "backup", R, A, "backup-protected", {"Resources": []}),
        make_setting("aws", "ssm", R, A, "ssm-managed", {"Instances": [
            {"InstanceId": i, "PingStatus": "Online"} for i in ("i-web1", "i-web2", "i-api1", "i-api2")]}),
        make_resource(DB, A, R, "rds", "db-instance", "orders", {"env": "prod"}, {
            "StorageEncrypted": False, "PubliclyAccessible": True, "MultiAZ": False, "BackupRetentionPeriod": 0,
            "AvailabilityZone": "eu-west-1a", "Engine": "postgres",
            "DBSubnetGroup": {"Subnets": [{"SubnetIdentifier": "s-a"}]}}, name="orders"),
        make_resource(AURORA, A, R, "rds", "db-instance", "aurora-1", {"env": "prod"}, {
            "StorageEncrypted": True, "PubliclyAccessible": False, "MultiAZ": False, "BackupRetentionPeriod": 7,
            "DBClusterIdentifier": "aurora"}, name="aurora-1"),
        make_resource(LB, A, R, "elasticloadbalancing", "load-balancer", "web", {"env": "prod"}, {
            "Scheme": "internet-facing", "AvailabilityZones": [{"ZoneName": "eu-west-1a"}], "Listeners": [
                {"Protocol": "HTTP", "Port": 80, "DefaultActions": [{"Type": "forward"}], "SslProtocols": []},
                {"Protocol": "HTTPS", "Port": 443, "SslPolicy": "ELBSecurityPolicy-2016-08",
                 "SslProtocols": ["TLSv1.2", "TLSv1.1", "TLSv1"], "DefaultActions": [{"Type": "forward"}]}]}, name="web"),
        make_resource(TG, A, R, "elasticloadbalancing", "target-group", "web", {"env": "prod"}, {
            "TargetHealth": [{"Id": "i-web1", "State": "healthy"}, {"Id": "i-web2", "State": "unhealthy",
                                                                     "Reason": "Target.FailedHealthChecks"}]}, name="web"),
        make_resource(ASG, A, R, "autoscaling", "autoscaling-group", "web", {"env": "prod"}, {
            "AvailabilityZones": ["eu-west-1a"], "TargetGroupARNs": [TG], "HealthCheckType": "EC2"}, name="web"),
        make_resource(CERT, A, R, "acm", "certificate", "abc", {}, {
            "DomainName": "shop.example.com", "InUseBy": [LB], "NotAfter": ago(-5), "Type": "AMAZON_ISSUED",
            "RenewalEligibility": "ELIGIBLE"}, name="shop.example.com"),
        make_resource(ALICE, A, GLOBAL, "iam", "user", "alice", {}, {"UserName": "alice"}, name="alice"),
        make_resource(f"arn:aws:iam::{A}:scamallscope-setting/credential-report", A, GLOBAL, "iam", "credential-report",
                      "credential-report", {}, {"Rows": [
                          {"user": "<root_account>", "arn": f"arn:aws:iam::{A}:root", "password_enabled": "not_supported",
                           "mfa_active": "false", "access_key_1_active": "false", "access_key_2_active": "false"},
                          {"user": "alice", "arn": ALICE, "password_enabled": "true", "mfa_active": "false",
                           "access_key_1_active": "true", "access_key_1_last_rotated": ago(200),
                           "access_key_1_last_used_date": ago(1), "access_key_2_active": "false"},
                          {"user": "bob", "arn": f"arn:aws:iam::{A}:user/bob", "password_enabled": "true",
                           "mfa_active": "true", "access_key_1_active": "true", "access_key_1_last_rotated": ago(10),
                           "access_key_1_last_used_date": "N/A", "access_key_2_active": "false"}]}),
    ]
    links = [
        ("vpc", "vpc-1", "subnet", "s-a", "contains"), ("vpc", "vpc-1", "subnet", "s-b", "contains"),
        ("vpc", "vpc-1", "subnet", "s-pa", "contains"), ("vpc", "vpc-1", "subnet", "s-pb", "contains"),
        ("subnet", "s-a", "instance", "i-bastion", "contains"), ("subnet", "s-pa", "instance", "i-web1", "contains"),
        ("subnet", "s-pa", "instance", "i-web2", "contains"), ("subnet", "s-pa", "instance", "i-api1", "contains"),
        ("subnet", "s-pb", "instance", "i-api2", "contains"), ("subnet", "s-a", "nat-gateway", "nat-1", "contains"),
        ("vpc", "vpc-1", "route-table", "rt-private", "contains"),
        ("route-table", "rt-private", "subnet", "s-pa", "routes"), ("route-table", "rt-private", "subnet", "s-pb", "routes"),
        ("route-table", "rt-private", "nat-gateway", "nat-1", "routes_to"),
        ("instance", "i-bastion", "security-group", "sg-open", "uses"), ("instance", "i-web1", "security-group", "sg-web", "uses"),
        ("volume", "vol-bastion", "instance", "i-bastion", "attached"), ("volume", "vol-web1", "instance", "i-web1", "attached"),
        ("volume", "vol-api1", "instance", "i-api1", "attached"),
        ("snapshot", "snap-api1", "volume", "vol-api1", "snapshot_of"),
    ]
    s["links"] = [link(ec2arn(a, b), ec2arn(c, d), t) for a, b, c, d, t in links]
    s["links"] += [link(TG, ec2arn("instance", "i-web1"), "targets"), link(TG, ec2arn("instance", "i-web2"), "targets"),
                   link(ASG, ec2arn("instance", "i-web1"), "manages"), link(LB, TG, "routes_to")]
    regional = [("ec2", t) for t in ("vpc", "subnet", "security-group", "instance", "route-table", "volume", "snapshot",
                                     "elastic-ip", "nat-gateway", "vpc-endpoint", "flow-log", "setting")]
    regional += [("rds", "db-instance"), ("elasticloadbalancing", "load-balancer"), ("elasticloadbalancing", "target-group"),
                 ("autoscaling", "autoscaling-group"), ("acm", "certificate"), ("guardduty", "setting"),
                 ("backup", "setting"), ("ssm", "setting")]
    s["units"] = [ok_unit(svc, t, R, 0) for svc, t in regional]
    s["units"] += [ok_unit("iam", "credential-report", GLOBAL, 1), ok_unit("cloudtrail", "trail", GLOBAL, 0),
                   ok_unit("iam", "user", GLOBAL, 1)]
    return s


NODES = {ec2arn("instance", "i-bastion"): {"exposure": "exposed"}, ec2arn("subnet", "s-a"): {"internet_route": True}}
COVERAGE = {"savings_plans_pct": 10.0, "reservations_pct": None, "on_demand_usd": 500.0, "days": 30}
