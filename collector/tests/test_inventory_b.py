"""Spec 10: inventory for availability, cost and account controls (moto; Stubber where moto lacks it)."""

import re

import pytest
from botocore.exceptions import ClientError

from scamallscope import graph, snapshot
from scamallscope.collectors import ec2 as ec2_collector
from scamallscope.model import is_complete

from test_snapshot import REGION, arn, build_estate

ACCOUNT = "123456789012"


def collect(session):
    return snapshot.collect(session, [REGION])


def by_type(snap, kind):
    return {r["id"]: r for r in snap["resources"] if r["type"] == kind}


def links(snap):
    return {(l["source"], l["target"], l["type"]) for l in snap["links"]}


@pytest.fixture
def estate(session):
    vpc, subnet, sg, instance = build_estate(session)
    return session.client("ec2", region_name=REGION), vpc, subnet, sg, instance


def test_INV_1_volumes_and_attachment(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    az = ec2.describe_subnets(SubnetIds=[subnet])["Subnets"][0]["AvailabilityZone"]
    attached = ec2.create_volume(AvailabilityZone=az, Size=20, VolumeType="gp2")["VolumeId"]
    ec2.attach_volume(VolumeId=attached, InstanceId=instance, Device="/dev/sdf")
    loose = ec2.create_volume(AvailabilityZone=az, Size=50, VolumeType="gp3")["VolumeId"]

    snap = collect(session)
    vols = by_type(snap, "volume")
    assert {attached, loose} <= set(vols)
    assert (arn("volume", attached), arn("instance", instance), "attached") in links(snap)
    assert not any(l[0] == arn("volume", loose) for l in links(snap))


def test_INV_2_own_snapshots_only(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    az = ec2.describe_subnets(SubnetIds=[subnet])["Subnets"][0]["AvailabilityZone"]
    vol = ec2.create_volume(AvailabilityZone=az, Size=8)["VolumeId"]
    snap_id = ec2.create_snapshot(VolumeId=vol, Description="nightly")["SnapshotId"]

    snap = collect(session)
    snaps = by_type(snap, "snapshot")
    assert snap_id in snaps
    assert all(s["config"].get("OwnerId") in (None, ACCOUNT) for s in snaps.values())  # moto's AMI snapshots dropped
    assert (arn("snapshot", snap_id), arn("volume", vol), "snapshot_of") in links(snap)


def test_INV_3_elastic_ips(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    used = ec2.allocate_address(Domain="vpc")["AllocationId"]
    ec2.associate_address(AllocationId=used, InstanceId=instance)
    idle = ec2.allocate_address(Domain="vpc")["AllocationId"]

    snap = collect(session)
    eips = by_type(snap, "elastic-ip")
    assert {used, idle} <= set(eips)
    assert (arn("elastic-ip", used), arn("instance", instance), "attached") in links(snap)
    nodes = {e["data"]["id"]: e["data"] for e in graph.to_graph(snap)["elements"] if e["group"] == "nodes"}
    assert nodes[arn("elastic-ip", used)]["associated"] is True
    assert nodes[arn("elastic-ip", idle)]["associated"] is False


def test_INV_4_nat_gateway_and_route(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
    nat = ec2.create_nat_gateway(SubnetId=subnet, AllocationId=eip)["NatGateway"]["NatGatewayId"]
    rt = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=rt, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat)

    snap = collect(session)
    assert nat in by_type(snap, "nat-gateway")
    assert (arn("subnet", subnet), arn("nat-gateway", nat), "contains") in links(snap)
    assert (arn("route-table", rt), arn("nat-gateway", nat), "routes_to") in links(snap)


def test_INV_5_vpc_endpoint_and_flow_log(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    ep = ec2.create_vpc_endpoint(VpcId=vpc, ServiceName=f"com.amazonaws.{REGION}.s3",
                                 VpcEndpointType="Gateway")["VpcEndpoint"]["VpcEndpointId"]
    session.client("s3", region_name=REGION).create_bucket(
        Bucket="example-flow-logs", CreateBucketConfiguration={"LocationConstraint": REGION})
    fl = ec2.create_flow_logs(ResourceIds=[vpc], ResourceType="VPC", TrafficType="ALL",
                              LogDestinationType="s3", LogDestination="arn:aws:s3:::example-flow-logs")["FlowLogIds"][0]

    snap = collect(session)
    assert ep in by_type(snap, "vpc-endpoint") and fl in by_type(snap, "flow-log")
    assert (arn("vpc", vpc), arn("vpc-endpoint", ep), "contains") in links(snap)
    assert (arn("flow-log", fl), arn("vpc", vpc), "logs") in links(snap)


def test_INV_6_ebs_encryption_by_default_setting(session, estate):
    snap = collect(session)
    settings = by_type(snap, "setting")
    s = settings["ebs-encryption-by-default"]
    assert s["config"] == {"Enabled": False} and s["service"] == "ec2" and s["region"] == REGION
    assert s["arn"] == f"arn:aws:ec2:{REGION}:{ACCOUNT}:scamallscope-setting/ebs-encryption-by-default"

    session.client("ec2", region_name=REGION).enable_ebs_encryption_by_default()
    assert by_type(collect(session), "setting")["ebs-encryption-by-default"]["config"]["Enabled"] is True


def test_INV_15_failed_new_unit_is_error_not_empty(session, estate, monkeypatch):
    def denied(client, ctx):
        raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "no"}}, "DescribeVolumes")

    monkeypatch.setattr(ec2_collector, "COLLECTORS",
                        [(t, denied if t == "volume" else fn) for t, fn in ec2_collector.COLLECTORS])
    snap = collect(session)
    units = {(u["service"], u["resource_type"]): u for u in snap["units"]}
    assert units[("ec2", "volume")]["status"] == "error"
    assert units[("ec2", "instance")]["status"] == "ok"
    assert not is_complete(snap)


def test_INV_16_graph_fields_and_no_ip_addresses(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    az = ec2.describe_subnets(SubnetIds=[subnet])["Subnets"][0]["AvailabilityZone"]
    vol = ec2.create_volume(AvailabilityZone=az, Size=20, VolumeType="gp2", Encrypted=True)["VolumeId"]
    ec2.allocate_address(Domain="vpc")

    g = graph.to_graph(collect(session))
    nodes = {e["data"]["id"]: e["data"] for e in g["elements"] if e["group"] == "nodes"}
    v = nodes[arn("volume", vol)]
    assert (v["size_gb"], v["volume_type"], v["encrypted"], v["availability_zone"]) == (20, "gp2", True, az)
    i = nodes[arn("instance", instance)]
    assert i["availability_zone"] == az and "imds_v2_required" in i and i["auto_recovery"]
    text = str(g)
    assert "PublicIp" not in text and "PrivateIpAddress" not in text
    assert not re.search(r"'(\d{1,3}\.){3}\d{1,3}'", text)  # no bare IPv4 values (CIDRs have a slash)


def test_snapshot_manager():
    assert graph.snapshot_manager({"Tags": [{"Key": "aws:dlm:lifecycle-policy-id", "Value": "x"}]}) == "dlm"
    assert graph.snapshot_manager({"Description": "This snapshot is created by the AWS Backup service on ..."}) == "backup"
    assert graph.snapshot_manager({"Description": "by hand"}) is None


def _second_subnet(ec2, vpc):
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"]]
    return ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.2.0/24", AvailabilityZone=azs[1])["Subnet"]["SubnetId"]


def test_INV_7_rds_instance(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    other = _second_subnet(ec2, vpc)
    rds = session.client("rds", region_name=REGION)
    rds.create_db_subnet_group(DBSubnetGroupName="db", DBSubnetGroupDescription="db", SubnetIds=[subnet, other])
    db = rds.create_db_instance(DBInstanceIdentifier="orders-db", Engine="postgres", DBInstanceClass="db.t3.micro",
                                MasterUsername="admin", MasterUserPassword="example-not-real",  # pragma: allowlist secret
                                AllocatedStorage=20, DBSubnetGroupName="db", VpcSecurityGroupIds=[sg],
                                MultiAZ=False, StorageEncrypted=False, PubliclyAccessible=True,
                                BackupRetentionPeriod=0, Tags=[{"Key": "env", "Value": "prod"}])["DBInstance"]

    snap = collect(session)
    r = by_type(snap, "db-instance")["orders-db"]
    assert r["arn"] == db["DBInstanceArn"] and r["tags"] == {"env": "prod"}
    assert r["config"]["MultiAZ"] is False and r["config"]["PubliclyAccessible"] is True
    assert "Endpoint" not in r["config"] and "MasterUserPassword" not in str(r["config"])
    assert (arn("vpc", vpc), r["arn"], "contains") in links(snap)
    assert (r["arn"], arn("security-group", sg), "uses") in links(snap)
    node = {e["data"]["id"]: e["data"] for e in graph.to_graph(snap)["elements"] if e["group"] == "nodes"}[r["arn"]]
    assert (node["multi_az"], node["encrypted"], node["publicly_accessible"], node["backup_retention_days"]) == (False, False, True, 0)


def _alb(session, ec2, vpc, subnet, sg, instance):
    other = _second_subnet(ec2, vpc)
    elb = session.client("elbv2", region_name=REGION)
    lb = elb.create_load_balancer(Name="web", Subnets=[subnet, other], SecurityGroups=[sg], Scheme="internet-facing",
                                  Tags=[{"Key": "app", "Value": "web"}])["LoadBalancers"][0]
    tg = elb.create_target_group(Name="web", Protocol="HTTP", Port=80, VpcId=vpc, TargetType="instance")["TargetGroups"][0]
    elb.register_targets(TargetGroupArn=tg["TargetGroupArn"], Targets=[{"Id": instance}])
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
    acm = session.client("acm", region_name=REGION)
    cert = acm.request_certificate(DomainName="web.example.com")["CertificateArn"]
    elb.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTPS", Port=443,
                        SslPolicy="ELBSecurityPolicy-2016-08", Certificates=[{"CertificateArn": cert}],
                        DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
    return lb, tg


def test_INV_8_load_balancer_listeners_and_targets(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    lb, tg = _alb(session, ec2, vpc, subnet, sg, instance)

    snap = collect(session)
    r = by_type(snap, "load-balancer")["web"]
    assert r["tags"] == {"app": "web"} and "DNSName" not in r["config"]
    listeners = {x["Protocol"]: x for x in r["config"]["Listeners"]}
    assert listeners["HTTP"]["SslProtocols"] == []
    assert "TLSv1.2" in listeners["HTTPS"]["SslProtocols"]  # from DescribeSSLPolicies, not a list in our code
    t = by_type(snap, "target-group")["web"]
    assert [h["Id"] for h in t["config"]["TargetHealth"]] == [instance]
    assert (lb["LoadBalancerArn"], tg["TargetGroupArn"], "routes_to") in links(snap)
    assert (tg["TargetGroupArn"], arn("instance", instance), "targets") in links(snap)
    node = {e["data"]["id"]: e["data"] for e in graph.to_graph(snap)["elements"] if e["group"] == "nodes"}[r["arn"]]
    assert len(node["availability_zones"]) == 2 and node["scheme"] == "internet-facing"
    assert {(x["protocol"], x["redirects_to_https"]) for x in node["listeners"]} == {("HTTP", False), ("HTTPS", False)}


def test_INV_9_autoscaling_group(session, estate):
    ec2, vpc, subnet, sg, instance = estate
    lb, tg = _alb(session, ec2, vpc, subnet, sg, instance)
    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    asg = session.client("autoscaling", region_name=REGION)
    asg.create_launch_configuration(LaunchConfigurationName="web", ImageId=image, InstanceType="t3.micro")
    asg.create_auto_scaling_group(AutoScalingGroupName="web", LaunchConfigurationName="web", MinSize=1, MaxSize=2,
                                  DesiredCapacity=1, VPCZoneIdentifier=subnet, TargetGroupARNs=[tg["TargetGroupArn"]],
                                  HealthCheckType="EC2", Tags=[{"Key": "env", "Value": "prod", "PropagateAtLaunch": True}])

    snap = collect(session)
    g = by_type(snap, "autoscaling-group")["web"]
    assert g["tags"] == {"env": "prod"} and len(g["config"]["AvailabilityZones"]) == 1
    managed = [l for l in links(snap) if l[0] == g["arn"] and l[2] == "manages"]
    assert len(managed) == 1
    assert (g["arn"], tg["TargetGroupArn"], "registers") in links(snap)
