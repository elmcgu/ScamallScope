import json

import pytest
from botocore.exceptions import ClientError

from scamallscope import exposure, graph, snapshot
from scamallscope.model import Resource, Snapshot

from test_snapshot import REGION, arn


def make_estate(session, *, public_ip=True, igw_route=True, explicit_table=True, open_cidr="0.0.0.0/0"):
    """VPC + subnet + instance with port 22 allowed from open_cidr and port 443 from 10.0.0.0/8."""
    ec2 = session.client("ec2", region_name=REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    igw = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc)

    if explicit_table:
        table = ec2.create_route_table(VpcId=vpc)["RouteTable"]["RouteTableId"]
        ec2.associate_route_table(RouteTableId=table, SubnetId=subnet)
    else:
        table = ec2.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc]}, {"Name": "association.main", "Values": ["true"]}]
        )["RouteTables"][0]["RouteTableId"]
    if igw_route:
        ec2.create_route(RouteTableId=table, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)

    sg = ec2.create_security_group(GroupName="web", Description="web", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[
        {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": open_cidr}]},
        {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
    ])

    image = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
    instance = ec2.run_instances(ImageId=image, MinCount=1, MaxCount=1, NetworkInterfaces=[{
        "DeviceIndex": 0, "SubnetId": subnet, "Groups": [sg], "AssociatePublicIpAddress": public_ip,
    }])["Instances"][0]["InstanceId"]
    return {"vpc": vpc, "subnet": subnet, "igw": igw, "table": table, "sg": sg, "instance": instance}


def result_for(session, ids):
    snap = snapshot.collect(session, [REGION])
    return exposure.analyse(snap)[arn("instance", ids["instance"])], snap


def test_port_open_to_world_with_public_ip_and_igw_route_is_exposed(session):
    ids = make_estate(session)

    result, _ = result_for(session, ids)

    assert result["exposure"] == "exposed"
    assert [{k: v for k, v in p.items() if k != "network_acl"} for p in result["ports"]] == [
        {"protocol": "tcp", "from_port": 22, "to_port": 22, "family": "ipv4", "security_group": ids["sg"]}
    ]  # 443 is private only
    assert result["ports"][0]["network_acl"].startswith("acl-")  # the VPC default ACL


def test_main_route_table_is_used_when_subnet_has_no_explicit_one(session):
    ids = make_estate(session, explicit_table=False)

    result, _ = result_for(session, ids)

    assert result["exposure"] == "exposed"


@pytest.mark.parametrize("kwargs, reason", [
    ({"public_ip": False}, "no public IP address"),
    ({"igw_route": False}, "no default route to an internet gateway"),
    ({"open_cidr": "203.0.113.0/24"}, "no inbound rule open to the internet"),
])
def test_not_exposed_when_one_condition_is_missing(session, kwargs, reason):
    ids = make_estate(session, **kwargs)

    result, _ = result_for(session, ids)

    assert result == {"exposure": "not_exposed", "reason": reason, "ports": []}


def test_detached_gateway_does_not_count(session):
    ids = make_estate(session)
    session.client("ec2", region_name=REGION).detach_internet_gateway(
        InternetGatewayId=ids["igw"], VpcId=ids["vpc"])

    result, _ = result_for(session, ids)

    assert result["exposure"] == "not_exposed"


@pytest.mark.parametrize("operation, unit", [
    ("DescribeRouteTables", "route-table"),
    ("DescribeInternetGateways", "internet-gateway"),
    ("DescribeSecurityGroups", "security-group"),
    ("DescribeNetworkAcls", "network-acl"),
])
def test_unknown_when_a_needed_unit_failed(session, operation, unit):
    ids = make_estate(session)

    def deny(**kwargs):
        raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}, operation)

    session.events.register(f"before-call.ec2.{operation}", deny)

    result, _ = result_for(session, ids)

    assert result["exposure"] == "unknown"
    assert unit in result["reason"]


def test_stopped_instance_is_not_exposed(session):
    ids = make_estate(session)
    session.client("ec2", region_name=REGION).stop_instances(InstanceIds=[ids["instance"]])

    result, _ = result_for(session, ids)

    assert result["reason"] == "instance is not running"


def test_graph_shows_exposure_and_new_links(session):
    ids = make_estate(session)
    _, snap = result_for(session, ids)

    g = graph.to_graph(snap)
    nodes = {e["data"]["id"]: e["data"] for e in g["elements"] if e["group"] == "nodes"}
    edges = {(e["data"]["source"], e["data"]["target"], e["data"]["type"])
             for e in g["elements"] if e["group"] == "edges"}

    node = nodes[arn("instance", ids["instance"])]
    assert node["exposure"] == "exposed" and node["exposed_ports"][0]["from_port"] == 22
    assert (arn("internet-gateway", ids["igw"]), arn("vpc", ids["vpc"]), "attached") in edges
    assert (arn("route-table", ids["table"]), arn("subnet", ids["subnet"]), "routes") in edges
    assert (arn("route-table", ids["table"]), arn("internet-gateway", ids["igw"]), "routes_to") in edges
    assert "network ACL" in g["meta"]["exposure_checks"]
    acl_nodes = [n for n in nodes.values() if n["type"] == "network-acl"]
    assert any(n["is_default"] and n["entries"] for n in acl_nodes)
    assert any(e[1] == arn("subnet", ids["subnet"]) and e[2] == "filters" for e in edges)


def test_security_group_on_network_interface_creates_uses_link(session):
    ids = make_estate(session)
    _, snap = result_for(session, ids)

    links = {(l["source"], l["target"], l["type"]) for l in snap["links"]}

    assert (arn("instance", ids["instance"]), arn("security-group", ids["sg"]), "uses") in links


def test_second_interface_with_public_ip_is_checked():
    """Primary interface is private; a second interface has a public IP and an open group."""
    region, acct = REGION, "123456789012"

    def res(kind: str, rid: str, config: dict) -> Resource:
        return {"arn": f"arn:aws:ec2:{region}:{acct}:{kind}/{rid}", "id": rid, "type": kind,
                "region": region, "service": "ec2", "account_id": acct, "name": None, "tags": {}, "config": config}

    snap: Snapshot = {
        "schema_version": 1, "account_id": acct, "partition": "aws",
        "collected_at": "2026-11-03T00:00:00+00:00", "regions": [region],
        "units": [],
        "resources": [
            res("subnet", "subnet-priv", {"SubnetId": "subnet-priv", "VpcId": "vpc-1"}),
            res("subnet", "subnet-pub", {"SubnetId": "subnet-pub", "VpcId": "vpc-1"}),
            res("internet-gateway", "igw-1", {"Attachments": [{"VpcId": "vpc-1", "State": "available"}]}),
            res("route-table", "rtb-main", {"VpcId": "vpc-1", "Associations": [{"Main": True}],
                                            "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]}),
            res("route-table", "rtb-pub", {"VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-pub"}],
                                           "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1",
                                                       "State": "active"}]}),
            res("network-acl", "acl-1", {"NetworkAclId": "acl-1", "VpcId": "vpc-1", "IsDefault": True,
                                         "Associations": [], "Entries": [
                {"RuleNumber": 100, "Egress": False, "Protocol": "-1", "RuleAction": "allow",
                 "CidrBlock": "0.0.0.0/0"}]}),
            res("security-group", "sg-priv", {"IpPermissions": []}),
            res("security-group", "sg-open", {"IpPermissions": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}),
            res("instance", "i-1", {"State": {"Name": "running"}, "SubnetId": "subnet-priv", "NetworkInterfaces": [
                {"SubnetId": "subnet-priv", "Attachment": {"DeviceIndex": 0}, "Groups": [{"GroupId": "sg-priv"}]},
                {"SubnetId": "subnet-pub", "Attachment": {"DeviceIndex": 1}, "Groups": [{"GroupId": "sg-open"}],
                 "Association": {"PublicIp": "198.51.100.7"}},
            ]}),
        ],
        "links": [],
    }

    result = exposure.analyse(snap)[f"arn:aws:ec2:{region}:{acct}:instance/i-1"]

    assert result["exposure"] == "exposed"
    # "All protocols" is reported as TCP, UDP and ICMP, as far as the ACL lets them in.
    assert {(p["protocol"], p["from_port"], p["to_port"]) for p in result["ports"]} == {
        ("tcp", 0, 65535), ("udp", 0, 65535), ("icmp", None, None)}
    assert {p["security_group"] for p in result["ports"]} == {"sg-open"}


def use_custom_acl(session, ids, entries):
    """Give the subnet its own network ACL with the given inbound entries."""
    ec2 = session.client("ec2", region_name=REGION)
    acl = ec2.create_network_acl(VpcId=ids["vpc"])["NetworkAcl"]["NetworkAclId"]
    for e in entries:
        ec2.create_network_acl_entry(NetworkAclId=acl, Egress=False, **e)
    current = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [ids["subnet"]]}])["NetworkAcls"][0]
    assoc = next(a["NetworkAclAssociationId"] for a in current["Associations"] if a["SubnetId"] == ids["subnet"])
    ec2.replace_network_acl_association(AssociationId=assoc, NetworkAclId=acl)
    return acl


ALLOW_ALL = {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0"}


def test_acl_deny_before_allow_blocks_the_port(session):
    ids = make_estate(session)
    use_custom_acl(session, ids, [
        {"RuleNumber": 90, "Protocol": "6", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0",
         "PortRange": {"From": 22, "To": 22}},
        ALLOW_ALL,
    ])

    result, _ = result_for(session, ids)

    assert result == {"exposure": "not_exposed", "ports": [],
                      "reason": "network ACL blocks the ports the security group opens"}


def test_acl_allow_before_deny_lets_the_port_in(session):
    ids = make_estate(session)
    acl = use_custom_acl(session, ids, [
        {"RuleNumber": 50, "Protocol": "6", "RuleAction": "allow", "CidrBlock": "0.0.0.0/0",
         "PortRange": {"From": 22, "To": 22}},
        {"RuleNumber": 60, "Protocol": "-1", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0"},
    ])

    result, _ = result_for(session, ids)

    assert result["exposure"] == "exposed"
    assert result["ports"][0]["network_acl"] == acl


def test_acl_with_no_matching_allow_denies_by_default(session):
    ids = make_estate(session)
    use_custom_acl(session, ids, [])  # only the built-in "*" deny

    result, _ = result_for(session, ids)

    assert result["exposure"] == "not_exposed"


def test_narrow_acl_deny_does_not_close_the_port_to_the_world(session):
    ids = make_estate(session)
    use_custom_acl(session, ids, [
        {"RuleNumber": 10, "Protocol": "-1", "RuleAction": "deny", "CidrBlock": "203.0.113.0/24"},
        ALLOW_ALL,
    ])

    result, _ = result_for(session, ids)

    assert result["exposure"] == "exposed"


def test_only_the_part_of_a_range_the_acl_allows_is_reported(session):
    ids = make_estate(session)
    session.client("ec2", region_name=REGION).authorize_security_group_ingress(
        GroupId=ids["sg"], IpProtocol="tcp", FromPort=8000, ToPort=8100, CidrIp="0.0.0.0/0")
    use_custom_acl(session, ids, [
        {"RuleNumber": 10, "Protocol": "6", "RuleAction": "deny", "CidrBlock": "0.0.0.0/0",
         "PortRange": {"From": 8050, "To": 8059}},
        ALLOW_ALL,
    ])

    result, _ = result_for(session, ids)

    assert {(p["from_port"], p["to_port"]) for p in result["ports"]} == {(22, 22), (8000, 8049), (8060, 8100)}


def test_subnet_internet_route_marks_public_and_private_subnets(session):
    ids = make_estate(session)
    ec2 = session.client("ec2", region_name=REGION)
    private = ec2.create_subnet(VpcId=ids["vpc"], CidrBlock="10.0.2.0/24")["Subnet"]["SubnetId"]
    _, snap = result_for(session, ids)

    routes = exposure.subnet_internet_routes(snap)

    assert routes[arn("subnet", ids["subnet"])] is True
    assert routes[arn("subnet", private)] is False  # main table has no internet route
    nodes = {e["data"]["id"]: e["data"] for e in graph.to_graph(snap)["elements"] if e["group"] == "nodes"}
    assert nodes[arn("subnet", ids["subnet"])]["internet_route"] is True


def test_subnet_internet_route_is_unknown_when_route_tables_failed(session):
    ids = make_estate(session)

    def deny(**kwargs):
        raise ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}}, "DescribeRouteTables")

    session.events.register("before-call.ec2.DescribeRouteTables", deny)
    _, snap = result_for(session, ids)

    assert exposure.subnet_internet_routes(snap)[arn("subnet", ids["subnet"])] is None
