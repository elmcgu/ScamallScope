import json
import stat

from scamallscope import graph, snapshot
from scamallscope.cli import main

from test_snapshot import REGION, arn, build_estate


def collected(session):
    """Snapshot as it looks after a JSON round trip, like the CLI reads it."""
    snap = snapshot.collect(session, [REGION])
    return json.loads(json.dumps(snap.to_dict(), default=str))


def nodes_and_edges(g):
    nodes = {e["data"]["id"]: e["data"] for e in g["elements"] if e["group"] == "nodes"}
    edges = [e["data"] for e in g["elements"] if e["group"] == "edges"]
    return nodes, edges


def test_every_resource_is_a_node_and_every_link_an_edge(session):
    vpc, subnet, sg, instance = build_estate(session)
    snap = collected(session)

    g = graph.to_graph(snap)
    nodes, edges = nodes_and_edges(g)

    assert set(nodes) == {r["arn"] for r in snap["resources"]}
    assert len(edges) == len(snap["links"])
    assert all(e["source"] in nodes and e["target"] in nodes for e in edges)
    assert len({e["id"] for e in edges}) == len(edges)  # Cytoscape needs unique ids
    assert nodes[arn("vpc", vpc)]["label"] == "main"
    assert nodes[arn("subnet", subnet)]["label"] == subnet  # no Name tag: falls back to id
    assert g["meta"]["complete"] and g["meta"]["dropped_edges"] == 0


def test_security_group_rules_are_kept(session):
    *_, sg, _ = build_estate(session)
    session.client("ec2", region_name=REGION).authorize_security_group_ingress(
        GroupId=sg, IpProtocol="tcp", FromPort=22, ToPort=22, CidrIp="0.0.0.0/0"
    )

    nodes, _ = nodes_and_edges(graph.to_graph(collected(session)))

    assert {"protocol": "tcp", "from_port": 22, "to_port": 22, "sources": ["0.0.0.0/0"]} \
        in nodes[arn("security-group", sg)]["ingress"]


def test_raw_config_and_addresses_stay_out(session):
    *_, instance = build_estate(session)

    nodes, _ = nodes_and_edges(graph.to_graph(collected(session)))
    node = nodes[arn("instance", instance)]

    assert "config" not in node
    assert "PublicIpAddress" not in json.dumps(node) and "PrivateIpAddress" not in json.dumps(node)
    assert isinstance(node["has_public_ip"], bool)


def test_edges_to_missing_nodes_are_dropped_and_counted():
    snap = {
        "account_id": "123456789012", "collected_at": "2026-11-03T00:00:00+00:00", "regions": [REGION],
        "units": [{"service": "ec2", "resource_type": "vpc", "region": REGION, "status": "error",
                   "count": 0, "error": "UnauthorizedOperation: denied"}],
        "resources": [{"arn": "arn:s", "id": "subnet-1", "name": None, "type": "subnet", "service": "ec2",
                       "region": REGION, "account_id": "123456789012", "tags": {}, "config": {}}],
        "links": [{"source": "arn:vpc-missing", "target": "arn:s", "type": "contains"}],
    }

    g = graph.to_graph(snap)

    assert [e for e in g["elements"] if e["group"] == "edges"] == []
    assert g["meta"]["dropped_edges"] == 1
    assert not g["meta"]["complete"]
    assert g["meta"]["failed_units"][0]["resource_type"] == "vpc"


def test_cli_graph_writes_private_file(session, tmp_path, monkeypatch):
    build_estate(session)
    monkeypatch.setattr("scamallscope.cli.boto3.Session", lambda **kw: session)
    snap_file = tmp_path / "acct.snapshot.json"
    assert main(["collect", "--region", REGION, "--output", str(snap_file)]) == 0

    assert main(["graph", str(snap_file)]) == 0

    out = tmp_path / "acct.graph.json"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert json.loads(out.read_text())["elements"]
