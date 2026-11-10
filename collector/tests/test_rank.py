"""Spec 13: duplicates, priority and totals."""

from scamallscope import findings, rank

BUCKET = "arn:aws:s3:::demo-backups"
VOL = "arn:aws:ec2:eu-west-1:123456789012:volume/vol-1"
WEB = "arn:aws:ec2:eu-west-1:123456789012:instance/i-web"
DB = "arn:aws:ec2:eu-west-1:123456789012:instance/i-db"


def f(source, check, sev, bps, resource, saving=None, pillar=None):
    return findings.make(source, check, check, sev, bps, resource, resource or "account", "eu-west-1",
                         pillar=pillar, savings_usd=saving)


def test_RNK_1_prowler_duplicate_of_own_rule():
    p = f("prowler", "s3_bucket_default_encryption", "high", ["SEC08-BP02"], BUCKET)
    h = f("inventory", "HYG-S3-002", "medium", ["SEC08-BP02"], BUCKET)
    rank.apply([p, h], {})
    assert p["duplicate_of"] == h["id"] and h["duplicate_of"] is None
    assert h["also_reported_by"] == ["prowler"]


def test_RNK_2_hub_beats_own_cost_rule():
    hub = f("costhub", "COST-HUB-Delete", "low", ["COST04-BP03"], VOL, 12.5)
    own = f("inventory", "COST-EBS-001", "low", ["COST04-BP03"], VOL, 8.0)
    rank.apply([own, hub], {})
    assert own["duplicate_of"] == hub["id"] and hub["also_reported_by"] == ["inventory"]


def test_RNK_3_different_pillars_are_not_duplicates():
    a = f("inventory", "SEC-EBS-001", "medium", ["SEC08-BP02"], VOL)
    b = f("inventory", "COST-EBS-001", "low", ["COST04-BP03"], VOL, 8.0)
    rank.apply([a, b], {})
    assert a["duplicate_of"] is None and b["duplicate_of"] is None


def test_RNK_4_exposed_first():
    exposed = f("inventory", "SEC-EC2-001", "high", ["SEC06-BP02"], WEB)
    private = f("inventory", "SEC-EC2-001", "high", ["SEC06-BP02"], DB)
    rank.apply([exposed, private], {WEB: {"exposure": "exposed", "tags": {"env": "prod"}}, DB: {"tags": {"env": "prod"}}})
    assert exposed["priority"] > private["priority"]


def test_RNK_5_saving_beats_severity():
    big = f("inventory", "COST-EBS-001", "low", ["COST04-BP03"], VOL, 50)
    small = f("costhub", "COST-HUB-Rightsize", "high", ["COST06-BP02"], WEB, 10)
    rank.apply([big, small], {})
    assert big["priority"] > small["priority"]


def test_prod_ranks_reliability_higher():
    prod = f("inventory", "REL-AZ-002", "high", ["REL10-BP01"], WEB)
    dev = f("inventory", "REL-AZ-002", "high", ["REL10-BP01"], DB)
    rank.apply([prod, dev], {WEB: {"tags": {}}, DB: {"tags": {"env": "dev"}}})  # no env tag = prod
    assert prod["priority"] == 90 and dev["priority"] == 70


def test_RNK_6_summary_counts_primaries_once():
    hub = f("costhub", "COST-HUB-Delete", "low", ["COST04-BP03"], VOL, 12.5)
    own = f("inventory", "COST-EBS-001", "low", ["COST04-BP03"], VOL, 8.0)
    eip = f("inventory", "COST-EIP-001", "low", ["COST04-BP03"], None, 3.65)
    spof = f("inventory", "REL-AZ-001", "high", ["REL10-BP01"], None)
    s = rank.apply([hub, own, eip, spof], {})
    assert s["savings_usd"] == 16.15 and s["savings_estimated"] is True
    assert s["open"]["low"] == 2 and s["open"]["high"] == 1 and s["single_points_of_failure"] == 1
    assert s["by_pillar"] == {"security": 0, "cost": 2, "reliability": 1}
