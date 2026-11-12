"""Spec 12: security, cost and availability rules. One hit and one clean case per rule."""

import pytest

from scamallscope import hygiene
from scamallscope.model import make_resource

import estate_b as E
from estate_b import ec2arn as a


def run(snap=None, sources=None, extras=None, nodes=None):
    return hygiene.run(snap or E.snapshot(), E.NODES if nodes is None else nodes,
                       {"cost": {}} if sources is None else sources,
                       extras={"cost_coverage": E.COVERAGE} if extras is None else extras, today=E.TODAY)


@pytest.fixture(scope="module")
def out():
    return run()


def hits(out, rule):
    return {(f["resource"] or f["resource_name"]): f for f in out["findings"] if f["check_id"] == rule}


# (rule, resource ARN or name that must be hit, severity, a resource that must not be hit or None)
CASES = [
    ("SEC-NET-001", a("instance", "i-bastion"), "critical", a("instance", "i-web1")),
    ("SEC-EC2-001", a("instance", "i-bastion"), "medium", a("instance", "i-web1")),
    ("SEC-EC2-002", a("instance", "i-bastion"), "low", a("instance", "i-web1")),
    ("SEC-EBS-001", a("volume", "vol-bastion"), "medium", a("volume", "vol-web1")),
    ("SEC-EBS-002", f"arn:aws:ec2:{E.R}:{E.A}:scamallscope-setting/ebs-encryption-by-default", "medium", None),
    ("SEC-RDS-001", E.DB, "high", E.AURORA),
    ("SEC-RDS-002", E.DB, "critical", E.AURORA),
    ("SEC-ELB-001", E.LB, "medium", None),
    ("SEC-ELB-002", E.LB, "medium", None),
    ("SEC-ACM-001", E.CERT, "high", None),
    ("SEC-IAM-002", E.ALICE, "medium", "bob"),
    ("SEC-IAM-003", E.ALICE, "high", "bob"),
    ("SEC-IAM-004", "root user", "critical", None),
    ("SEC-LOG-001", "account", "high", None),
    ("SEC-LOG-002", a("vpc", "vpc-1"), "low", None),
    ("SEC-DET-001", f"arn:aws:guardduty:{E.R}:{E.A}:scamallscope-setting/guardduty", "medium", None),
    ("COST-EBS-001", a("volume", "vol-loose"), "low", a("volume", "vol-web1")),
    ("COST-EBS-002", a("volume", "vol-bastion"), "info", a("volume", "vol-loose")),
    ("COST-SNAP-001", a("snapshot", "snap-old"), "low", a("snapshot", "snap-backup")),
    ("COST-EIP-001", a("elastic-ip", "eipalloc-idle"), "low", a("elastic-ip", "eipalloc-used")),
    ("COST-NAT-001", a("nat-gateway", "nat-1"), "low", None),
    ("COST-COV-001", "account", "medium", None),
    ("REL-AZ-001", "app web (main)", "high", "app api (main)"),
    ("REL-AZ-002", E.DB, "high", E.AURORA),
    ("REL-AZ-003", E.LB, "high", None),
    ("REL-AZ-004", a("nat-gateway", "nat-1"), "medium", None),
    ("REL-HEAL-001", a("instance", "i-bastion"), "medium", a("instance", "i-api1")),
    ("REL-HEAL-002", E.ASG, "low", None),
    ("REL-HEAL-003", E.TG, "high", None),
    ("REL-BAK-001", a("volume", "vol-bastion"), "high", a("volume", "vol-api1")),
    ("REL-BAK-002", E.DB, "high", E.AURORA),
    ("REL-BAK-003", a("snapshot", "snap-old"), "medium", a("snapshot", "snap-backup")),
]


@pytest.mark.parametrize("rule,hit,severity,clean", CASES, ids=[c[0] for c in CASES])
def test_rule(out, rule, hit, severity, clean):
    found = hits(out, rule)
    assert hit in found, f"{rule}: {sorted(found)}"
    assert found[hit]["severity"] == severity
    assert clean is None or clean not in found
    assert found[hit]["remediation"]


def test_SEC_NET_001_high_when_not_exposed():
    assert hits(run(nodes={}), "SEC-NET-001")[a("instance", "i-bastion")]["severity"] == "high"


def test_SEC_RDS_002_high_in_private_subnet():
    assert hits(run(nodes={}), "SEC-RDS-002")[E.DB]["severity"] == "high"


def test_REL_AZ_001_standalone_and_target_group(out):
    found = hits(out, "REL-AZ-001")
    assert found[a("instance", "i-bastion")]["severity"] == "medium"  # alone, prod
    assert found[E.TG]["severity"] == "high"  # both targets in eu-west-1a
    assert a("instance", "i-web1") not in found  # in an ASG and a target


def test_cost_savings(out):
    assert hits(out, "COST-EBS-001")[a("volume", "vol-loose")]["savings_usd"] == 8.0
    assert hits(out, "COST-EBS-002")[a("volume", "vol-bastion")]["savings_usd"] == 0.4
    assert hits(out, "COST-SNAP-001")[a("snapshot", "snap-old")]["savings_usd"] == 2.5
    assert hits(out, "COST-EIP-001")[a("elastic-ip", "eipalloc-idle")]["savings_usd"] == 3.65
    assert hits(out, "COST-NAT-001")[a("nat-gateway", "nat-1")]["savings_usd"] is None


def test_COST_NAT_001_clean_with_gateway_endpoint():
    snap = E.snapshot()
    ep = E.ec2("vpc-endpoint", "vpce-s3", {"VpcEndpointType": "Gateway", "ServiceName": f"com.amazonaws.{E.R}.s3"})
    snap["resources"].append(ep)
    snap["links"].append({"source": a("vpc", "vpc-1"), "target": ep["arn"], "type": "contains"})
    assert not hits(run(snap), "COST-NAT-001")


def test_COST_COV_001_needs_cost_source_and_low_coverage():
    assert not hits(run(sources={}), "COST-COV-001")
    assert not hits(run(extras={"cost_coverage": {**E.COVERAGE, "savings_plans_pct": 80.0}}), "COST-COV-001")
    assert not hits(run(extras={"cost_coverage": {**E.COVERAGE, "on_demand_usd": 50.0}}), "COST-COV-001")


def test_SEC_LOG_001_clean_with_logging_trail():
    snap = E.snapshot()
    snap["resources"].append(make_resource(f"arn:aws:cloudtrail:{E.R}:{E.A}:trail/org", E.A, "global", "cloudtrail",
                                           "trail", "org", {}, {"IsMultiRegionTrail": True, "IsLogging": True}))
    assert not hits(run(snap), "SEC-LOG-001")
    assert run(snap)["coverage"]["SEC04-BP01"]["passed"] >= 1


def test_SEC_LOG_002_clean_with_flow_log():
    snap = E.snapshot()
    fl = E.ec2("flow-log", "fl-1", {"ResourceId": "vpc-1"})
    snap["resources"].append(fl)
    snap["links"].append({"source": fl["arn"], "target": a("vpc", "vpc-1"), "type": "logs"})
    assert not hits(run(snap), "SEC-LOG-002")


def test_REL_BAK_001_backup_recovery_point_counts():
    snap = E.snapshot()
    backup = next(r for r in snap["resources"] if r["id"] == "backup-protected")
    backup["config"]["Resources"] = [{"ResourceArn": a("volume", "vol-bastion"), "LastBackupTime": E.ago(2)},
                                     {"ResourceArn": E.DB, "LastBackupTime": E.ago(30)}]
    found = hits(run(snap), "REL-BAK-001")
    assert a("volume", "vol-bastion") not in found and E.DB in found  # 30 days is not recent


def test_REL_HEAL_001_recover_alarm_counts():
    out = run(sources={"cost": {}, "cloudwatch": {a("instance", "i-bastion"): {"recover_alarm": True, "alarms": 1}}})
    assert not hits(out, "REL-HEAL-001")


def test_RUL_1_failed_unit_checks_nothing():
    snap = E.snapshot()
    for u in snap["units"]:
        if u["service"] == "ssm":
            u["status"] = "error"
    out, ok = run(snap), run()
    assert not hits(out, "SEC-EC2-002") and hits(ok, "SEC-EC2-002")
    # SEC06-BP03 is also checked by SEC-NET-001; the failed SSM unit adds nothing to it.
    sec = out["coverage"]["SEC06-BP03"]
    assert sec["passed"] + sec["failed"] < ok["coverage"]["SEC06-BP03"]["passed"] + ok["coverage"]["SEC06-BP03"]["failed"]


def test_RUL_1_missing_report_unit():
    snap = E.snapshot()
    snap["units"] = [u for u in snap["units"] if u["resource_type"] != "credential-report"]
    out = run(snap)
    assert not hits(out, "SEC-IAM-002") and not hits(out, "SEC-IAM-004")


def test_RUL_2_no_env_tag_is_prod():
    snap = E.snapshot()
    db = next(r for r in snap["resources"] if r["arn"] == E.DB)
    db["tags"] = {}
    assert hits(run(snap), "REL-AZ-002")[E.DB]["severity"] == "high"
    db["tags"] = {"env": "test"}
    assert hits(run(snap), "REL-AZ-002")[E.DB]["severity"] == "low"


def test_RUL_4_every_finding_has_remediation_and_cost_has_savings_key(out):
    assert all(f["remediation"] for f in out["findings"])
    assert all("savings_usd" in f for f in out["findings"])
    assert all(f["savings_usd"] is None for f in out["findings"] if f["pillar"] != "cost")


def test_every_rule_in_spec_has_a_case():
    ids = {r.id for r in hygiene.rules(hygiene.DEFAULT_REQUIRED_TAGS)}
    new = {i for i in ids if i.split("-")[0] in ("SEC", "COST", "REL")}
    assert new == {c[0] for c in CASES}


def test_env_and_app_tag_keys_can_be_set():
    snap = E.snapshot()
    for r in snap["resources"]:  # same estate, tagged with other keys
        r["tags"] = {{"env": "environment", "app": "service"}.get(k, k): v for k, v in r["tags"].items()}
    default = hygiene.run(E.snapshot(), E.NODES, {}, today=E.TODAY)["findings"]
    renamed = hygiene.run(snap, E.NODES, {}, today=E.TODAY, env_tag="environment", app_tag="service")["findings"]

    def rel(found):
        return sorted((f["check_id"], f["severity"], f["title"]) for f in found if f["pillar"] == "reliability")
    assert rel(renamed) == rel(default) and any(c == "REL-AZ-001" and "App " in t for c, _, t in rel(renamed))


def _judged(out, bp):
    c = out["coverage"].get(bp) or {"passed": 0, "failed": 0}
    return c["passed"] + c["failed"]


def test_RUL_5_not_applicable_is_not_counted_as_clear():
    base = run()
    snap = E.snapshot()
    stopped = E.instance("i-stopped", "eu-west-1a", {"env": "prod"}, tokens="optional")
    stopped["config"]["State"] = {"Name": "stopped"}
    snap["resources"].append(stopped)
    out = run(snap)
    # IMDSv1 rule: a stopped instance is neither a hit nor a pass.
    assert a("instance", "i-stopped") not in hits(out, "SEC-EC2-001")
    assert _judged(out, "SEC06-BP02") == _judged(base, "SEC06-BP02")
    # Settings rules judge only their own setting, and only in a Region with workloads.
    unrelated = E.snapshot()
    unrelated["resources"] = [r for r in unrelated["resources"] if r["type"] in ("setting", "vpc", "subnet")]
    assert _judged(run(unrelated, nodes={}), "SEC08-BP02") == 0  # no instances or volumes: EBS default not judged
