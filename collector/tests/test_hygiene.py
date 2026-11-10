from scamallscope import hygiene

import estate

WEB, APP, DB, OLD = (estate.iarn(i) for i in ("i-0web1", "i-0app1", "i-0db1", "i-0old1"))


def run(nodes=None, sources=None, tags=hygiene.DEFAULT_REQUIRED_TAGS, snap=None):
    return hygiene.run(snap or estate.snapshot(), nodes or {}, sources or {}, tags)


def hits(out, rule, arn=None):
    return [f for f in out["findings"] if f["check_id"] == rule and (arn is None or f["resource"] == arn)]


def test_HYG_1_missing_tag_named():
    f = hits(run(), "HYG-TAG-001", DB)
    assert len(f) == 1 and "env" in f[0]["detail"] and f[0]["best_practices"] == ["COST03-BP02"]


def test_HYG_2_custom_required_tags():
    out = run(tags=("team",))
    assert hits(out, "HYG-TAG-001", WEB) and "team" in hits(out, "HYG-TAG-001", WEB)[0]["detail"]


def test_HYG_3_stopped_instance():
    assert hits(run(), "HYG-EC2-001", OLD) and not hits(run(), "HYG-EC2-001", WEB)


def test_HYG_4_idle_instance():
    out = run(sources={"cloudwatch": {APP: {"cpu_avg": 2.0, "cpu_max": 9.0, "days": 14, "alarms": 0}}})
    assert hits(out, "HYG-EC2-002", APP)[0]["severity"] == "medium"


def test_HYG_5_spiky_instance_not_idle():
    out = run(sources={"cloudwatch": {APP: {"cpu_avg": 2.0, "cpu_max": 60.0, "days": 14, "alarms": 1}}})
    assert not hits(out, "HYG-EC2-002")


def test_HYG_6_rule_needs_its_source():
    out = run()
    assert not hits(out, "HYG-EC2-002") and not hits(out, "HYG-MON-002")
    assert "COST06-BP02" not in out["coverage"] and "REL06-BP03" not in out["coverage"]


def test_HYG_7_deprecated_runtime():
    out = run()
    assert [f["resource_name"] for f in hits(out, "HYG-LAM-001")] == ["old-fn"]


def test_HYG_8_running_instance_without_agent():
    out = run(sources={"wazuh": {WEB: {}}})
    names = {f["resource"] for f in hits(out, "HYG-AGT-001")}
    assert APP in names and DB in names and WEB not in names and OLD not in names


def test_HYG_9_prometheus_down_is_high():
    out = run(sources={"prometheus": {APP: {"prom_up": 0}, WEB: {"prom_up": 1}}})
    assert hits(out, "HYG-MON-001", APP)[0]["severity"] == "high"
    assert hits(out, "HYG-MON-001", DB)[0]["severity"] == "medium"
    assert not hits(out, "HYG-MON-001", WEB)


def test_HYG_10_bucket_versioning():
    assert hits(run(), "HYG-S3-001")[0]["resource_name"] == "demo-backups"
    assert not hits(run(), "HYG-S3-002")


def test_unknown_bucket_detail_is_not_a_finding():
    snap = estate.snapshot()
    bucket = next(r for r in snap["resources"] if r["type"] == "bucket")
    bucket["config"]["DetailErrors"] = {"Versioning": "AccessDenied: no"}
    assert not hits(run(snap=snap), "HYG-S3-001")


def test_HYG_11_exposure_and_admin_become_findings():
    nodes = {WEB: {"exposure": "exposed", "exposure_reason": "public IP, open SG",
                   "exposed_ports": [{"protocol": "tcp", "from_port": 22}]},
             "arn:aws:iam::123456789012:user/ci-deployer": {"admin": True, "admin_reason": "AdministratorAccess"}}
    out = run(nodes=nodes)
    assert hits(out, "EXP-001", WEB)[0]["severity"] == "high" and "tcp/22" in hits(out, "EXP-001", WEB)[0]["detail"]
    assert hits(out, "IAM-ADMIN-001")[0]["severity"] == "medium"


def test_HYG_12_service_linked_role_not_flagged():
    snap = estate.snapshot()
    from scamallscope.model import make_resource
    role = make_resource("arn:aws:iam::123456789012:role/aws-service-role/x", "123456789012", "global", "iam",
                         "role", "x", {}, {"Path": "/aws-service-role/x/"})
    snap["resources"].append(role)
    out = run(snap=snap, nodes={role["arn"]: {"admin": True}})
    assert not hits(out, "IAM-ADMIN-001")


def test_HYG_13_coverage_from_rules_that_ran():
    out = run(sources={"ansible": {WEB: {}}})
    assert out["coverage"]["REL08-BP05"]["failed"] >= 1
    assert out["coverage"]["COST03-BP02"]["passed"] >= 1
