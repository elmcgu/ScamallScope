"""Spec 14: workloads for the Availability view."""

from scamallscope import availability, rules

import estate_b as E
from estate_b import ec2arn as a


def rows(snap=None, sources=None):
    snap = snap or E.snapshot()
    sources = sources if sources is not None else {}
    found = rules.run(snap, E.NODES, sources, today=E.TODAY)["findings"]
    for f in found:
        f["duplicate_of"] = None
    return {r["name"]: r for r in availability.workloads(snap, E.NODES, sources, found, E.TODAY)}


def test_AVL_1_app_in_two_azs_is_one_workload():
    r = rows()
    api = r["app api"]
    assert api["kind"] == "app" and api["azs"] == ["eu-west-1a", "eu-west-1b"] and api["prod"] is False
    assert set(api["members"]) == {a("instance", "i-api1"), a("instance", "i-api2")}
    web = r["app web"]
    assert web["azs"] == ["eu-west-1a"] and web["findings"] >= 1  # REL-AZ-001 on the group counts
    assert web["healing"] == "asg"  # i-web1 is in the web ASG


def test_AVL_2_standalone_instance():
    bastion = rows()["i-bastion"]
    assert bastion["kind"] == "instance" and bastion["healing"] == "none"  # AutoRecovery disabled
    assert bastion["backup"] == "missing"  # vol-bastion has no backup
    assert bastion["monitoring"] == "unknown"  # no CloudWatch or Prometheus loaded
    snap = E.snapshot()
    inst = next(x for x in snap["resources"] if x["id"] == "i-bastion")
    inst["config"]["MaintenanceOptions"]["AutoRecovery"] = "default"
    assert rows(snap)["i-bastion"]["healing"] == "auto-recovery"


def test_AVL_3_databases():
    r = rows()
    assert r["orders"]["kind"] == "database" and r["orders"]["healing"] == "none" and r["orders"]["backup"] == "missing"
    assert r["aurora-1"]["healing"] == "multi-az" and r["aurora-1"]["backup"] == "ok"


def test_backup_ok_with_recent_snapshot_and_monitoring_with_sources():
    api1 = a("instance", "i-api1")
    r = rows(sources={"cloudwatch": {api1: {"alarms": 1}, a("instance", "i-api2"): {"alarms": 0}}})
    assert r["app api"]["backup"] == "ok"  # vol-api1 has a snapshot from yesterday
    assert r["app api"]["monitoring"] == "none"  # one of the two has no alarm


def test_failed_backup_unit_is_unknown():
    snap = E.snapshot()
    for u in snap["units"]:
        if u["service"] == "backup":
            u["status"] = "error"
    assert rows(snap)["i-bastion"]["backup"] == "unknown"


def test_sorted_by_findings_then_prod():
    counts = [r["findings"] for r in rows().values()]
    assert counts == sorted(counts, reverse=True) and counts[0] > 0
