import json
import re
import shutil

import pytest

from scamallscope import enrich
from scamallscope.cli import main

import estate
from helpers import FIXTURES

WEB, APP = estate.iarn("i-0web1"), estate.iarn("i-0app1")


@pytest.fixture
def folder(tmp_path):
    d = tmp_path / "integrations"
    shutil.copytree(FIXTURES, d)
    return d


def nodes(g):
    return {e["data"]["id"]: e["data"] for e in g["elements"] if e["group"] == "nodes"}


def test_ENR_1_no_integrations():
    g = enrich.build(estate.snapshot(), {})
    assert g["schema_version"] == 2
    assert all(not m["loaded"] for m in g["meta"]["integrations"].values())
    assert {f["source"] for f in g["findings"]} == {"inventory"}
    assert g["cost"] is None


def test_ENR_2_all_sources(folder):
    g = enrich.build(estate.snapshot(), enrich.load_raw(folder))
    assert all(m["loaded"] for m in g["meta"]["integrations"].values()), g["meta"]["integrations"]
    ids = [f["id"] for f in g["findings"]]
    assert len(ids) == len(set(ids))
    assert {"prowler", "wazuh", "github", "ansible", "cost", "costhub", "hygiene", "inventory"} <= {f["source"] for f in g["findings"]}
    assert g["meta"]["integrations"]["costhub"]["enabled"] is True
    assert g["meta"]["integrations"]["costhub"]["compute_optimizer"] == "Active"


def test_ENR_3_broken_file_does_not_stop_the_rest(folder):
    (folder / "wazuh.json").write_text('{"agents": []}')
    g = enrich.build(estate.snapshot(), enrich.load_raw(folder))
    assert g["meta"]["integrations"]["wazuh"]["loaded"] is False
    assert "error" in g["meta"]["integrations"]["wazuh"]
    assert g["meta"]["integrations"]["github"]["loaded"] is True
    assert enrich.failed_sources(g) == ["wazuh"]


def test_ENR_4_node_has_data_from_every_source(folder):
    n = nodes(enrich.build(estate.snapshot(), enrich.load_raw(folder)))
    for key in ("wazuh", "deploy", "config_run", "metrics", "cost"):
        assert key in n[WEB], key
    assert n[WEB]["metrics"]["prom_up"] == 1 and n[WEB]["metrics"]["alarms"] == 1


def test_ENR_5_finding_counts(folder):
    g = enrich.build(estate.snapshot(), enrich.load_raw(folder))
    mine = [f for f in g["findings"] if f["resource"] == WEB and not f["duplicate_of"]]
    assert sum(nodes(g)[WEB]["finding_counts"].values()) == len(mine) > 0


def test_ENR_6_no_ip_addresses(folder):
    text = json.dumps(enrich.build(estate.snapshot(), enrich.load_raw(folder)))
    assert "PrivateIpAddress" not in text
    assert not re.search(r'"\d{1,3}(\.\d{1,3}){3}(:\d+)?"', text)


def test_ENR_7_idle_cost(folder):
    raw = enrich.load_raw(folder)
    raw.pop("costhub")  # with the hub loaded, HYG-EC2-002 does not run (RUL-3)
    g = enrich.build(estate.snapshot(), raw)
    idle = {f["resource"] for f in g["findings"] if f["check_id"] == "HYG-EC2-002"}
    assert idle == {APP}
    assert g["cost"]["idle_monthly_usd"] == nodes(g)[APP]["cost"]["monthly_usd"] == 15.0
    assert g["cost"]["top_resources"][0]["arn"] == WEB


def test_posture_has_all_three_pillars(folder):
    g = enrich.build(estate.snapshot(), enrich.load_raw(folder))
    assert set(g["posture"]) == {"security", "reliability", "cost"}
    sec = {r["id"]: r for r in g["posture"]["security"]["best_practices"]}
    assert sec["SEC06-BP01"]["status"] == "issues"
    assert "wazuh" in sec["SEC06-BP01"]["checked_by"]


def test_cli_enrich(tmp_path, folder, capsys):
    snap = tmp_path / "x.snapshot.json"
    snap.write_text(json.dumps(estate.snapshot()))
    assert main(["enrich", str(snap), "--integrations", str(folder)]) == 0
    out = tmp_path / "x.graph.json"
    assert json.loads(out.read_text())["schema_version"] == 2
    assert oct(out.stat().st_mode & 0o777) == "0o600"
    assert "wazuh       loaded" in capsys.readouterr().out


def test_findings_use_the_map_label(folder):
    g = enrich.build(estate.snapshot(), enrich.load_raw(folder))
    imds = next(f for f in g["findings"] if f["check_id"] == "ec2_instance_imdsv2_enabled")
    assert imds["resource_name"] == "prod-web-1"


def test_RUL_3_hub_replaces_cpu_idle_rule(folder):
    g = enrich.build(estate.snapshot(), enrich.load_raw(folder))
    assert not [f for f in g["findings"] if f["check_id"] == "HYG-EC2-002"]
    assert [f for f in g["findings"] if f["check_id"] == "COST-HUB-Rightsize"][0]["resource"] == APP


def test_hub_not_enabled_keeps_cpu_idle_rule(folder):
    raw = enrich.load_raw(folder)
    hub = json.loads(raw["costhub"].read_text())
    hub.update(enabled=False, recommendations=[])
    raw["costhub"].write_text(json.dumps(hub))
    g = enrich.build(estate.snapshot(), raw)
    assert [f["resource"] for f in g["findings"] if f["check_id"] == "HYG-EC2-002"] == [APP]
    assert g["meta"]["integrations"]["costhub"]["enabled"] is False
