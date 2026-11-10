import pytest

from scamallscope import hosts, httpjson
from scamallscope.integrations import wazuh

import estate
from fakehttp import FakeUrlopen
from helpers import fixture


@pytest.fixture
def out():
    return wazuh.parse(fixture("wazuh.json"), hosts.build(estate.snapshot()))


WEB, APP = estate.iarn("i-0web1"), estate.iarn("i-0app1")


def test_WAZ_1_agents_parsed_manager_skipped(out):
    assert set(out["resources"]) == {WEB, APP}
    assert out["resources"][WEB]["os_name"] == "Ubuntu"
    assert out["resources"][WEB]["os_version"] == "22.04.4 LTS"
    assert "wazuh-manager" not in out["unmatched"]


def test_WAZ_2_agent_named_by_instance_id(out):
    assert out["resources"][APP]["agent_id"] == "003"


def test_WAZ_3_ambiguous_name_unmatched(out):
    assert "twin" in out["unmatched"] and "ip-10-10-2-7" in out["unmatched"]


def test_WAZ_4_vulnerability_counts_and_severity(out):
    assert out["resources"][WEB]["vulns"] == {"critical": 1, "high": 2, "medium": 0, "low": 0}
    f = next(f for f in out["findings"] if f["resource"] == WEB)
    assert f["severity"] == "critical" and f["best_practices"] == ["SEC06-BP01"]
    assert "top: openssl" in f["detail"]


def test_WAZ_5_wazuh_5_field_names(out):
    assert out["resources"][APP]["vulns"] == {"critical": 0, "high": 0, "medium": 1, "low": 1}


def test_WAZ_6_disconnected_agent():
    raw = fixture("wazuh.json")
    raw["agents"]["data"]["affected_items"][1]["status"] = "disconnected"
    out = wazuh.parse(raw, hosts.build(estate.snapshot()))
    assert any(f["check_id"] == "wazuh-agent-not-active" and f["resource"] == WEB for f in out["findings"])
    assert out["coverage"]["SEC04-BP01"]["failed"] == 1


def test_WAZ_7_truncated_results_noted():
    raw = fixture("wazuh.json")
    raw["vulnerabilities"]["hits"]["total"]["value"] = 9000
    assert any("vulns_truncated" in n for n in wazuh.parse(raw, hosts.build(estate.snapshot()))["notes"])


def test_WAZ_8_top_packages_limited_and_sorted():
    vulns = [{"package": f"p{i % 7}", "version": "1", "severity": "low"} for i in range(30)]
    top = wazuh._top_packages(vulns)
    assert len(top) == 5
    assert [(t["name"], t["count"]) for t in top] == [("p0", 5), ("p1", 5), ("p2", 4), ("p3", 4), ("p4", 4)]


def test_WAZ_9_fetch_auth_and_paging(monkeypatch):
    page1 = {"data": {"affected_items": [{"id": str(i)} for i in range(500)], "total_affected_items": 501}}
    page2 = {"data": {"affected_items": [{"id": "500"}], "total_affected_items": 501}}
    fake = FakeUrlopen([("/security/user/authenticate", 200, {"data": {"token": "tok123"}}),
                        ("offset=0", 200, page1), ("offset=500", 200, page2),
                        ("_search", 200, {"hits": {"total": {"value": 0}, "hits": []}})])
    monkeypatch.setattr(httpjson, "urlopen", fake)
    raw = wazuh.fetch("https://wazuh.example:55000", "https://idx.example:9200", "reader", "s3cret-pw", "ir", "pw2")
    assert len(raw["agents"]["data"]["affected_items"]) == 501
    assert fake.requests[1].get_header("Authorization") == "Bearer tok123"
    assert fake.requests[0].get_header("Authorization").startswith("Basic ")
    body = fake.requests[3].data.decode()
    assert "vulnerability.severity" in body and "_source" in body


def test_WAZ_9_errors_do_not_leak_credentials(monkeypatch):
    fake = FakeUrlopen([("/security/user/authenticate", 401, {"title": "Unauthorized"})])
    monkeypatch.setattr(httpjson, "urlopen", fake)
    with pytest.raises(httpjson.HttpError) as err:
        wazuh.fetch("https://wazuh.example:55000", "https://idx.example:9200", "reader", "s3cret-pw", "ir", "pw2")
    assert "s3cret-pw" not in str(err.value) and "401" in str(err.value)


def test_WAZ_10_https_required():
    with pytest.raises(ValueError, match="https"):
        wazuh.fetch("https://wazuh.example:55000", "http://idx.example:9200", "u", "p", "u", "p")
