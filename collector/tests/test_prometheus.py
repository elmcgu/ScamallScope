import pytest

from scamallscope import hosts, httpjson
from scamallscope.integrations import prometheus

import estate
from fakehttp import FakeUrlopen
from helpers import fixture

WEB, APP = estate.iarn("i-0web1"), estate.iarn("i-0app1")


def parse(raw=None):
    return prometheus.parse(raw or fixture("prometheus.json"), hosts.build(estate.snapshot()))


def test_PRM_1_instance_id_label():
    assert parse()["resources"][WEB] == {"prom_up": 1}


def test_PRM_2_instance_label_host_name():
    assert APP in parse()["resources"]


def test_PRM_3_lowest_up_wins():
    assert parse()["resources"][APP]["prom_up"] == 0
    assert parse()["unmatched"] == ["gone-host:9100"]


def test_PRM_4_error_response():
    with pytest.raises(ValueError, match="bad_data"):
        parse({"response": {"status": "error", "errorType": "bad_data", "error": "bad_data: parse error"}})


def test_unmatched_ip_is_redacted():
    raw = fixture("prometheus.json")
    raw["response"]["data"]["result"] = [{"metric": {"instance": "10.1.2.3:9100"}, "value": [0, "1"]}]
    assert parse(raw)["unmatched"] == ["<ip>:9100"]


def test_fetch_sends_query_and_token(monkeypatch):
    fake = FakeUrlopen([("/api/v1/query", 200, {"status": "success", "data": {"resultType": "vector", "result": []}})])
    monkeypatch.setattr(httpjson, "urlopen", fake)
    raw = prometheus.fetch("https://prom.example", token="t0k")  # pragma: allowlist secret
    assert "query=up" in fake.requests[0].full_url
    assert fake.requests[0].get_header("Authorization") == "Bearer t0k"
    assert raw["response"]["status"] == "success"


def test_http_url_refused():
    with pytest.raises(ValueError):
        prometheus.fetch("http://prom.example")
