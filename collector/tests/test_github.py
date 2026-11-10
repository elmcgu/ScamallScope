from scamallscope import httpjson
from scamallscope.integrations import github

import estate
from fakehttp import FakeUrlopen
from helpers import fixture

WEB, APP = estate.iarn("i-0web1"), estate.iarn("i-0app1")


def test_GHB_1_newest_production_deployment():
    out = github.parse(fixture("github.json"), estate.snapshot())
    d = out["resources"][WEB]
    assert d["state"] == "success" and d["sha"] == "9f8e7d6" and d["environment"] == "production"
    assert d["url"] == "https://github.com/example-org/web/deployments"


def test_GHB_2_failed_deployment_is_high():
    out = github.parse(fixture("github.json"), estate.snapshot())
    f = next(f for f in out["findings"] if f["resource"] == APP)
    assert f["check_id"] == "github-deploy-failed" and f["severity"] == "high"
    assert f["best_practices"] == ["REL08-BP02"]


def test_GHB_3_environment_tag():
    snap = estate.snapshot()
    snap["resources"][0]["tags"]["scamallscope:environment"] = "staging"
    d = github.parse(fixture("github.json"), snap)["resources"][WEB]
    assert d["environment"] == "staging" and d["sha"] == "aaaabbb"


def test_GHB_4_tagged_repo_without_deployments():
    raw = fixture("github.json")
    raw["repos"]["example-org/api"]["deployments"] = []
    out = github.parse(raw, estate.snapshot())
    assert any(f["check_id"] == "github-no-deployment" and f["resource"] == APP for f in out["findings"])


def test_GHB_5_repos_from_tags():
    snap = estate.snapshot()
    snap["resources"][2]["tags"]["scamallscope:repo"] = "not a repo"
    assert github.repos_from_snapshot(snap) == ["example-org/api", "example-org/web"]


def test_GHB_6_fetch(monkeypatch):
    deps = [{"id": 7, "sha": "abc", "environment": "production", "created_at": "2026-11-01T00:00:00Z"},
            {"id": 6, "sha": "def", "environment": "production", "created_at": "2026-10-01T00:00:00Z"}]
    fake = FakeUrlopen([("/deployments/7/statuses", 200, [{"state": "success"}]),
                        ("/repos/o/r/deployments", 200, deps)])
    monkeypatch.setattr(httpjson, "urlopen", fake)
    raw = github.fetch(["o/r"], "ghp_made_up")
    assert raw["repos"]["o/r"]["statuses"] == {"7": [{"state": "success"}]}
    assert len(fake.requests) == 2
    assert fake.requests[0].get_header("Authorization") == "Bearer ghp_made_up"
    assert fake.requests[0].get_header("X-github-api-version") == "2022-11-28"
