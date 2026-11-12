"""Spec 15: scamallscope run (collect, fetches that have their inputs, enrich) into one folder."""

import json
import stat

import pytest
from test_snapshot import REGION, build_estate

from scamallscope import cli
from scamallscope.cli import main

from helpers import fixture


@pytest.fixture
def aws(session, monkeypatch):
    build_estate(session)
    monkeypatch.setattr("scamallscope.cli.boto3.Session", lambda **kw: session)
    for name in ("WAZUH_API_USER", "WAZUH_API_PASSWORD", "WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    fetched: list[str] = []

    def fake(source):
        def fetch(*a, **k):
            fetched.append(source)
            return fixture(f"{source}.json")
        return fetch
    for source in ("cloudwatch", "cost", "costhub"):
        monkeypatch.setattr(getattr(cli, source), "fetch", fake(source))
    return fetched


def test_RUN_1_one_folder_with_snapshot_raw_files_and_graph(aws, tmp_path):
    out = tmp_path / "run"
    assert main(["run", "--region", REGION, "--output-dir", str(out)]) == 0
    assert aws == ["cloudwatch", "cost", "costhub"]
    files = {p.relative_to(out).as_posix() for p in out.rglob("*.json")}
    assert files == {"snapshot.json", "graph.json", "integrations/cloudwatch.json", "integrations/cost.json",
                     "integrations/costhub.json"}
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in out.rglob("*.json"))
    meta = json.loads((out / "graph.json").read_text())["meta"]["integrations"]
    assert meta["costhub"]["loaded"] and meta["cost"]["loaded"] and not meta["wazuh"].get("loaded")


def test_RUN_2_fetches_without_inputs_are_left_out(aws, tmp_path, capsys):
    assert main(["run", "--region", REGION, "--output-dir", str(tmp_path), "--wazuh-url", "https://w.example:55000",
                 "--wazuh-indexer-url", "https://i.example:9200"]) == 0
    text = capsys.readouterr().out
    assert "wazuh       not fetched: WAZUH_API_USER" in text  # URLs given, credentials not set
    assert "github      not fetched: no resources tagged scamallscope:repo" in text
    assert "prometheus  not fetched: no --prometheus-url" in text


def test_RUN_3_a_failed_fetch_makes_the_run_partial(aws, tmp_path, monkeypatch):
    def boom(*a, **k):
        raise ValueError("made-up failure")
    monkeypatch.setattr(cli.cost, "fetch", boom)
    assert main(["run", "--region", REGION, "--output-dir", str(tmp_path)]) == 2
    assert not (tmp_path / "integrations" / "cost.json").exists()
    assert (tmp_path / "integrations" / "costhub.json").exists() and (tmp_path / "graph.json").exists()


def test_RUN_4_skip_and_add(aws, tmp_path):
    prowler = tmp_path / "prowler.ocsf.json"
    prowler.write_text(json.dumps(fixture("prowler.ocsf.json")))
    out = tmp_path / "run"
    assert main(["run", "--region", REGION, "--output-dir", str(out), "--skip", "cost,costhub",
                 "--add", str(prowler)]) == 0
    assert aws == ["cloudwatch"]
    assert (out / "integrations" / "prowler.ocsf.json").exists()
    assert json.loads((out / "graph.json").read_text())["meta"]["integrations"]["prowler"]["loaded"]


def test_RUN_5_unknown_skip_is_refused(aws, tmp_path):
    assert main(["run", "--region", REGION, "--output-dir", str(tmp_path), "--skip", "nope"]) == 1
    assert not any(tmp_path.iterdir())
