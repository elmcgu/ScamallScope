import pytest

from scamallscope import hosts
from scamallscope.integrations import ansible

import estate
from helpers import fixture

WEB, APP, DB = estate.iarn("i-0web1"), estate.iarn("i-0app1"), estate.iarn("i-0db1")


def parse(mode: ansible.Mode = "check"):
    return ansible.parse(fixture("ansible.json"), hosts.build(estate.snapshot()), mode)


def test_ANS_1_counts_per_host():
    out = parse()
    assert set(out["resources"]) == {WEB, APP, DB}
    assert out["resources"][WEB]["ok"] == 14 and out["resources"][WEB]["ran_at"].startswith("2026-11-04")


def test_ANS_2_drift_in_check_mode():
    assert any(f["check_id"] == "ansible-drift" and f["resource"] == APP for f in parse()["findings"])


def test_ANS_3_changes_expected_in_apply_mode():
    assert not any(f["check_id"] == "ansible-drift" for f in parse("apply")["findings"])


def test_ANS_4_unreachable_is_failed():
    f = next(f for f in parse()["findings"] if f["resource"] == DB)
    assert f["check_id"] == "ansible-host-failed" and f["best_practices"] == ["REL08-BP05"]


def test_ANS_5_unknown_host():
    assert parse()["unmatched"] == ["retired-host"]


def test_ANS_6_wrong_shape():
    with pytest.raises(ValueError, match="stats"):
        ansible.parse({"plays": []}, hosts.build(estate.snapshot()))
