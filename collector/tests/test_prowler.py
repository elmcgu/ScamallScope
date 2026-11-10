import pytest

from scamallscope.integrations import prowler

from helpers import fixture

ACCOUNT = "123456789012"
KNOWN = {"arn:aws:s3:::demo-backups"}


def parsed(files=None):
    return prowler.parse(files or {"prowler.ocsf.json": fixture("prowler.ocsf.json")}, ACCOUNT, KNOWN)


def test_PRW_1_only_fail_becomes_a_finding():
    assert len(parsed()["findings"]) == 4


def test_PRW_2_well_architected_ids_from_compliance():
    root = next(f for f in parsed()["findings"] if f["check_id"] == "iam_root_mfa_enabled")
    assert root["best_practices"] == ["SEC01-BP02"]
    assert root["pillar"] == "security" and root["severity"] == "critical"
    rds = next(f for f in parsed()["findings"] if f["check_id"] == "rds_instance_backup_enabled")
    assert rds["pillar"] == "reliability" and rds["best_practices"] == ["REL09-BP03"]
    imds = next(f for f in parsed()["findings"] if f["check_id"] == "ec2_instance_imdsv2_enabled")
    assert imds["best_practices"] == ["SEC03-BP01", "SEC06-BP01"]


def test_PRW_3_pass_counts_as_coverage():
    cov = parsed()["coverage"]["SEC01-BP02"]
    assert cov == {"passed": 1, "failed": 1}


def test_PRW_4_known_resource_is_linked():
    s3 = next(f for f in parsed()["findings"] if f["check_id"] == "s3_bucket_object_versioning")
    assert s3["resource"] == "arn:aws:s3:::demo-backups"


def test_PRW_5_unknown_resource_kept_by_name():
    root = next(f for f in parsed()["findings"] if f["check_id"] == "iam_root_mfa_enabled")
    assert root["resource"] is None and root["resource_name"] == "<root_account>"


def test_PRW_6_other_account_skipped():
    items = fixture("prowler.ocsf.json")
    items[0]["cloud"]["account"]["uid"] = "999999999999"
    out = prowler.parse({"p.json": items}, ACCOUNT, KNOWN)
    assert len(out["findings"]) == 3
    assert out["notes"] == ["skipped_other_account: 1"]


def test_PRW_7_wrong_shape_names_the_file():
    with pytest.raises(ValueError, match="bad.json"):
        prowler.parse({"bad.json": {"not": "a list"}}, ACCOUNT, KNOWN)
    with pytest.raises(ValueError, match="bad.json"):
        prowler.parse({"bad.json": [{"no_status": 1}]}, ACCOUNT, KNOWN)


def test_PRW_8_duplicates_across_files():
    items = fixture("prowler.ocsf.json")
    assert len(prowler.parse({"a.json": items, "b.json": items}, ACCOUNT, KNOWN)["findings"]) == 4
