import os

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch):
    # Never touch a real account from tests.
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_CONFIG_FILE", os.devnull)
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", os.devnull)


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.Session(region_name="eu-west-1")


@pytest.fixture(autouse=True)
def no_unmocked_services(monkeypatch):
    """moto 5.2.5 does not implement backup:ListProtectedResources or ssm:DescribeInstanceInformation.
    Under moto those two units return empty settings; test_inventory_b tests the real functions with Stubber."""
    from scamallscope.collectors import account
    from scamallscope.model import make_setting

    def empty(service, setting_id, key):
        return lambda client, ctx: ([make_setting(ctx["partition"], service, ctx["region"], ctx["account_id"],
                                                  setting_id, {key: []})], [])

    fake = {"backup": empty("backup", "backup-protected", "Resources"),
            "ssm": empty("ssm", "ssm-managed", "Instances")}
    monkeypatch.setattr(account, "REPORT_WAIT_S", 0)  # moto says STARTED on the first call
    monkeypatch.setattr(account, "REGIONAL", [(s, t, c, fake.get(s, fn)) for s, t, c, fn in account.REGIONAL])
