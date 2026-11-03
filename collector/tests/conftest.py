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
