"""A small made-up snapshot, built by hand (no moto), for integration and rule tests.

Account 123456789012 and every name here are made up. Fixture files in fixtures/ refer to them.
"""

from __future__ import annotations

from scamallscope.model import Snapshot, make_resource, new_snapshot

ACCOUNT = "123456789012"
R = "eu-west-1"


def iarn(iid: str, region: str = R) -> str:
    return f"arn:aws:ec2:{region}:{ACCOUNT}:instance/{iid}"


def instance(iid: str, name: str, state: str = "running", dns: str = "", **tags: str):
    return make_resource(iarn(iid), ACCOUNT, R, "ec2", "instance", iid, {"Name": name, **tags},
                         {"InstanceId": iid, "State": {"Name": state}, "PrivateDnsName": dns,
                          "InstanceType": "t3.micro"})


def snapshot() -> Snapshot:
    s = new_snapshot(ACCOUNT, "aws", "2026-11-04T06:00:00+00:00", [R, "global"])
    s["resources"] = [
        instance("i-0web1", "prod-web-1", dns="ip-10-10-1-5.eu-west-1.compute.internal", owner="web", env="prod",
                 **{"scamallscope:repo": "example-org/web", "scamallscope:environment": "production"}),
        instance("i-0app1", "prod-app-1", owner="web", env="prod", **{"scamallscope:repo": "example-org/api"}),
        instance("i-0db1", "prod-db-1", owner="data"),                       # missing env tag
        instance("i-0old1", "old-batch", state="stopped", owner="data", env="prod"),
        instance("i-0dup1", "twin", owner="x", env="dev"),
        instance("i-0dup2", "twin", owner="x", env="dev"),                    # same Name: ambiguous
        make_resource(f"arn:aws:s3:::demo-backups", ACCOUNT, "global", "s3", "bucket", "demo-backups",
                      {"owner": "data", "env": "prod"},
                      {"Name": "demo-backups", "Versioning": "Suspended",
                       "Encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
                       "DetailErrors": {}}, name="demo-backups"),
        make_resource(f"arn:aws:lambda:{R}:{ACCOUNT}:function:old-fn", ACCOUNT, R, "lambda", "function", "old-fn",
                      {"owner": "web", "env": "prod"}, {"Runtime": "python3.9"}, name="old-fn"),
        make_resource(f"arn:aws:lambda:{R}:{ACCOUNT}:function:new-fn", ACCOUNT, R, "lambda", "function", "new-fn",
                      {"owner": "web", "env": "prod"}, {"Runtime": "python3.12"}, name="new-fn"),
        make_resource(f"arn:aws:iam::{ACCOUNT}:user/ci-deployer", ACCOUNT, "global", "iam", "user", "ci-deployer",
                      {}, {"UserName": "ci-deployer"}, name="ci-deployer"),
    ]
    s["units"] = []
    return s
