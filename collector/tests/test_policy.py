"""POL-1, POL-2 (spec 10): infra/collector-read-only-policy.json is the one list of AWS permissions.

Every boto3 operation named in the collectors and AWS fetchers maps to an action in the policy, and
every action in the policy is used. Operations are found by name in the source and resolved against
the botocore models of the services we call.
"""

import json
import re
from pathlib import Path

import boto3
from botocore import xform_name

COLLECTOR = Path(__file__).resolve().parents[1]
POLICY = COLLECTOR.parent / "infra" / "collector-read-only-policy.json"
SOURCES = [*sorted((COLLECTOR / "scamallscope" / "collectors").glob("*.py")), COLLECTOR / "scamallscope" / "snapshot.py",
           *[COLLECTOR / "scamallscope" / "integrations" / f"{n}.py" for n in ("cloudwatch", "cost", "costhub")]]
# boto3 client name -> IAM action prefix
SERVICES = {"ec2": "ec2", "rds": "rds", "elbv2": "elasticloadbalancing", "autoscaling": "autoscaling", "acm": "acm",
            "cloudtrail": "cloudtrail", "iam": "iam", "guardduty": "guardduty", "backup": "backup", "ssm": "ssm",
            "lambda": "lambda", "s3": "s3", "s3control": "s3", "cloudwatch": "cloudwatch", "ce": "ce",
            "cost-optimization-hub": "cost-optimization-hub", "compute-optimizer": "compute-optimizer", "sts": "sts"}
# Operations whose IAM action has another name, or whose name exists in more than one service we use.
ACTIONS = {
    "get_caller_identity": set(),  # needs no permission
    "list_buckets": {"s3:ListAllMyBuckets"},
    "get_bucket_encryption": {"s3:GetEncryptionConfiguration"},
    "get_public_access_block": {"s3:GetBucketPublicAccessBlock", "s3:GetAccountPublicAccessBlock"},  # s3 and s3control
    "describe_load_balancers": {"elasticloadbalancing:DescribeLoadBalancers"},
    "describe_tags": {"elasticloadbalancing:DescribeTags"},
    "list_tags": {"lambda:ListTags"},
}


def operations() -> dict[str, set[str]]:
    ops: dict[str, set[str]] = {}
    for client, prefix in SERVICES.items():
        for op in boto3.client(client, region_name="us-east-1").meta.service_model.operation_names:
            ops.setdefault(xform_name(op), set()).add(f"{prefix}:{op}")
    return ops


def needed() -> dict[str, set[str]]:
    ops = operations()
    words = {w for f in SOURCES for w in re.findall(r"\b[a-z][a-z0-9_]+\b", f.read_text())}
    return {w: ACTIONS.get(w, ops[w]) for w in sorted(words & set(ops))}


def policy_actions() -> set[str]:
    return {a for s in json.loads(POLICY.read_text())["Statement"] for a in s["Action"]}


def test_POL_1_every_operation_is_in_the_policy():
    ambiguous = {op: acts for op, acts in needed().items() if len(acts) > 1 and op not in ACTIONS}
    assert not ambiguous, f"add these to ACTIONS: {ambiguous}"
    missing = {op: acts for op, acts in needed().items() if not acts <= policy_actions()}
    assert not missing, f"not in {POLICY.name}: {missing}"


def test_POL_2_every_policy_action_is_used_and_read_only():
    used = set().union(*needed().values())
    assert policy_actions() - used == set(), "remove unused actions from the policy (least privilege)"
    verbs = {a.split(":")[1] for a in policy_actions()}
    assert all(re.match(r"(Describe|Get|List|GenerateCredentialReport$)", v) for v in verbs)
