"""S3 buckets (global list, details per bucket).

Read-only calls: s3:ListAllMyBuckets, s3:GetBucketLocation, s3:GetBucketPolicyStatus,
s3:GetBucketPublicAccessBlock, s3:GetBucketAcl, s3:GetEncryptionConfiguration,
s3:GetBucketVersioning, s3:GetBucketTagging, s3:GetAccountPublicAccessBlock.

Bucket policies themselves are not read: AWS's own GetBucketPolicyStatus says whether the
policy makes the bucket public.
"""

from __future__ import annotations

from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

from ..model import GLOBAL, Resource, make_resource, tags_to_dict
from .base import Result

# Error codes that mean "not configured", not "failed".
NOT_CONFIGURED = {
    "NoSuchBucketPolicy", "NoSuchPublicAccessBlockConfiguration", "NoSuchTagSet",
    "ServerSideEncryptionConfigurationNotFoundError",
}


def _detail(errors: dict[str, str], name: str, call: Callable[[], Any]) -> Any:
    """Run one detail call. Not configured -> None. Failed -> None, and the error is recorded."""
    try:
        return call()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        if code not in NOT_CONFIGURED:
            errors[name] = f"{code}: {exc.response.get('Error', {}).get('Message', '')}".strip()
        return None
    except BotoCoreError as exc:
        errors[name] = f"{type(exc).__name__}: {exc}"
        return None


def account_public_access_block(s3control: Any, account_id: str) -> tuple[dict[str, Any] | None, str | None]:
    errors: dict[str, str] = {}
    block = _detail(errors, "AccountPublicAccessBlock",
                    lambda: s3control.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"])
    return block, errors.get("AccountPublicAccessBlock")


def collect_buckets(s3: Any, s3control: Any, partition: str, account_id: str) -> Result:
    account_block, account_error = account_public_access_block(s3control, account_id)
    resources: list[Resource] = []
    for b in s3.list_buckets().get("Buckets", []):
        name = b["Name"]
        errors: dict[str, str] = {}
        if account_error:
            errors["AccountPublicAccessBlock"] = account_error
        location = _detail(errors, "Location", lambda: s3.get_bucket_location(Bucket=name).get("LocationConstraint"))
        config = {
            "Name": name,
            "CreationDate": b.get("CreationDate"),
            "Region": (location or "us-east-1") if "Location" not in errors else None,
            "PolicyStatus": _detail(errors, "PolicyStatus", lambda: s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]),
            "PublicAccessBlock": _detail(errors, "PublicAccessBlock",
                                         lambda: s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]),
            "AccountPublicAccessBlock": account_block,
            "Grants": _detail(errors, "Acl", lambda: s3.get_bucket_acl(Bucket=name)["Grants"]),
            "Encryption": _detail(errors, "Encryption",
                                  lambda: s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]),
            "Versioning": _detail(errors, "Versioning", lambda: s3.get_bucket_versioning(Bucket=name).get("Status")),
            "DetailErrors": errors,
        }
        tag_set = _detail(errors, "Tagging", lambda: s3.get_bucket_tagging(Bucket=name)["TagSet"])
        resources.append(make_resource(
            f"arn:{partition}:s3:::{name}", account_id, GLOBAL, "s3", "bucket", name,
            tags_to_dict(tag_set), config, name=name,
        ))
    return resources, []
