"""Account controls: CloudTrail, IAM credential report, GuardDuty, AWS Backup, SSM, ACM (spec 10).

Read-only: cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus, iam:GenerateCredentialReport,
iam:GetCredentialReport, guardduty:ListDetectors, guardduty:GetDetector,
backup:ListProtectedResources, ssm:DescribeInstanceInformation, acm:ListCertificates,
acm:DescribeCertificate. GenerateCredentialReport makes a report; it changes no IAM setting.
"""

from __future__ import annotations

import csv
import io
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from ..model import GLOBAL, Resource, make_resource, make_setting, setting_arn, tags_to_dict
from .base import Context, Result
from .base import items as _items

REPORT_COLUMNS = (
    "user", "arn", "password_enabled", "mfa_active",
    "access_key_1_active", "access_key_1_last_rotated", "access_key_1_last_used_date",
    "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date",
)
REPORT_TRIES, REPORT_WAIT_S = 10, 2.0


def collect_trails(client_for: Callable[[str], Any], regions: list[str], partition: str, account_id: str) -> Result:
    """Trails listed from every collected Region (a single-Region trail is visible only in its home
    Region), one per trail ARN, with status read in each trail's home Region."""
    trails: dict[str, dict[str, Any]] = {}
    for region in regions:
        for t in client_for(region).describe_trails(includeShadowTrails=True).get("trailList", []):
            trails.setdefault(t["TrailARN"], {**t, "HomeRegion": t.get("HomeRegion") or region})
    resources: list[Resource] = []
    for arn, t in sorted(trails.items()):
        status = client_for(t["HomeRegion"]).get_trail_status(Name=arn)
        config = {k: t.get(k) for k in ("Name", "TrailARN", "HomeRegion", "IsMultiRegionTrail",
                                         "IsOrganizationTrail", "LogFileValidationEnabled", "KmsKeyId")}
        config["IsLogging"] = bool(status.get("IsLogging"))
        resources.append(make_resource(arn, account_id, GLOBAL, "cloudtrail", "trail", t["Name"],
                                       {}, config, name=t["Name"]))
    return resources, []


def parse_credential_report(content: bytes | str) -> list[dict[str, str]]:
    text = content.decode("utf-8") if isinstance(content, bytes) else content
    return [{k: row.get(k, "") for k in REPORT_COLUMNS} for row in csv.DictReader(io.StringIO(text))]


def collect_credential_report(iam: Any, partition: str, account_id: str,
                              sleep: Callable[[float], None] | None = None) -> Result:
    for _ in range(REPORT_TRIES):
        if iam.generate_credential_report().get("State") == "COMPLETE":
            break
        (sleep or time.sleep)(REPORT_WAIT_S)
    try:
        content = iam.get_credential_report()["Content"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("ReportInProgress", "ReportNotPresent"):
            raise RuntimeError("credential report not ready after waiting") from exc
        raise
    arn = setting_arn(partition, "iam", "", account_id, "credential-report")  # IAM ARNs have no Region
    return [make_resource(arn, account_id, GLOBAL, "iam", "credential-report", "credential-report", {},
                          {"Rows": parse_credential_report(content)}, name="IAM credential report")], []


def collect_guardduty(client: Any, ctx: Context) -> Result:
    detectors = [{"Id": d, "Status": client.get_detector(DetectorId=d).get("Status")}
                 for d in _items(client, "list_detectors", "DetectorIds")]
    return [make_setting(ctx["partition"], "guardduty", ctx["region"], ctx["account_id"], "guardduty",
                         {"Detectors": detectors})], []


def collect_backup_protected(client: Any, ctx: Context) -> Result:
    items = [{"ResourceArn": r.get("ResourceArn"), "ResourceType": r.get("ResourceType"),
              "LastBackupTime": r.get("LastBackupTime")}
             for r in _items(client, "list_protected_resources", "Results")]
    return [make_setting(ctx["partition"], "backup", ctx["region"], ctx["account_id"], "backup-protected",
                         {"Resources": items})], []


def collect_ssm_managed(client: Any, ctx: Context) -> Result:
    items = [{"InstanceId": i.get("InstanceId"), "PingStatus": i.get("PingStatus")}
             for i in _items(client, "describe_instance_information", "InstanceInformationList")]
    return [make_setting(ctx["partition"], "ssm", ctx["region"], ctx["account_id"], "ssm-managed",
                         {"Instances": items})], []


def collect_certificates(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    for summary in _items(client, "list_certificates", "CertificateSummaryList"):
        c = client.describe_certificate(CertificateArn=summary["CertificateArn"])["Certificate"]
        config = {k: c.get(k) for k in ("DomainName", "Type", "Status", "NotAfter", "NotBefore",
                                         "InUseBy", "RenewalEligibility", "KeyAlgorithm")}
        resources.append(make_resource(c["CertificateArn"], ctx["account_id"], ctx["region"], "acm", "certificate",
                                       c["CertificateArn"].rsplit("/", 1)[-1], tags_to_dict(None), config,
                                       name=c.get("DomainName")))
    return resources, []


# Per Region: (service, resource type, boto3 client name, collector).
REGIONAL: list[tuple[str, str, str, Callable[[Any, Context], Result]]] = [
    ("acm", "certificate", "acm", collect_certificates),
    ("guardduty", "setting", "guardduty", collect_guardduty),
    ("backup", "setting", "backup", collect_backup_protected),
    ("ssm", "setting", "ssm", collect_ssm_managed),
]
