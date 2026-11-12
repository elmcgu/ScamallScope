"""Spec 12 security rules."""

from __future__ import annotations

from typing import Any

from ..graph import redirects_to_https
from ..model import GLOBAL, Resource
from .engine import NA, Ctx, GroupRule, Hit, Rule, hit, is_running, name_of

OPEN = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = (22, 3389)
KEY_MAX_DAYS, CERT_WARN_DAYS, CERT_URGENT_DAYS = 90, 30, 7


def _open_admin_ports(group: Resource) -> list[int]:
    found = set()
    for p in group["config"].get("IpPermissions") or []:
        sources = {x.get("CidrIp") for x in p.get("IpRanges", [])} | {x.get("CidrIpv6") for x in p.get("Ipv6Ranges", [])}
        if not sources & OPEN or p.get("IpProtocol") not in ("tcp", "-1", "6"):
            continue
        lo, hi = p.get("FromPort"), p.get("ToPort")
        for port in ADMIN_PORTS:
            if p.get("IpProtocol") == "-1" or lo is None or (lo <= port <= (hi if hi is not None else lo)):
                found.add(port)
    return sorted(found)


def _ssh_rdp_open(r, node, src, ctx):
    if not is_running(r):
        return NA
    ports = sorted({p for g in ctx.linked("uses", r["arn"]) if g in ctx.res for p in _open_admin_ports(ctx.res[g])})
    if not ports:
        return None
    sev = "critical" if node.get("exposure") == "exposed" else "high"
    return hit(sev, f"Instance {name_of(r)} allows {'/'.join(map(str, ports))} from anywhere",
                f"security group ingress from 0.0.0.0/0 or ::/0 on port {', '.join(map(str, ports))}")


def _imdsv1(r, node, src, ctx):
    if not is_running(r):
        return NA
    if (r["config"].get("MetadataOptions") or {}).get("HttpTokens") != "required":
        return hit("medium", f"Instance {name_of(r)} allows IMDSv1", "MetadataOptions.HttpTokens is not required")
    return None


def _not_ssm(r, node, src, ctx):
    if not is_running(r):
        return NA
    managed = {i.get("InstanceId") for i in (ctx.setting("ssm", "ssm-managed", r["region"]) or {}).get("Instances", [])}
    if r["id"] not in managed:
        return hit("low", f"Instance {name_of(r)} is not managed by Systems Manager", "not in DescribeInstanceInformation")
    return None


def _volume_unencrypted(r, node, src, ctx):
    if not r["config"].get("Encrypted"):
        return hit("medium", f"Volume {name_of(r)} is not encrypted", f"{r['config'].get('Size')} GB {r['config'].get('VolumeType')}")
    return None


def _ebs_default_off(r, node, src, ctx):
    if r["service"] != "ec2" or r["id"] != "ebs-encryption-by-default" or not ctx.region_has(r["region"], {"instance", "volume"}):
        return NA
    if r["config"].get("Enabled"):
        return None
    return hit("medium", f"EBS encryption by default is off in {r['region']}", "new volumes are not encrypted unless asked")


def _rds_unencrypted(r, node, src, ctx):
    if not r["config"].get("StorageEncrypted"):
        return hit("high", f"Database {name_of(r)} is not encrypted at rest", f"engine {r['config'].get('Engine')}")
    return None


def _rds_public(r, node, src, ctx):
    if not r["config"].get("PubliclyAccessible"):
        return None
    subnets = [s.get("SubnetIdentifier") for s in (r["config"].get("DBSubnetGroup") or {}).get("Subnets", [])]
    arns = {f"arn:{r['arn'].split(':')[1]}:ec2:{r['region']}:{r['account_id']}:subnet/{s}" for s in subnets if s}
    public = any(ctx.nodes.get(a, {}).get("internet_route") is True for a in arns)
    return hit("critical" if public else "high", f"Database {name_of(r)} is publicly accessible",
                "PubliclyAccessible true" + (", in a subnet with an internet route" if public else ""))


def _http_no_redirect(r, node, src, ctx):
    if r["config"].get("Scheme") != "internet-facing":
        return NA
    plain = [x for x in r["config"].get("Listeners") or [] if x.get("Protocol") == "HTTP" and not redirects_to_https(x)]
    if plain:
        return hit("medium", f"Load balancer {name_of(r)} serves plain HTTP",
                    f"HTTP listener on port {', '.join(str(x.get('Port')) for x in plain)} does not redirect to HTTPS")
    return None


def _old_tls(r, node, src, ctx):
    if not any(x.get("Protocol") in ("HTTPS", "TLS") for x in r["config"].get("Listeners") or []):
        return NA
    old = [x for x in r["config"].get("Listeners") or [] if {"TLSv1", "TLSv1.1"} & set(x.get("SslProtocols") or [])]
    if old:
        return hit("medium", f"Load balancer {name_of(r)} allows TLS 1.0 or 1.1",
                    "; ".join(f"port {x.get('Port')}: {x.get('SslPolicy')}" for x in old))
    return None


def _cert_expiry(r, node, src, ctx):
    if not r["config"].get("InUseBy"):
        return NA
    since = ctx.days_since(r["config"].get("NotAfter"))
    if since is None:
        return NA
    days = -since
    if days <= CERT_WARN_DAYS:
        sev = "high" if days <= CERT_URGENT_DAYS else "medium"
        return hit(sev, f"Certificate {name_of(r)} expires in {max(int(days), 0)} days",
                    f"type {r['config'].get('Type')}, renewal {r['config'].get('RenewalEligibility')}")
    return None


def _report_rows(ctx: Ctx) -> list[dict[str, str]] | None:
    reports = ctx.by_type["credential-report"]
    if not reports or not ctx.unit_ok("iam", "credential-report", GLOBAL):
        return None
    return reports[0]["config"].get("Rows") or []


def _user_ref(ctx: Ctx, row: dict[str, str]) -> dict[str, Any]:
    arn = row.get("arn")
    return {"resource": arn if arn in ctx.res else None, "resource_name": row.get("user", "?"), "region": GLOBAL}


def _old_keys(ctx: Ctx) -> tuple[int, list[Hit]]:
    rows = _report_rows(ctx)
    if rows is None:
        return 0, []
    users = [r for r in rows if r.get("user") != "<root_account>"]
    hits: list[Hit] = []
    for row in users:
        problems = []
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            age = ctx.days_since(row.get(f"access_key_{n}_last_rotated"))
            unused = ctx.days_since(row.get(f"access_key_{n}_last_used_date"))
            if age is not None and age > KEY_MAX_DAYS:
                problems.append(f"key {n} is {int(age)} days old")
            elif unused is not None and unused > KEY_MAX_DAYS:
                problems.append(f"key {n} not used for {int(unused)} days")
        if problems:
            hits.append(hit("medium", f"IAM user {row.get('user')} has old or unused access keys", "; ".join(problems),
                             **_user_ref(ctx, row)))
    return len(users), hits


def _no_mfa(ctx: Ctx) -> tuple[int, list[Hit]]:
    rows = _report_rows(ctx)
    if rows is None:
        return 0, []
    users = [r for r in rows if r.get("user") != "<root_account>" and r.get("password_enabled") == "true"]
    return len(users), [hit("high", f"IAM user {r.get('user')} can sign in without MFA", "console password, no MFA device",
                             **_user_ref(ctx, r)) for r in users if r.get("mfa_active") != "true"]


def _root(ctx: Ctx) -> tuple[int, list[Hit]]:
    rows = [r for r in _report_rows(ctx) or [] if r.get("user") == "<root_account>"]
    if not rows:
        return 0, []
    row = rows[0]
    problems = (["no MFA"] if row.get("mfa_active") != "true" else []) + \
        [f"access key {n} active" for n in ("1", "2") if row.get(f"access_key_{n}_active") == "true"]
    if not problems:
        return 1, []
    return 1, [hit("critical", "Root user is not secured", ", ".join(problems), resource=None,
                    resource_name="root user", region=GLOBAL)]


def _no_trail(ctx: Ctx) -> tuple[int, list[Hit]]:
    if not ctx.unit_ok("cloudtrail", "trail", GLOBAL):
        return 0, []
    good = [t for t in ctx.by_type["trail"] if t["config"].get("IsMultiRegionTrail") and t["config"].get("IsLogging")]
    if good:
        return 1, []
    return 1, [hit("high", "No multi-Region CloudTrail trail is logging",
                    f"{len(ctx.by_type['trail'])} trail(s), none multi-Region and logging",
                    resource=None, resource_name="account", region=GLOBAL)]


def _no_flow_logs(r, node, src, ctx):
    if not any(is_running(i) for i in ctx.by_type["instance"] if ctx.vpc_of(i) == r["arn"]):
        return NA
    logged = {t for f in ctx.by_type["flow-log"] for t in ctx.linked("logs", f["arn"])}
    subnets = [s for s in ctx.linked("contains", r["arn"]) if ctx.res.get(s, {}).get("type") == "subnet"]
    if r["arn"] in logged or (subnets and all(s in logged for s in subnets)):
        return None
    return hit("low", f"VPC {name_of(r)} has no flow log", "no flow log on the VPC or on all of its subnets")


def _guardduty_off(r, node, src, ctx):
    if r["service"] != "guardduty" or r["id"] != "guardduty" or \
            not ctx.region_has(r["region"], {"instance", "function", "db-instance"}):
        return NA
    if any(d.get("Status") == "ENABLED" for d in r["config"].get("Detectors", [])):
        return None
    return hit("medium", f"GuardDuty is not enabled in {r['region']}", "no detector with status ENABLED")


def rules() -> list[Rule | GroupRule]:
    inv = ("inventory",)
    return [
        Rule("SEC-NET-001", "SEC06-BP03", inv, {"instance"}, _ssh_rdp_open,
             "Remove the 0.0.0.0/0 rule for SSH/RDP; use Systems Manager Session Manager instead.",
             units=(("ec2", "security-group"),)),
        Rule("SEC-EC2-001", "SEC06-BP02", inv, {"instance"}, _imdsv1,
             "aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required (test the app first)."),
        Rule("SEC-EC2-002", "SEC06-BP03", inv, {"instance"}, _not_ssm,
             "Install the SSM Agent and give the instance profile AmazonSSMManagedInstanceCore.", units=(("ssm", "setting"),)),
        Rule("SEC-EBS-001", "SEC08-BP02", inv, {"volume"}, _volume_unencrypted,
             "Snapshot, copy the snapshot with encryption, and replace the volume."),
        Rule("SEC-EBS-002", "SEC08-BP02", inv, {"setting"}, _ebs_default_off,
             "aws ec2 enable-ebs-encryption-by-default --region <region>"),
        Rule("SEC-RDS-001", "SEC08-BP02", inv, {"db-instance"}, _rds_unencrypted,
             "Restore an encrypted copy from a snapshot and switch over."),
        Rule("SEC-RDS-002", "SEC05-BP01", inv, {"db-instance"}, _rds_public,
             "Set PubliclyAccessible false and keep the database in private subnets."),
        Rule("SEC-ELB-001", "SEC09-BP02", inv, {"load-balancer"}, _http_no_redirect,
             "Change the HTTP listener's default action to redirect to HTTPS (301)."),
        Rule("SEC-ELB-002", "SEC09-BP02", inv, {"load-balancer"}, _old_tls,
             "Use a TLS 1.2 or 1.3 security policy, for example ELBSecurityPolicy-TLS13-1-2-2021-06."),
        Rule("SEC-ACM-001", "SEC09-BP01", inv, {"certificate"}, _cert_expiry,
             "Renew or replace the certificate; for ACM certificates check why renewal failed (DNS validation record)."),
        GroupRule("SEC-IAM-002", "SEC02-BP05", inv, _old_keys, "Rotate the key (create new, deploy, delete old) or delete it if unused."),
        GroupRule("SEC-IAM-003", "SEC02-BP01", inv, _no_mfa, "Require MFA for the user, or move them to IAM Identity Center."),
        GroupRule("SEC-IAM-004", "SEC01-BP02", inv, _root, "Add MFA to the root user and delete any root access keys."),
        GroupRule("SEC-LOG-001", "SEC04-BP01", inv, _no_trail, "Create a multi-Region trail to an S3 bucket with log file validation."),
        Rule("SEC-LOG-002", "SEC04-BP01", inv, {"vpc"}, _no_flow_logs, "Turn on VPC Flow Logs to S3 or CloudWatch Logs.",
             units=(("ec2", "flow-log"),)),
        Rule("SEC-DET-001", "SEC04-BP01", inv, {"setting"}, _guardduty_off, "Turn on GuardDuty in the Region."),
    ]

