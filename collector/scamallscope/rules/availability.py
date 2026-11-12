"""Spec 12 availability (Reliability) rules, and the backup helpers the Availability view shares."""

from __future__ import annotations

from collections import defaultdict

from ..model import Resource
from .engine import NA, Ctx, GroupRule, Hit, Rule, az_of, hit, is_running, name_of

BACKUP_RECENT_DAYS = 7


def _single_az(ctx: Ctx) -> tuple[int, list[Hit]]:
    hits: list[Hit] = []
    checked = 0
    groups: dict[tuple[str, str, str], list[Resource]] = defaultdict(list)
    for i in ctx.by_type["instance"]:
        if not is_running(i):
            continue
        if app := ctx.app_of(i):
            groups[(i["region"], ctx.vpc_of(i) or "no VPC", app)].append(i)
        elif not ctx.in_asg(i["arn"]) and not ctx.is_target(i["arn"]):
            checked += 1
            hits.append(hit("medium" if ctx.is_prod(i) else "low", f"Instance {name_of(i)} runs alone",
                             f"one instance in {az_of(i)}, not in an Auto Scaling group or behind a load balancer",
                             resource=i["arn"], resource_name=name_of(i), region=i["region"]))
    for (region, vpc, app), members in sorted(groups.items()):
        checked += 1
        azs = sorted({az_of(m) or "?" for m in members})
        if len(azs) == 1:
            prod = any(ctx.is_prod(m) for m in members)
            vpc_name = name_of(ctx.res[vpc]) if vpc in ctx.res else vpc
            hits.append(hit("high" if prod else "medium", f"App {app} runs in one Availability Zone",
                             f"{len(members)} instance(s), all in {azs[0]}", resource=None,
                             resource_name=f"app {app} ({vpc_name})", region=region))
    for tg in ctx.by_type["target-group"]:
        azs = {az_of(ctx.res[t]) for t in ctx.linked("targets", tg["arn"]) if t in ctx.res}
        if not azs:
            continue
        checked += 1
        if len(azs) == 1:
            hits.append(hit("high" if ctx.is_prod(tg) else "medium", f"Target group {name_of(tg)} has targets in one AZ",
                             f"all targets in {next(iter(azs))}", resource=tg["arn"], resource_name=name_of(tg),
                             region=tg["region"]))
    return checked, hits


def _rds_single_az(r, node, src, ctx):
    if r["config"].get("DBClusterIdentifier"):
        return NA  # Aurora is judged by its cluster, not collected yet (Phase E)
    if r["config"].get("MultiAZ"):
        return None
    return hit("high" if ctx.is_prod(r) else "low", f"Database {name_of(r)} is not Multi-AZ",
                f"single instance in {r['config'].get('AvailabilityZone')}")


def _one_az(r, node, src, ctx):
    zones = r["config"].get("AvailabilityZones") or []
    names = sorted(n for z in zones if (n := z.get("ZoneName") if isinstance(z, dict) else z))
    if not names:
        return NA
    if len(names) == 1:
        kind = "Load balancer" if r["type"] == "load-balancer" else "Auto Scaling group"
        return hit("high", f"{kind} {name_of(r)} uses one Availability Zone", f"only {names[0]}")
    return None


def _shared_nat(r, node, src, ctx):
    subnets: set[str] = set()
    explicit = {s for rt in ctx.by_type["route-table"] for s in ctx.linked("routes", rt["arn"])}
    for t in ctx.linking("routes_to", r["arn"]):
        table = ctx.res.get(t)
        if not table or not any(x.get("NatGatewayId") == r["id"] and x.get("DestinationCidrBlock") == "0.0.0.0/0"
                                for x in table["config"].get("Routes", [])):
            continue
        subnets |= ctx.linked("routes", t)
        if any(a.get("Main") for a in table["config"].get("Associations", [])):
            vpc = ctx.vpc_of(table)
            subnets |= {s["arn"] for s in ctx.by_type["subnet"] if ctx.vpc_of(s) == vpc and s["arn"] not in explicit}
    azs = sorted({a for s in subnets if s in ctx.res and (a := ctx.res[s]["config"].get("AvailabilityZone"))})
    if len(azs) >= 2:
        return hit("medium", f"NAT gateway {name_of(r)} serves {len(azs)} Availability Zones",
                    f"private subnets in {', '.join(azs)} lose internet access if its AZ fails")
    return None


def _no_healing(r, node, src, ctx):
    if not is_running(r) or ctx.in_asg(r["arn"]):
        return NA  # an ASG replaces its instances
    if (r["config"].get("MaintenanceOptions") or {}).get("AutoRecovery") != "disabled":
        return None
    if (src["cloudwatch"].get(r["arn"]) or {}).get("recover_alarm"):
        return None
    return hit("medium", f"Instance {name_of(r)} has no automatic recovery",
                "AutoRecovery disabled, not in an Auto Scaling group, no recover alarm")


def _ec2_health_check(r, node, src, ctx):
    if not r["config"].get("TargetGroupARNs"):
        return NA
    if r["config"].get("HealthCheckType") == "EC2":
        return hit("low", f"Auto Scaling group {name_of(r)} ignores load balancer health",
                    "HealthCheckType EC2: instances failing the target group check are not replaced")
    return None


def _unhealthy_targets(r, node, src, ctx):
    if not r["config"].get("TargetHealth"):
        return NA
    bad = [t for t in r["config"].get("TargetHealth") or [] if t.get("State") == "unhealthy"]
    if bad:
        return hit("high", f"Target group {name_of(r)} has {len(bad)} unhealthy target(s)",
                    "; ".join(f"{t.get('Id')}: {t.get('Reason') or 'unhealthy'}" for t in bad[:5]))
    return None


def backed_up(r: Resource, ctx: Ctx) -> bool:
    protected = {p.get("ResourceArn"): p.get("LastBackupTime")
                 for p in (ctx.setting("backup", "backup-protected", r["region"]) or {}).get("Resources", [])}
    age = ctx.days_since(protected.get(r["arn"]))
    if age is not None and age <= BACKUP_RECENT_DAYS:
        return True
    if r["type"] == "db-instance":
        return (r["config"].get("BackupRetentionPeriod") or 0) > 0
    for s in ctx.linking("snapshot_of", r["arn"]):
        snap_age = ctx.days_since(ctx.res[s]["config"].get("StartTime")) if s in ctx.res else None
        if snap_age is not None and snap_age <= BACKUP_RECENT_DAYS:
            return True
    return False


def needs_backup(r: Resource, ctx: Ctx) -> bool:
    """Volumes attached to an instance that is not in an ASG (ASG instances are replaceable), and databases."""
    if r["type"] == "db-instance":
        return True
    attached = [i for i in ctx.linked("attached", r["arn"]) if i in ctx.res]
    return r["config"].get("State") == "in-use" and bool(attached) and not all(ctx.in_asg(i) for i in attached)


def _no_backup(r, node, src, ctx):
    if not needs_backup(r, ctx):
        return NA
    if r["type"] == "volume" and not ctx.unit_ok("ec2", "snapshot", r["region"]):
        return NA
    if backed_up(r, ctx):
        return None
    what = "Volume" if r["type"] == "volume" else "Database"
    return hit("high" if ctx.is_prod(r) else "medium", f"{what} {name_of(r)} has no recent backup",
                f"no AWS Backup recovery point or snapshot in {BACKUP_RECENT_DAYS} days")


def _no_retention(r, node, src, ctx):
    if (r["config"].get("BackupRetentionPeriod") or 0) == 0:
        return hit("high", f"Database {name_of(r)} has automated backups turned off", "BackupRetentionPeriod 0")
    return None


def _snapshot_unencrypted(r, node, src, ctx):
    if not r["config"].get("Encrypted"):
        return hit("medium", f"Snapshot {name_of(r)} is not encrypted", f"from volume {r['config'].get('VolumeId')}")
    return None


def rules() -> list[Rule | GroupRule]:
    inv = ("inventory",)
    return [
        GroupRule("REL-AZ-001", "REL10-BP01", inv, _single_az,
                  "Run at least two instances in two AZs behind a load balancer, managed by an Auto Scaling group."),
        Rule("REL-AZ-002", "REL10-BP01", inv, {"db-instance"}, _rds_single_az, "Modify the instance to Multi-AZ (short failover during the change)."),
        Rule("REL-AZ-003", "REL10-BP01", inv, {"load-balancer", "autoscaling-group"}, _one_az, "Add subnets in a second AZ."),
        Rule("REL-AZ-004", "REL10-BP01", inv, {"nat-gateway"}, _shared_nat,
             "Create one NAT gateway per AZ and route each AZ's private subnets to its own.",
             units=(("ec2", "route-table"), ("ec2", "subnet"))),
        Rule("REL-HEAL-001", "REL11-BP03", inv, {"instance"}, _no_healing,
             "Set AutoRecovery to default, add a CloudWatch recover alarm, or put it in an Auto Scaling group."),
        Rule("REL-HEAL-002", "REL11-BP01", inv, {"autoscaling-group"}, _ec2_health_check,
             "Set the group's health check type to ELB."),
        Rule("REL-HEAL-003", "REL11-BP01", inv, {"target-group"}, _unhealthy_targets,
             "Check the health check path and the application on the unhealthy targets."),
        Rule("REL-BAK-001", "REL09-BP03", inv, {"volume", "db-instance"}, _no_backup,
             "Add the resource to an AWS Backup plan (or a Data Lifecycle Manager policy for volumes).",
             units=(("backup", "setting"),)),
        Rule("REL-BAK-002", "REL09-BP03", inv, {"db-instance"}, _no_retention, "Set the backup retention period to 7 days or more."),
        Rule("REL-BAK-003", "REL09-BP02", inv, {"snapshot"}, _snapshot_unencrypted, "Copy the snapshot with encryption and delete the old one."),
    ]

