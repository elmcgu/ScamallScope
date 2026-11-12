"""Spec 12 cost rules. Prices are estimates (decision by Ellis, 2026-11-10)."""

from __future__ import annotations

from ..findings import severity_for_saving
from ..graph import snapshot_manager
from ..model import GLOBAL
from .engine import NA, Ctx, GroupRule, Hit, Rule, hit, name_of

SNAPSHOT_OLD_DAYS = 180
COVERAGE_MIN_PCT, COVERAGE_MIN_ON_DEMAND = 50.0, 100.0

# Estimates only (decision by Ellis, 2026-11-10). From the worked examples on the EBS pricing page
# (R59) and the VPC pricing page (R55); not Region-specific. Phase E: Price List API.
PRICES_AS_OF = "2026-11-10"
EBS_GB_MONTH = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015}
SNAPSHOT_GB_MONTH = 0.05
PUBLIC_IPV4_HOUR = 0.005
HOURS_A_MONTH = 730


def _cost_hit(title: str, detail: str, saving: float | None) -> Hit:
    return hit(severity_for_saving(saving) if saving is not None else "low", title, detail,
                savings_usd=round(saving, 2) if saving is not None else None)


def _unattached_volume(r, node, src, ctx):
    if r["config"].get("State") != "available":
        return None
    price = EBS_GB_MONTH.get(r["config"].get("VolumeType") or "")
    size = r["config"].get("Size") or 0
    return _cost_hit(f"Volume {name_of(r)} is not attached", f"{size} GB {r['config'].get('VolumeType')}, still charged",
                     size * price if price is not None else None)


def _gp2(r, node, src, ctx):
    if r["config"].get("State") == "available":
        return NA  # an unattached volume is COST-EBS-001: deleting it saves more
    if r["config"].get("VolumeType") != "gp2":
        return None
    size = r["config"].get("Size") or 0
    return _cost_hit(f"Volume {name_of(r)} is gp2", f"{size} GB; gp3 is cheaper per GB",
                     size * (EBS_GB_MONTH["gp2"] - EBS_GB_MONTH["gp3"]))


def _old_snapshot(r, node, src, ctx):
    age = ctx.days_since(r["config"].get("StartTime"))
    if age is None or snapshot_manager(r["config"]):
        return NA  # no date, or AWS Backup / DLM manage its life
    if age <= SNAPSHOT_OLD_DAYS:
        return None
    size = r["config"].get("VolumeSize") or 0
    return _cost_hit(f"Snapshot {name_of(r)} is {int(age)} days old", f"{size} GB, not made by AWS Backup or DLM; "
                     "saving is an upper bound (snapshots are incremental)", size * SNAPSHOT_GB_MONTH)


def _idle_eip(r, node, src, ctx):
    c = r["config"]
    if c.get("AssociationId") or c.get("InstanceId") or c.get("NetworkInterfaceId"):
        return None
    return _cost_hit(f"Elastic IP {name_of(r)} is not in use", "public IPv4 addresses are charged when idle",
                     PUBLIC_IPV4_HOUR * HOURS_A_MONTH)


def _nat_without_endpoints(r, node, src, ctx):
    if r["config"].get("State") != "available":
        return NA
    vpc = ctx.vpc_of(r)
    endpoints = [e for e in ctx.by_type["vpc-endpoint"] if vpc and vpc in ctx.linking("contains", e["arn"])]
    if any(e["config"].get("VpcEndpointType") == "Gateway" and str(e["config"].get("ServiceName", "")).endswith((".s3", ".dynamodb"))
           for e in endpoints):
        return None
    return hit("low", f"NAT gateway {name_of(r)} has no S3 or DynamoDB gateway endpoint beside it",
                "traffic to S3 and DynamoDB goes through the NAT gateway and pays its data charge", savings_usd=None)


def _low_coverage(ctx: Ctx) -> tuple[int, list[Hit]]:
    cov = ctx.extras.get("cost_coverage")
    if not cov or cov.get("savings_plans_pct") is None:
        return 0, []
    sp, ri, od = cov["savings_plans_pct"], cov.get("reservations_pct"), cov.get("on_demand_usd") or 0
    if sp < COVERAGE_MIN_PCT and (ri is None or ri < COVERAGE_MIN_PCT) and od > COVERAGE_MIN_ON_DEMAND:
        return 1, [hit("medium", "Most eligible compute is on demand",
                        f"Savings Plans cover {sp}% and RIs {ri if ri is not None else 'n/a'}%; ${od:,.2f} on demand in {cov.get('days')} days",
                        resource=None, resource_name="account", region=GLOBAL, savings_usd=None)]
    return 1, []


def rules() -> list[Rule | GroupRule]:
    inv = ("inventory",)
    return [
        Rule("COST-EBS-001", "COST04-BP03", inv, {"volume"}, _unattached_volume, "Snapshot it if needed, then delete the volume."),
        Rule("COST-EBS-002", "COST06-BP02", inv, {"volume"}, _gp2, "aws ec2 modify-volume --volume-id <id> --volume-type gp3 (no downtime)."),
        Rule("COST-SNAP-001", "COST04-BP05", inv, {"snapshot"}, _old_snapshot,
             "Delete it if not needed, or manage snapshots with Data Lifecycle Manager or AWS Backup."),
        Rule("COST-EIP-001", "COST04-BP03", inv, {"elastic-ip"}, _idle_eip, "Release the Elastic IP if nothing needs it."),
        Rule("COST-NAT-001", "COST08-BP02", inv, {"nat-gateway"}, _nat_without_endpoints,
             "Add S3 and DynamoDB gateway endpoints to the VPC (no hourly charge).", units=(("ec2", "vpc-endpoint"),)),
        GroupRule("COST-COV-001", "COST07-BP04", inv + ("cost",), _low_coverage,
                  "Review the Savings Plans recommendation in Cost Explorer and buy a small commitment first."),
    ]

