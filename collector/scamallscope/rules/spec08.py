"""Spec 08 rules: tags, stopped and idle instances, S3, Lambda, IAM, agents, monitoring, exposure, admin."""

from __future__ import annotations

from ..model import Resource
from .engine import NA, Check, Ctx, GroupRule, Rule, hit, name_of, state_of

TAGGED_TYPES = {"instance", "bucket", "function", "vpc", "volume", "db-instance", "load-balancer", "autoscaling-group"}
IDLE_AVG, IDLE_MAX = 5.0, 20.0

# Lambda "Deprecated runtimes" table, https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html (R38).
DEPRECATED_RUNTIMES_AS_OF = "2026-11-04"
DEPRECATED_RUNTIMES = frozenset({
    "python3.10", "provided.al2", "nodejs20.x", "ruby3.2", "python3.9", "nodejs18.x", "dotnet6",
    "python3.8", "nodejs16.x", "dotnet7", "java8", "go1.x", "provided", "ruby2.7", "nodejs14.x",
    "python3.7", "dotnetcore3.1", "nodejs12.x", "python3.6", "dotnet5.0", "dotnetcore2.1",
    "nodejs10.x", "ruby2.5", "python2.7", "nodejs8.10", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10",
    "dotnetcore1.0", "dotnetcore2.0", "nodejs",
})


def _tags(required: tuple[str, ...]) -> Check:
    def check(r, node, src, ctx):
        missing = [t for t in required if not r["tags"].get(t)]
        if missing:
            return hit("low", f"{r['type']} {name_of(r)} is missing tags", f"missing: {', '.join(missing)}")
        return None
    return check


def _stopped(r, node, src, ctx):
    if state_of(r) == "stopped":
        return hit("low", f"Instance {name_of(r)} is stopped", "EBS volumes and Elastic IPs are still charged")
    return None


def _idle(r, node, src, ctx):
    m = src["cloudwatch"].get(r["arn"])
    if state_of(r) != "running" or not m or m.get("cpu_avg") is None or m.get("cpu_max") is None:
        return NA
    if m["cpu_avg"] < IDLE_AVG and m["cpu_max"] < IDLE_MAX:
        return hit("medium", f"Instance {name_of(r)} looks idle",
                f"CPU average {m['cpu_avg']}%, peak {m['cpu_max']}% over {m.get('days')} days")
    return None


def _unknown(r: Resource, detail: str) -> bool:
    return detail in (r["config"].get("DetailErrors") or {})


def _versioning(r, node, src, ctx):
    if _unknown(r, "Versioning"):
        return NA
    if r["config"].get("Versioning") == "Enabled":
        return None
    return hit("low", f"Bucket {name_of(r)} has no versioning", f"versioning: {r['config'].get('Versioning') or 'never enabled'}")


def _encryption(r, node, src, ctx):
    if _unknown(r, "Encryption"):
        return NA
    if r["config"].get("Encryption"):
        return None
    return hit("medium", f"Bucket {name_of(r)} has no default encryption", "no ServerSideEncryptionConfiguration")


def _runtime(r, node, src, ctx):
    rt = r["config"].get("Runtime")
    if not rt:
        return NA  # container image: no managed runtime
    if rt in DEPRECATED_RUNTIMES:
        return hit("medium", f"Function {name_of(r)} uses deprecated runtime {rt}", f"deprecated as of {DEPRECATED_RUNTIMES_AS_OF} list")
    return None


def _iam_user(r, node, src, ctx):
    return hit("low", f"IAM user {name_of(r)} has long-term credentials", "prefer federation and roles with temporary credentials")


def _no_agent(r, node, src, ctx):
    if state_of(r) != "running":
        return NA
    if r["arn"] not in src["wazuh"]:
        return hit("medium", f"Instance {name_of(r)} has no Wazuh agent", "no matched agent: no vulnerability or OS data")
    return None


def _not_scraped(r, node, src, ctx):
    if state_of(r) != "running":
        return NA
    p = src["prometheus"].get(r["arn"])
    if p is None:
        return hit("medium", f"Instance {name_of(r)} is not monitored by Prometheus", "no up series for this instance")
    if p.get("prom_up") == 0:
        return hit("high", f"Prometheus target down on {name_of(r)}", "up = 0")
    return None


def _no_alarm(r, node, src, ctx):
    m = src["cloudwatch"].get(r["arn"])
    if state_of(r) != "running" or m is None:
        return NA
    if not m.get("alarms"):
        return hit("low", f"Instance {name_of(r)} has no CloudWatch alarm", "no metric alarm with its InstanceId")
    return None


def _not_managed(r, node, src, ctx):
    if state_of(r) != "running":
        return NA
    if r["arn"] not in src["ansible"]:
        return hit("low", f"Instance {name_of(r)} was not in the Ansible run", "not configured by the playbook")
    return None


def _exposed(r, node, src, ctx):
    if node.get("exposure") in (None, "unknown"):
        return NA
    if node.get("exposure") == "exposed":
        ports = ", ".join(f"{p['protocol']}/{p['from_port'] if p.get('from_port') is not None else 'all'}"
                          for p in node.get("exposed_ports") or [])
        return hit("high", f"{r['type']} {name_of(r)} is reachable from the internet",
                    node.get("exposure_reason", "") + (f" ({ports})" if ports else ""))
    return None


def _admin(r, node, src, ctx):
    if node.get("admin") and not str(r["config"].get("Path", "")).startswith("/aws-service-role/"):
        return hit("medium", f"{r['type']} {name_of(r)} has admin rights", node.get("admin_reason") or "")
    return None


def _hub_enabled(ctx: Ctx) -> bool:
    return "costhub" in ctx.loaded


def rules(required_tags: tuple[str, ...]) -> list[Rule | GroupRule]:
    inv = ("inventory",)
    return [
        Rule("HYG-TAG-001", "COST03-BP02", inv, TAGGED_TYPES, _tags(required_tags),
             "Add the missing tags and activate them as cost allocation tags."),
        Rule("HYG-EC2-001", "COST04-BP03", inv, {"instance"}, _stopped,
             "Terminate it if it is not needed; snapshot the volumes first."),
        Rule("HYG-EC2-002", "COST06-BP02", inv + ("cloudwatch",), {"instance"}, _idle,
             "Stop, downsize or schedule it. Turn on Compute Optimizer for a better recommendation.",
             when=lambda ctx: not _hub_enabled(ctx)),
        Rule("HYG-S3-001", "REL09-BP01", inv, {"bucket"}, _versioning, "Turn on S3 Versioning with a lifecycle rule for old versions."),
        Rule("HYG-S3-002", "SEC08-BP02", inv, {"bucket"}, _encryption, "Set default encryption (SSE-S3 or SSE-KMS)."),
        Rule("HYG-LAM-001", "SEC06-BP01", inv, {"function"}, _runtime, "Move the function to a supported runtime."),
        Rule("HYG-IAM-001", "SEC02-BP02", inv, {"user"}, _iam_user,
             "Use IAM Identity Center or roles; remove the user's access keys and password if they are not needed."),
        Rule("HYG-AGT-001", "SEC06-BP01", inv + ("wazuh",), {"instance"}, _no_agent, "Install and enrol the Wazuh agent."),
        Rule("HYG-MON-001", "REL06-BP01", inv + ("prometheus",), {"instance"}, _not_scraped,
             "Add the instance to Prometheus scraping and check the exporter."),
        Rule("HYG-MON-002", "REL06-BP03", inv + ("cloudwatch",), {"instance"}, _no_alarm,
             "Add a CloudWatch alarm (status check failed, CPU) that notifies someone."),
        Rule("HYG-CFG-001", "REL08-BP05", inv + ("ansible",), {"instance"}, _not_managed, "Add the host to the Ansible inventory."),
        Rule("EXP-001", "SEC05-BP01", inv, {"instance", "bucket", "function"}, _exposed,
             "Remove the public path: security group, public IP, bucket policy or function URL auth."),
        Rule("IAM-ADMIN-001", "SEC03-BP02", inv, {"user", "group", "role"}, _admin, "Replace admin rights with a policy for the tasks needed."),
    ]

