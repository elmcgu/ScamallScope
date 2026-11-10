"""Hygiene rules that use the inventory, often joined with another source (spec 08).

A rule runs only when all its inputs are loaded. A rule that did not run covers nothing on the
scorecard, so its best practice stays "not checked" rather than "clear".
"""

from __future__ import annotations

from typing import Any, Callable

from .findings import Finding, Parsed, cover, empty_parsed, make
from .model import Resource, Snapshot

DEFAULT_REQUIRED_TAGS = ("owner", "env")
TAGGED_TYPES = {"instance", "bucket", "function", "vpc"}
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

Sources = dict[str, dict[str, dict[str, Any]]]  # loaded source -> ARN -> data


def _state(r: Resource) -> str | None:
    return (r["config"].get("State") or {}).get("Name")


def _name(r: Resource) -> str:
    return r.get("name") or r["id"]


class Rule:
    def __init__(self, rule_id: str, bp: str, needs: tuple[str, ...], types: set[str],
                 check: Callable[[Resource, dict[str, Any], Sources], tuple[str, str, str] | None]):
        """check returns (severity, title, detail) for a finding, or None when the resource is fine."""
        self.id, self.bp, self.needs, self.types, self.check = rule_id, bp, needs, types, check


def _tags(required: tuple[str, ...]):
    def check(r: Resource, node: dict[str, Any], src: Sources):
        missing = [t for t in required if not r["tags"].get(t)]
        if missing:
            return "low", f"{r['type']} {_name(r)} is missing tags", f"missing: {', '.join(missing)}"
        return None
    return check


def _stopped(r, node, src):
    if _state(r) == "stopped":
        return "low", f"Instance {_name(r)} is stopped", "EBS volumes and Elastic IPs are still charged"
    return None


def _idle(r, node, src):
    m = src["cloudwatch"].get(r["arn"])
    if _state(r) != "running" or not m or m.get("cpu_avg") is None or m.get("cpu_max") is None:
        return None
    if m["cpu_avg"] < IDLE_AVG and m["cpu_max"] < IDLE_MAX:
        return ("medium", f"Instance {_name(r)} looks idle",
                f"CPU average {m['cpu_avg']}%, peak {m['cpu_max']}% over {m.get('days')} days")
    return None


def _unknown(r: Resource, detail: str) -> bool:
    return detail in (r["config"].get("DetailErrors") or {})


def _versioning(r, node, src):
    if _unknown(r, "Versioning") or r["config"].get("Versioning") == "Enabled":
        return None
    return "low", f"Bucket {_name(r)} has no versioning", f"versioning: {r['config'].get('Versioning') or 'never enabled'}"


def _encryption(r, node, src):
    if _unknown(r, "Encryption") or r["config"].get("Encryption"):
        return None
    return "medium", f"Bucket {_name(r)} has no default encryption", "no ServerSideEncryptionConfiguration"


def _runtime(r, node, src):
    rt = r["config"].get("Runtime")
    if rt in DEPRECATED_RUNTIMES:
        return "medium", f"Function {_name(r)} uses deprecated runtime {rt}", f"deprecated as of {DEPRECATED_RUNTIMES_AS_OF} list"
    return None


def _iam_user(r, node, src):
    return "low", f"IAM user {_name(r)} has long-term credentials", "prefer federation and roles with temporary credentials"


def _no_agent(r, node, src):
    if _state(r) == "running" and r["arn"] not in src["wazuh"]:
        return "medium", f"Instance {_name(r)} has no Wazuh agent", "no matched agent: no vulnerability or OS data"
    return None


def _not_scraped(r, node, src):
    if _state(r) != "running":
        return None
    p = src["prometheus"].get(r["arn"])
    if p is None:
        return "medium", f"Instance {_name(r)} is not monitored by Prometheus", "no up series for this instance"
    if p.get("prom_up") == 0:
        return "high", f"Prometheus target down on {_name(r)}", "up = 0"
    return None


def _no_alarm(r, node, src):
    m = src["cloudwatch"].get(r["arn"])
    if _state(r) == "running" and m is not None and not m.get("alarms"):
        return "low", f"Instance {_name(r)} has no CloudWatch alarm", "no metric alarm with its InstanceId"
    return None


def _not_managed(r, node, src):
    if _state(r) == "running" and r["arn"] not in src["ansible"]:
        return "low", f"Instance {_name(r)} was not in the Ansible run", "not configured by the playbook"
    return None


def _exposed(r, node, src):
    if node.get("exposure") == "exposed":
        ports = ", ".join(f"{p['protocol']}/{p['from_port'] if p.get('from_port') is not None else 'all'}"
                          for p in node.get("exposed_ports") or [])
        return "high", f"{r['type']} {_name(r)} is reachable from the internet", node.get("exposure_reason", "") + (f" ({ports})" if ports else "")
    return None


def _admin(r, node, src):
    if node.get("admin") and not str(r["config"].get("Path", "")).startswith("/aws-service-role/"):
        return "medium", f"{r['type']} {_name(r)} has admin rights", node.get("admin_reason") or ""
    return None


def rules(required_tags: tuple[str, ...]) -> list[Rule]:
    inv = ("inventory",)
    return [
        Rule("HYG-TAG-001", "COST03-BP02", inv, TAGGED_TYPES, _tags(required_tags)),
        Rule("HYG-EC2-001", "COST04-BP03", inv, {"instance"}, _stopped),
        Rule("HYG-EC2-002", "COST06-BP02", inv + ("cloudwatch",), {"instance"}, _idle),
        Rule("HYG-S3-001", "REL09-BP01", inv, {"bucket"}, _versioning),
        Rule("HYG-S3-002", "SEC08-BP02", inv, {"bucket"}, _encryption),
        Rule("HYG-LAM-001", "SEC06-BP01", inv, {"function"}, _runtime),
        Rule("HYG-IAM-001", "SEC02-BP02", inv, {"user"}, _iam_user),
        Rule("HYG-AGT-001", "SEC06-BP01", inv + ("wazuh",), {"instance"}, _no_agent),
        Rule("HYG-MON-001", "REL06-BP01", inv + ("prometheus",), {"instance"}, _not_scraped),
        Rule("HYG-MON-002", "REL06-BP03", inv + ("cloudwatch",), {"instance"}, _no_alarm),
        Rule("HYG-CFG-001", "REL08-BP05", inv + ("ansible",), {"instance"}, _not_managed),
        Rule("EXP-001", "SEC05-BP01", inv, {"instance", "bucket", "function"}, _exposed),
        Rule("IAM-ADMIN-001", "SEC03-BP02", inv, {"user", "group", "role"}, _admin),
    ]


def run(snapshot: Snapshot, nodes: dict[str, dict[str, Any]], sources: Sources,
        required_tags: tuple[str, ...] = DEFAULT_REQUIRED_TAGS) -> Parsed:
    """sources: data per loaded source (ARN -> data). 'inventory' is always loaded."""
    loaded = {"inventory", *sources}
    src: Sources = {k: sources.get(k, {}) for k in ("wazuh", "prometheus", "cloudwatch", "ansible")}
    out = empty_parsed()
    for rule in rules(required_tags):
        if not set(rule.needs) <= loaded:
            continue
        checked = failed = 0
        for r in snapshot["resources"]:
            if r["type"] not in rule.types:
                continue
            checked += 1
            hit = rule.check(r, nodes.get(r["arn"], {}), src)
            if hit:
                failed += 1
                sev, title, detail = hit
                source = "inventory" if rule.needs == ("inventory",) else "hygiene"
                f: Finding = make(source, rule.id, title, sev, [rule.bp], r["arn"], _name(r), r["region"], detail)  # type: ignore[arg-type]
                out["findings"].append(f)
        if checked:
            if failed:
                cover(out["coverage"], [rule.bp], failed=True, n=failed)
            if checked > failed:
                cover(out["coverage"], [rule.bp], n=checked - failed)
    return out
