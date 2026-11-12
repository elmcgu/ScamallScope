"""Rules over the inventory, often joined with another source (specs 08 and 12).

A rule runs only when all its inputs are loaded, and checks a resource only when the units it
needs collected without error. A rule that checked nothing covers nothing on the scorecard, so
its best practice stays "not checked" rather than "clear".
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timezone
from typing import Any, Callable, Final, Literal, TypedDict

from .findings import Finding, Parsed, Severity, cover, empty_parsed, make, severity_for_saving
from .graph import redirects_to_https, snapshot_manager
from .model import GLOBAL, Resource, Snapshot

DEFAULT_REQUIRED_TAGS = ("owner", "env")
DEFAULT_ENV_TAG, DEFAULT_APP_TAG = "env", "app"  # tag keys; set per estate with --env-tag and --app-tag
TAGGED_TYPES = {"instance", "bucket", "function", "vpc", "volume", "db-instance", "load-balancer", "autoscaling-group"}
IDLE_AVG, IDLE_MAX = 5.0, 20.0
PROD_VALUES = {"prod", "production", "prd"}
OPEN = {"0.0.0.0/0", "::/0"}
ADMIN_PORTS = (22, 3389)
KEY_MAX_DAYS, CERT_WARN_DAYS, CERT_URGENT_DAYS = 90, 30, 7
SNAPSHOT_OLD_DAYS, BACKUP_RECENT_DAYS = 180, 7
COVERAGE_MIN_PCT, COVERAGE_MIN_ON_DEMAND = 50.0, 100.0

# Lambda "Deprecated runtimes" table, https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html (R38).
DEPRECATED_RUNTIMES_AS_OF = "2026-11-04"
DEPRECATED_RUNTIMES = frozenset({
    "python3.10", "provided.al2", "nodejs20.x", "ruby3.2", "python3.9", "nodejs18.x", "dotnet6",
    "python3.8", "nodejs16.x", "dotnet7", "java8", "go1.x", "provided", "ruby2.7", "nodejs14.x",
    "python3.7", "dotnetcore3.1", "nodejs12.x", "python3.6", "dotnet5.0", "dotnetcore2.1",
    "nodejs10.x", "ruby2.5", "python2.7", "nodejs8.10", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10",
    "dotnetcore1.0", "dotnetcore2.0", "nodejs",
})

# Estimates only (decision by Ellis, 2026-11-10). From the worked examples on the EBS pricing page
# (R59) and the VPC pricing page (R55); not Region-specific. Phase E: Price List API.
PRICES_AS_OF = "2026-11-10"
EBS_GB_MONTH = {"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015}
SNAPSHOT_GB_MONTH = 0.05
PUBLIC_IPV4_HOUR = 0.005
HOURS_A_MONTH = 730

Sources = dict[str, dict[str, dict[str, Any]]]  # loaded source -> ARN -> data


class _HitBase(TypedDict):
    severity: Severity
    title: str


class Hit(_HitBase, total=False):
    detail: str
    remediation: str
    savings_usd: float | None
    resource: str | None  # group rules only
    resource_name: str
    region: str


# ---------------------------------------------------------------- context


class Ctx:
    """Indexes over one snapshot, built once per run, so rules can follow links and settings."""

    def __init__(self, snapshot: Snapshot, nodes: dict[str, dict[str, Any]], src: Sources,
                 loaded: set[str], extras: dict[str, Any], today: date,
                 env_tag: str = DEFAULT_ENV_TAG, app_tag: str = DEFAULT_APP_TAG):
        self.snapshot, self.nodes, self.src, self.loaded, self.extras, self.today = snapshot, nodes, src, loaded, extras, today
        self.env_tag, self.app_tag = env_tag, app_tag
        self.res = {r["arn"]: r for r in snapshot["resources"]}
        self.out_links: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        self.in_links: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
        for link in snapshot["links"]:
            self.out_links[link["type"]][link["source"]].add(link["target"])
            self.in_links[link["type"]][link["target"]].add(link["source"])
        self.units = {(u["service"], u["resource_type"], u["region"]): u["status"] for u in snapshot["units"]}
        self.by_type: dict[str, list[Resource]] = defaultdict(list)
        for r in snapshot["resources"]:
            self.by_type[r["type"]].append(r)
        self.settings = {(r["service"], r["id"], r["region"]): r for r in self.by_type["setting"]}

    def unit_ok(self, service: str, resource_type: str, region: str) -> bool:
        """Missing counts as not collected: never treat it as "nothing there"."""
        return self.units.get((service, resource_type, region)) == "ok"

    def setting(self, service: str, setting_id: str, region: str) -> dict[str, Any] | None:
        r = self.settings.get((service, setting_id, region))
        return r["config"] if r else None

    def linked(self, link_type: str, source: str) -> set[str]:
        return self.out_links[link_type].get(source, set())

    def linking(self, link_type: str, target: str) -> set[str]:
        return self.in_links[link_type].get(target, set())

    def vpc_of(self, r: Resource) -> str | None:
        if r["type"] == "vpc":
            return r["arn"]
        for parent in self.linking("contains", r["arn"]):
            p = self.res.get(parent)
            if p and p["type"] == "vpc":
                return parent
            if p and p["type"] == "subnet":
                return self.vpc_of(p)
        return None

    def is_prod(self, r: Resource) -> bool:
        return prod_tags(r["tags"], self.env_tag)

    def app_of(self, r: Resource) -> str | None:
        return r["tags"].get(self.app_tag) or None

    def in_asg(self, instance_arn: str) -> bool:
        return bool(self.linking("manages", instance_arn))

    def is_target(self, instance_arn: str) -> bool:
        return bool(self.linking("targets", instance_arn))

    def region_has(self, region: str, types: set[str]) -> bool:
        return any(r["region"] == region and r["type"] in types for r in self.snapshot["resources"])

    def days_since(self, iso: Any) -> float | None:
        if not iso or iso in ("N/A", "not_supported", "no_information"):
            return None
        try:
            when = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        except ValueError:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        now = datetime.combine(self.today, datetime.min.time(), tzinfo=timezone.utc)
        return (now - when).total_seconds() / 86400


def prod_tags(tags: dict[str, str], env_tag: str = DEFAULT_ENV_TAG) -> bool:
    """Prod when the environment tag says so, or when there is none (decision by Ellis, 2026-11-10)."""
    env = (tags.get(env_tag) or "").strip().lower()
    return not env or env in PROD_VALUES


def _state(r: Resource) -> str | None:
    return (r["config"].get("State") or {}).get("Name") if r["type"] == "instance" else r["config"].get("State")


def _running(r: Resource) -> bool:
    return r["type"] == "instance" and _state(r) == "running"


def _name(r: Resource) -> str:
    return r.get("name") or r["id"]


def _az(r: Resource) -> str | None:
    return (r["config"].get("Placement") or {}).get("AvailabilityZone") or r["config"].get("AvailabilityZone")


# ---------------------------------------------------------------- rule types

NA: Final = "n/a"  # the rule does not apply to this resource, or cannot judge it: neither passed nor failed
Result = Hit | None | Literal["n/a"]  # Hit: failed. None: passed. NA: not judged.
Check = Callable[[Resource, dict[str, Any], Sources, Ctx], Result]


class Rule:
    """One check per resource of the listed types."""

    def __init__(self, rule_id: str, bp: str, needs: tuple[str, ...], types: set[str], check: Check,
                 remediation: str, units: tuple[tuple[str, str], ...] = (), when: Callable[[Ctx], bool] | None = None):
        self.id, self.bp, self.needs, self.types, self.check = rule_id, bp, needs, types, check
        self.remediation, self.units, self.when = remediation, units, when


class GroupRule:
    """A check over the whole snapshot (account settings, groups of resources). Returns (checked, hits)."""

    def __init__(self, rule_id: str, bp: str, needs: tuple[str, ...], run: Callable[[Ctx], tuple[int, list[Hit]]],
                 remediation: str):
        self.id, self.bp, self.needs, self.run, self.remediation = rule_id, bp, needs, run, remediation


def _hit(severity: str, title: str, detail: str = "", **extra: Any) -> Hit:
    return {"severity": severity, "title": title, "detail": detail, **extra}  # type: ignore[typeddict-item]


# ---------------------------------------------------------------- spec 08 rules


def _tags(required: tuple[str, ...]) -> Check:
    def check(r, node, src, ctx):
        missing = [t for t in required if not r["tags"].get(t)]
        if missing:
            return _hit("low", f"{r['type']} {_name(r)} is missing tags", f"missing: {', '.join(missing)}")
        return None
    return check


def _stopped(r, node, src, ctx):
    if _state(r) == "stopped":
        return _hit("low", f"Instance {_name(r)} is stopped", "EBS volumes and Elastic IPs are still charged")
    return None


def _idle(r, node, src, ctx):
    m = src["cloudwatch"].get(r["arn"])
    if _state(r) != "running" or not m or m.get("cpu_avg") is None or m.get("cpu_max") is None:
        return NA
    if m["cpu_avg"] < IDLE_AVG and m["cpu_max"] < IDLE_MAX:
        return _hit("medium", f"Instance {_name(r)} looks idle",
                f"CPU average {m['cpu_avg']}%, peak {m['cpu_max']}% over {m.get('days')} days")
    return None


def _unknown(r: Resource, detail: str) -> bool:
    return detail in (r["config"].get("DetailErrors") or {})


def _versioning(r, node, src, ctx):
    if _unknown(r, "Versioning"):
        return NA
    if r["config"].get("Versioning") == "Enabled":
        return None
    return _hit("low", f"Bucket {_name(r)} has no versioning", f"versioning: {r['config'].get('Versioning') or 'never enabled'}")


def _encryption(r, node, src, ctx):
    if _unknown(r, "Encryption"):
        return NA
    if r["config"].get("Encryption"):
        return None
    return _hit("medium", f"Bucket {_name(r)} has no default encryption", "no ServerSideEncryptionConfiguration")


def _runtime(r, node, src, ctx):
    rt = r["config"].get("Runtime")
    if not rt:
        return NA  # container image: no managed runtime
    if rt in DEPRECATED_RUNTIMES:
        return _hit("medium", f"Function {_name(r)} uses deprecated runtime {rt}", f"deprecated as of {DEPRECATED_RUNTIMES_AS_OF} list")
    return None


def _iam_user(r, node, src, ctx):
    return _hit("low", f"IAM user {_name(r)} has long-term credentials", "prefer federation and roles with temporary credentials")


def _no_agent(r, node, src, ctx):
    if _state(r) != "running":
        return NA
    if r["arn"] not in src["wazuh"]:
        return _hit("medium", f"Instance {_name(r)} has no Wazuh agent", "no matched agent: no vulnerability or OS data")
    return None


def _not_scraped(r, node, src, ctx):
    if _state(r) != "running":
        return NA
    p = src["prometheus"].get(r["arn"])
    if p is None:
        return _hit("medium", f"Instance {_name(r)} is not monitored by Prometheus", "no up series for this instance")
    if p.get("prom_up") == 0:
        return _hit("high", f"Prometheus target down on {_name(r)}", "up = 0")
    return None


def _no_alarm(r, node, src, ctx):
    m = src["cloudwatch"].get(r["arn"])
    if _state(r) != "running" or m is None:
        return NA
    if not m.get("alarms"):
        return _hit("low", f"Instance {_name(r)} has no CloudWatch alarm", "no metric alarm with its InstanceId")
    return None


def _not_managed(r, node, src, ctx):
    if _state(r) != "running":
        return NA
    if r["arn"] not in src["ansible"]:
        return _hit("low", f"Instance {_name(r)} was not in the Ansible run", "not configured by the playbook")
    return None


def _exposed(r, node, src, ctx):
    if node.get("exposure") in (None, "unknown"):
        return NA
    if node.get("exposure") == "exposed":
        ports = ", ".join(f"{p['protocol']}/{p['from_port'] if p.get('from_port') is not None else 'all'}"
                          for p in node.get("exposed_ports") or [])
        return _hit("high", f"{r['type']} {_name(r)} is reachable from the internet",
                    node.get("exposure_reason", "") + (f" ({ports})" if ports else ""))
    return None


def _admin(r, node, src, ctx):
    if node.get("admin") and not str(r["config"].get("Path", "")).startswith("/aws-service-role/"):
        return _hit("medium", f"{r['type']} {_name(r)} has admin rights", node.get("admin_reason") or "")
    return None


# ---------------------------------------------------------------- spec 12: security


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
    if not _running(r):
        return NA
    ports = sorted({p for g in ctx.linked("uses", r["arn"]) if g in ctx.res for p in _open_admin_ports(ctx.res[g])})
    if not ports:
        return None
    sev = "critical" if node.get("exposure") == "exposed" else "high"
    return _hit(sev, f"Instance {_name(r)} allows {'/'.join(map(str, ports))} from anywhere",
                f"security group ingress from 0.0.0.0/0 or ::/0 on port {', '.join(map(str, ports))}")


def _imdsv1(r, node, src, ctx):
    if not _running(r):
        return NA
    if (r["config"].get("MetadataOptions") or {}).get("HttpTokens") != "required":
        return _hit("medium", f"Instance {_name(r)} allows IMDSv1", "MetadataOptions.HttpTokens is not required")
    return None


def _not_ssm(r, node, src, ctx):
    if not _running(r):
        return NA
    managed = {i.get("InstanceId") for i in (ctx.setting("ssm", "ssm-managed", r["region"]) or {}).get("Instances", [])}
    if r["id"] not in managed:
        return _hit("low", f"Instance {_name(r)} is not managed by Systems Manager", "not in DescribeInstanceInformation")
    return None


def _volume_unencrypted(r, node, src, ctx):
    if not r["config"].get("Encrypted"):
        return _hit("medium", f"Volume {_name(r)} is not encrypted", f"{r['config'].get('Size')} GB {r['config'].get('VolumeType')}")
    return None


def _ebs_default_off(r, node, src, ctx):
    if r["service"] != "ec2" or r["id"] != "ebs-encryption-by-default" or not ctx.region_has(r["region"], {"instance", "volume"}):
        return NA
    if r["config"].get("Enabled"):
        return None
    return _hit("medium", f"EBS encryption by default is off in {r['region']}", "new volumes are not encrypted unless asked")


def _rds_unencrypted(r, node, src, ctx):
    if not r["config"].get("StorageEncrypted"):
        return _hit("high", f"Database {_name(r)} is not encrypted at rest", f"engine {r['config'].get('Engine')}")
    return None


def _rds_public(r, node, src, ctx):
    if not r["config"].get("PubliclyAccessible"):
        return None
    subnets = [s.get("SubnetIdentifier") for s in (r["config"].get("DBSubnetGroup") or {}).get("Subnets", [])]
    arns = {f"arn:{r['arn'].split(':')[1]}:ec2:{r['region']}:{r['account_id']}:subnet/{s}" for s in subnets if s}
    public = any(ctx.nodes.get(a, {}).get("internet_route") is True for a in arns)
    return _hit("critical" if public else "high", f"Database {_name(r)} is publicly accessible",
                "PubliclyAccessible true" + (", in a subnet with an internet route" if public else ""))


def _http_no_redirect(r, node, src, ctx):
    if r["config"].get("Scheme") != "internet-facing":
        return NA
    plain = [x for x in r["config"].get("Listeners") or [] if x.get("Protocol") == "HTTP" and not redirects_to_https(x)]
    if plain:
        return _hit("medium", f"Load balancer {_name(r)} serves plain HTTP",
                    f"HTTP listener on port {', '.join(str(x.get('Port')) for x in plain)} does not redirect to HTTPS")
    return None


def _old_tls(r, node, src, ctx):
    if not any(x.get("Protocol") in ("HTTPS", "TLS") for x in r["config"].get("Listeners") or []):
        return NA
    old = [x for x in r["config"].get("Listeners") or [] if {"TLSv1", "TLSv1.1"} & set(x.get("SslProtocols") or [])]
    if old:
        return _hit("medium", f"Load balancer {_name(r)} allows TLS 1.0 or 1.1",
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
        return _hit(sev, f"Certificate {_name(r)} expires in {max(int(days), 0)} days",
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
            hits.append(_hit("medium", f"IAM user {row.get('user')} has old or unused access keys", "; ".join(problems),
                             **_user_ref(ctx, row)))
    return len(users), hits


def _no_mfa(ctx: Ctx) -> tuple[int, list[Hit]]:
    rows = _report_rows(ctx)
    if rows is None:
        return 0, []
    users = [r for r in rows if r.get("user") != "<root_account>" and r.get("password_enabled") == "true"]
    return len(users), [_hit("high", f"IAM user {r.get('user')} can sign in without MFA", "console password, no MFA device",
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
    return 1, [_hit("critical", "Root user is not secured", ", ".join(problems), resource=None,
                    resource_name="root user", region=GLOBAL)]


def _no_trail(ctx: Ctx) -> tuple[int, list[Hit]]:
    if not ctx.unit_ok("cloudtrail", "trail", GLOBAL):
        return 0, []
    good = [t for t in ctx.by_type["trail"] if t["config"].get("IsMultiRegionTrail") and t["config"].get("IsLogging")]
    if good:
        return 1, []
    return 1, [_hit("high", "No multi-Region CloudTrail trail is logging",
                    f"{len(ctx.by_type['trail'])} trail(s), none multi-Region and logging",
                    resource=None, resource_name="account", region=GLOBAL)]


def _no_flow_logs(r, node, src, ctx):
    if not any(_running(i) for i in ctx.by_type["instance"] if ctx.vpc_of(i) == r["arn"]):
        return NA
    logged = {t for f in ctx.by_type["flow-log"] for t in ctx.linked("logs", f["arn"])}
    subnets = [s for s in ctx.linked("contains", r["arn"]) if ctx.res.get(s, {}).get("type") == "subnet"]
    if r["arn"] in logged or (subnets and all(s in logged for s in subnets)):
        return None
    return _hit("low", f"VPC {_name(r)} has no flow log", "no flow log on the VPC or on all of its subnets")


def _guardduty_off(r, node, src, ctx):
    if r["service"] != "guardduty" or r["id"] != "guardduty" or \
            not ctx.region_has(r["region"], {"instance", "function", "db-instance"}):
        return NA
    if any(d.get("Status") == "ENABLED" for d in r["config"].get("Detectors", [])):
        return None
    return _hit("medium", f"GuardDuty is not enabled in {r['region']}", "no detector with status ENABLED")


# ---------------------------------------------------------------- spec 12: cost


def _cost_hit(title: str, detail: str, saving: float | None) -> Hit:
    return _hit(severity_for_saving(saving) if saving is not None else "low", title, detail,
                savings_usd=round(saving, 2) if saving is not None else None)


def _unattached_volume(r, node, src, ctx):
    if r["config"].get("State") != "available":
        return None
    price = EBS_GB_MONTH.get(r["config"].get("VolumeType") or "")
    size = r["config"].get("Size") or 0
    return _cost_hit(f"Volume {_name(r)} is not attached", f"{size} GB {r['config'].get('VolumeType')}, still charged",
                     size * price if price is not None else None)


def _gp2(r, node, src, ctx):
    if r["config"].get("State") == "available":
        return NA  # an unattached volume is COST-EBS-001: deleting it saves more
    if r["config"].get("VolumeType") != "gp2":
        return None
    size = r["config"].get("Size") or 0
    return _cost_hit(f"Volume {_name(r)} is gp2", f"{size} GB; gp3 is cheaper per GB",
                     size * (EBS_GB_MONTH["gp2"] - EBS_GB_MONTH["gp3"]))


def _old_snapshot(r, node, src, ctx):
    age = ctx.days_since(r["config"].get("StartTime"))
    if age is None or snapshot_manager(r["config"]):
        return NA  # no date, or AWS Backup / DLM manage its life
    if age <= SNAPSHOT_OLD_DAYS:
        return None
    size = r["config"].get("VolumeSize") or 0
    return _cost_hit(f"Snapshot {_name(r)} is {int(age)} days old", f"{size} GB, not made by AWS Backup or DLM; "
                     "saving is an upper bound (snapshots are incremental)", size * SNAPSHOT_GB_MONTH)


def _idle_eip(r, node, src, ctx):
    c = r["config"]
    if c.get("AssociationId") or c.get("InstanceId") or c.get("NetworkInterfaceId"):
        return None
    return _cost_hit(f"Elastic IP {_name(r)} is not in use", "public IPv4 addresses are charged when idle",
                     PUBLIC_IPV4_HOUR * HOURS_A_MONTH)


def _nat_without_endpoints(r, node, src, ctx):
    if r["config"].get("State") != "available":
        return NA
    vpc = ctx.vpc_of(r)
    endpoints = [e for e in ctx.by_type["vpc-endpoint"] if vpc and vpc in ctx.linking("contains", e["arn"])]
    if any(e["config"].get("VpcEndpointType") == "Gateway" and str(e["config"].get("ServiceName", "")).endswith((".s3", ".dynamodb"))
           for e in endpoints):
        return None
    return _hit("low", f"NAT gateway {_name(r)} has no S3 or DynamoDB gateway endpoint beside it",
                "traffic to S3 and DynamoDB goes through the NAT gateway and pays its data charge", savings_usd=None)


def _low_coverage(ctx: Ctx) -> tuple[int, list[Hit]]:
    cov = ctx.extras.get("cost_coverage")
    if not cov or cov.get("savings_plans_pct") is None:
        return 0, []
    sp, ri, od = cov["savings_plans_pct"], cov.get("reservations_pct"), cov.get("on_demand_usd") or 0
    if sp < COVERAGE_MIN_PCT and (ri is None or ri < COVERAGE_MIN_PCT) and od > COVERAGE_MIN_ON_DEMAND:
        return 1, [_hit("medium", "Most eligible compute is on demand",
                        f"Savings Plans cover {sp}% and RIs {ri if ri is not None else 'n/a'}%; ${od:,.2f} on demand in {cov.get('days')} days",
                        resource=None, resource_name="account", region=GLOBAL, savings_usd=None)]
    return 1, []


# ---------------------------------------------------------------- spec 12: availability


def _single_az(ctx: Ctx) -> tuple[int, list[Hit]]:
    hits: list[Hit] = []
    checked = 0
    groups: dict[tuple[str, str, str], list[Resource]] = defaultdict(list)
    for i in ctx.by_type["instance"]:
        if not _running(i):
            continue
        if app := ctx.app_of(i):
            groups[(i["region"], ctx.vpc_of(i) or "no VPC", app)].append(i)
        elif not ctx.in_asg(i["arn"]) and not ctx.is_target(i["arn"]):
            checked += 1
            hits.append(_hit("medium" if ctx.is_prod(i) else "low", f"Instance {_name(i)} runs alone",
                             f"one instance in {_az(i)}, not in an Auto Scaling group or behind a load balancer",
                             resource=i["arn"], resource_name=_name(i), region=i["region"]))
    for (region, vpc, app), members in sorted(groups.items()):
        checked += 1
        azs = sorted({_az(m) or "?" for m in members})
        if len(azs) == 1:
            prod = any(ctx.is_prod(m) for m in members)
            vpc_name = _name(ctx.res[vpc]) if vpc in ctx.res else vpc
            hits.append(_hit("high" if prod else "medium", f"App {app} runs in one Availability Zone",
                             f"{len(members)} instance(s), all in {azs[0]}", resource=None,
                             resource_name=f"app {app} ({vpc_name})", region=region))
    for tg in ctx.by_type["target-group"]:
        azs = {_az(ctx.res[t]) for t in ctx.linked("targets", tg["arn"]) if t in ctx.res}
        if not azs:
            continue
        checked += 1
        if len(azs) == 1:
            hits.append(_hit("high" if ctx.is_prod(tg) else "medium", f"Target group {_name(tg)} has targets in one AZ",
                             f"all targets in {next(iter(azs))}", resource=tg["arn"], resource_name=_name(tg),
                             region=tg["region"]))
    return checked, hits


def _rds_single_az(r, node, src, ctx):
    if r["config"].get("DBClusterIdentifier"):
        return NA  # Aurora is judged by its cluster, not collected yet (Phase E)
    if r["config"].get("MultiAZ"):
        return None
    return _hit("high" if ctx.is_prod(r) else "low", f"Database {_name(r)} is not Multi-AZ",
                f"single instance in {r['config'].get('AvailabilityZone')}")


def _one_az(r, node, src, ctx):
    zones = r["config"].get("AvailabilityZones") or []
    names = sorted(n for z in zones if (n := z.get("ZoneName") if isinstance(z, dict) else z))
    if not names:
        return NA
    if len(names) == 1:
        kind = "Load balancer" if r["type"] == "load-balancer" else "Auto Scaling group"
        return _hit("high", f"{kind} {_name(r)} uses one Availability Zone", f"only {names[0]}")
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
        return _hit("medium", f"NAT gateway {_name(r)} serves {len(azs)} Availability Zones",
                    f"private subnets in {', '.join(azs)} lose internet access if its AZ fails")
    return None


def _no_healing(r, node, src, ctx):
    if not _running(r) or ctx.in_asg(r["arn"]):
        return NA  # an ASG replaces its instances
    if (r["config"].get("MaintenanceOptions") or {}).get("AutoRecovery") != "disabled":
        return None
    if (src["cloudwatch"].get(r["arn"]) or {}).get("recover_alarm"):
        return None
    return _hit("medium", f"Instance {_name(r)} has no automatic recovery",
                "AutoRecovery disabled, not in an Auto Scaling group, no recover alarm")


def _ec2_health_check(r, node, src, ctx):
    if not r["config"].get("TargetGroupARNs"):
        return NA
    if r["config"].get("HealthCheckType") == "EC2":
        return _hit("low", f"Auto Scaling group {_name(r)} ignores load balancer health",
                    "HealthCheckType EC2: instances failing the target group check are not replaced")
    return None


def _unhealthy_targets(r, node, src, ctx):
    if not r["config"].get("TargetHealth"):
        return NA
    bad = [t for t in r["config"].get("TargetHealth") or [] if t.get("State") == "unhealthy"]
    if bad:
        return _hit("high", f"Target group {_name(r)} has {len(bad)} unhealthy target(s)",
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
    return _hit("high" if ctx.is_prod(r) else "medium", f"{what} {_name(r)} has no recent backup",
                f"no AWS Backup recovery point or snapshot in {BACKUP_RECENT_DAYS} days")


def _no_retention(r, node, src, ctx):
    if (r["config"].get("BackupRetentionPeriod") or 0) == 0:
        return _hit("high", f"Database {_name(r)} has automated backups turned off", "BackupRetentionPeriod 0")
    return None


def _snapshot_unencrypted(r, node, src, ctx):
    if not r["config"].get("Encrypted"):
        return _hit("medium", f"Snapshot {_name(r)} is not encrypted", f"from volume {r['config'].get('VolumeId')}")
    return None


# ---------------------------------------------------------------- registry


def _hub_enabled(ctx: Ctx) -> bool:
    return "costhub" in ctx.loaded


def rules(required_tags: tuple[str, ...]) -> list[Rule | GroupRule]:
    inv = ("inventory",)
    return [
        # spec 08
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
        # spec 12: security
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
        # spec 12: cost
        Rule("COST-EBS-001", "COST04-BP03", inv, {"volume"}, _unattached_volume, "Snapshot it if needed, then delete the volume."),
        Rule("COST-EBS-002", "COST06-BP02", inv, {"volume"}, _gp2, "aws ec2 modify-volume --volume-id <id> --volume-type gp3 (no downtime)."),
        Rule("COST-SNAP-001", "COST04-BP05", inv, {"snapshot"}, _old_snapshot,
             "Delete it if not needed, or manage snapshots with Data Lifecycle Manager or AWS Backup."),
        Rule("COST-EIP-001", "COST04-BP03", inv, {"elastic-ip"}, _idle_eip, "Release the Elastic IP if nothing needs it."),
        Rule("COST-NAT-001", "COST08-BP02", inv, {"nat-gateway"}, _nat_without_endpoints,
             "Add S3 and DynamoDB gateway endpoints to the VPC (no hourly charge).", units=(("ec2", "vpc-endpoint"),)),
        GroupRule("COST-COV-001", "COST07-BP04", inv + ("cost",), _low_coverage,
                  "Review the Savings Plans recommendation in Cost Explorer and buy a small commitment first."),
        # spec 12: availability
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


# ---------------------------------------------------------------- engine


def run(snapshot: Snapshot, nodes: dict[str, dict[str, Any]], sources: Sources,
        required_tags: tuple[str, ...] = DEFAULT_REQUIRED_TAGS, extras: dict[str, Any] | None = None,
        today: date | None = None, env_tag: str = DEFAULT_ENV_TAG, app_tag: str = DEFAULT_APP_TAG) -> Parsed:
    """sources: data per loaded source (ARN -> data). 'inventory' is always loaded.
    extras: cost_coverage (from the cost summary). today: defaults to the snapshot's date."""
    loaded = {"inventory", *sources}
    src: Sources = {k: sources.get(k, {}) for k in ("wazuh", "prometheus", "cloudwatch", "ansible")}
    day = today or date.fromisoformat(snapshot["collected_at"][:10])
    ctx = Ctx(snapshot, nodes, src, loaded, extras or {}, day, env_tag, app_tag)
    out = empty_parsed()
    for rule in rules(required_tags):
        if not set(rule.needs) <= loaded:
            continue
        source = "inventory" if rule.needs == ("inventory",) else "hygiene"
        found: list[Hit] = []
        if isinstance(rule, GroupRule):
            checked, found = rule.run(ctx)
        else:
            if rule.when and not rule.when(ctx):
                continue
            checked = 0
            for r in snapshot["resources"]:
                if r["type"] not in rule.types:
                    continue
                if any(not ctx.unit_ok(svc, t, r["region"]) for svc, t in rule.units):
                    continue
                hit = rule.check(r, nodes.get(r["arn"], {}), src, ctx)
                if hit == NA:
                    continue
                checked += 1
                if hit is not None:
                    found.append({**hit, "resource": r["arn"], "resource_name": _name(r), "region": r["region"]})  # type: ignore[typeddict-item]
        for h in found:
            f: Finding = make(source, rule.id, h["title"], h["severity"], [rule.bp], h.get("resource"),
                              h.get("resource_name", "?"), h.get("region", GLOBAL), h.get("detail", ""),
                              h.get("remediation") or rule.remediation, savings_usd=h.get("savings_usd"))
            out["findings"].append(f)
        if checked:
            if found:
                cover(out["coverage"], [rule.bp], failed=True, n=len(found))
            if checked > len(found):
                cover(out["coverage"], [rule.bp], n=checked - len(found))
    return out
