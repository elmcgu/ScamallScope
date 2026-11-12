"""The rules engine: context over one snapshot, rule types and helpers (specs 08 and 12).

A rule runs only when all its inputs are loaded, and checks a resource only when the units it
needs collected without error. A check returns a hit (failed), None (passed) or NA (not
applicable). A rule that judged nothing covers nothing on the scorecard, so its best practice
stays "not checked" rather than "clear".
"""

from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timezone
from typing import Any, Callable, Final, Literal, TypedDict

from ..findings import Severity
from ..model import Resource, Snapshot

DEFAULT_REQUIRED_TAGS = ("owner", "env")
DEFAULT_ENV_TAG, DEFAULT_APP_TAG = "env", "app"  # tag keys; set per estate with --env-tag and --app-tag
PROD_VALUES = {"prod", "production", "prd"}

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


def state_of(r: Resource) -> str | None:
    return (r["config"].get("State") or {}).get("Name") if r["type"] == "instance" else r["config"].get("State")


def is_running(r: Resource) -> bool:
    return r["type"] == "instance" and state_of(r) == "running"


def name_of(r: Resource) -> str:
    return r.get("name") or r["id"]


def az_of(r: Resource) -> str | None:
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


def hit(severity: str, title: str, detail: str = "", **extra: Any) -> Hit:
    return {"severity": severity, "title": title, "detail": detail, **extra}  # type: ignore[typeddict-item]
