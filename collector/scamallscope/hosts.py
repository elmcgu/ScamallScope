"""Match host names from other tools (Wazuh, Ansible, Prometheus) to EC2 instances.

A name that fits more than one instance is not matched: a wrong match is worse than none.
"""

from __future__ import annotations

from typing import TypedDict

from .model import Snapshot

HOST_TAG = "scamallscope:host"


class Index(TypedDict):
    keys: dict[str, set[str]]  # lower-case name -> instance ARNs
    instances: dict[str, str]  # instance id -> ARN


def _short(name: str) -> str:
    """'web-1.example.internal' -> 'web-1'; 'web-1:9100' -> 'web-1'. Instance ids have no dots."""
    return name.strip().lower().split(":")[0].split(".")[0]


def build(snapshot: Snapshot) -> Index:
    keys: dict[str, set[str]] = {}
    instances: dict[str, str] = {}
    for r in snapshot["resources"]:
        if r["type"] != "instance":
            continue
        instances[r["id"]] = r["arn"]
        names = {r["id"], r["tags"].get("Name", ""), r["tags"].get(HOST_TAG, ""),
                 str(r["config"].get("PrivateDnsName") or "")}
        for n in names:
            if n:
                keys.setdefault(_short(n), set()).add(r["arn"])
    return {"keys": keys, "instances": instances}


def match(index: Index, name: str | None) -> str | None:
    if not name:
        return None
    for candidate in (name.strip().lower(), _short(name)):
        arns = index["keys"].get(candidate)
        if arns:
            return next(iter(arns)) if len(arns) == 1 else None
    return None


def by_instance_id(index: Index, instance_id: str | None) -> str | None:
    return index["instances"].get(instance_id or "")
