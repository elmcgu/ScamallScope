"""Snapshot + raw integration files -> graph JSON v2 (decision 0002, spec 09). No network here."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from . import availability, graph, hosts, hygiene, posture, rank
from .findings import Coverage, Finding, Parsed, counts
from .integrations import ansible, cloudwatch, cost, costhub, github, prometheus, prowler, wazuh
from .model import Snapshot

GRAPH_SCHEMA_VERSION = 2
NODE_KEYS = {"wazuh": "wazuh", "github": "deploy", "ansible": "config_run", "cloudwatch": "metrics",
             "prometheus": "metrics", "cost": "cost"}
SOURCES = ("prowler", "wazuh", "github", "ansible", "cloudwatch", "prometheus", "cost", "costhub")


def _read(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_raw(folder: Path | None) -> dict[str, Any]:
    """Raw files present in the folder. Prowler may have several files."""
    raw: dict[str, Any] = {}
    if not folder or not folder.is_dir():
        return raw
    prowler_files = sorted(folder.glob("prowler*.json"))
    if prowler_files:
        raw["prowler"] = {p.name: p for p in prowler_files}
    for source in SOURCES[1:]:
        p = folder / f"{source}.json"
        if p.is_file():
            raw[source] = p
    return raw


def _parse(source: str, value: Any, snap: Snapshot, index: hosts.Index, known: set[str],
           ansible_mode: ansible.Mode, today: date | None) -> tuple[Parsed, dict[str, Any] | None]:
    if source == "prowler":
        return prowler.parse({name: _read(p) for name, p in value.items()}, snap["account_id"], known), None
    data = _read(value)
    if source == "wazuh":
        return wazuh.parse(data, index), None
    if source == "github":
        return github.parse(data, snap), None
    if source == "ansible":
        return ansible.parse(data, index, ansible_mode), None
    if source == "cloudwatch":
        return cloudwatch.parse(data, index), None
    if source == "prometheus":
        return prometheus.parse(data, index), None
    if source == "cost":
        return cost.parse(data, index, today)
    if source == "costhub":
        return costhub.parse(data, known), {"enabled": bool(data.get("enabled")),
                                            "compute_optimizer": data.get("compute_optimizer")}
    raise ValueError(source)


def build(snap: Snapshot, raw: dict[str, Any], required_tags: tuple[str, ...] = hygiene.DEFAULT_REQUIRED_TAGS,
          ansible_mode: ansible.Mode = "check", today: date | None = None) -> dict[str, Any]:
    g = graph.to_graph(snap)
    nodes = {e["data"]["id"]: e["data"] for e in g["elements"] if e["group"] == "nodes"}
    index = hosts.build(snap)
    known = set(nodes)

    findings: list[Finding] = []
    coverage: dict[str, dict[str, Coverage]] = {}
    per_source: dict[str, dict[str, dict[str, Any]]] = {}
    meta: dict[str, Any] = {}
    cost_summary: dict[str, Any] | None = None
    for source in SOURCES:
        if source not in raw:
            meta[source] = {"loaded": False}
            continue
        try:
            parsed, extra = _parse(source, raw[source], snap, index, known, ansible_mode, today)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            meta[source] = {"loaded": False, "error": f"{type(exc).__name__}: {exc}"[:300]}
            continue
        if source == "cost":
            cost_summary = extra
        findings.extend(parsed["findings"])
        coverage[source] = parsed["coverage"]
        per_source[source] = parsed["resources"]
        matched = len(parsed["resources"]) or len({f["resource"] for f in parsed["findings"] if f["resource"]})
        meta[source] = {"loaded": True, "findings": len(parsed["findings"]), "matched": matched,
                        "unmatched": sorted(set(parsed["unmatched"])), "notes": parsed["notes"]}
        if source == "costhub" and extra:
            meta[source].update(extra)

    # costhub counts as loaded for the rules only when the hub is enabled (decision 0003).
    rule_sources = {k: v for k, v in per_source.items()
                    if k != "cost" and not (k == "costhub" and not meta.get("costhub", {}).get("enabled"))}
    if "cost" in per_source:
        rule_sources["cost"] = {}
    extras = {"cost_coverage": (cost_summary or {}).get("coverage")}
    rules = hygiene.run(snap, nodes, rule_sources, required_tags, extras, today)
    findings.extend(rules["findings"])
    coverage["hygiene"] = rules["coverage"]

    # One finding per id (a source may report the same thing twice).
    unique: dict[str, Finding] = {}
    for f in findings:
        unique.setdefault(f["id"], f)
    findings = sorted(unique.values(), key=lambda f: f["id"])
    for f in findings:  # show the same name as the map does
        if f["resource"] in nodes:
            f["resource_name"] = nodes[f["resource"]]["label"]

    for source, resources in per_source.items():
        key = NODE_KEYS.get(source)
        if not key:
            continue
        for arn, data in resources.items():
            if arn in nodes:
                nodes[arn].setdefault(key, {}).update(data)
    summary = rank.apply(findings, nodes)
    by_resource: dict[str, list[Finding]] = {}
    for f in findings:
        if f["resource"] and not f["duplicate_of"]:  # the map counts each issue once, like the Overview
            by_resource.setdefault(f["resource"], []).append(f)
    for arn, node in nodes.items():
        node["finding_counts"] = counts(by_resource.get(arn, []))
        node["finding_counts_by_pillar"] = {p: counts([f for f in by_resource.get(arn, []) if f["pillar"] == p])
                                            for p in ("security", "cost", "reliability")}

    if cost_summary is not None:
        idle = {f["resource"] for f in findings if f["check_id"] in ("HYG-EC2-002", "COST-HUB-Stop")
                and not f["duplicate_of"]}
        cost_summary["idle_monthly_usd"] = round(sum(
            (nodes[a].get("cost") or {}).get("monthly_usd", 0) for a in idle if a in nodes), 2)
        top = sorted(((n.get("cost") or {}).get("monthly_usd", 0), n["label"], arn) for arn, n in nodes.items()
                     if (n.get("cost") or {}).get("monthly_usd"))
        cost_summary["top_resources"] = [{"arn": a, "label": label, "monthly_usd": v} for v, label, a in reversed(top[-10:])]

    g["schema_version"] = GRAPH_SCHEMA_VERSION
    g["meta"]["integrations"] = meta
    g["findings"] = findings
    g["summary"] = summary
    g["workloads"] = availability.workloads(snap, nodes, rule_sources, findings, today)
    g["posture"] = posture.scorecard(findings, coverage)
    g["cost"] = cost_summary
    return g


def failed_sources(g: dict[str, Any]) -> list[str]:
    return [s for s, m in g["meta"]["integrations"].items() if m.get("error")]
