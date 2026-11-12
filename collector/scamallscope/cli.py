"""Command line: scamallscope collect | graph | inventory | changes | history | fetch | enrich."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from . import enrich, graph, httpjson, inventory, rules, snapshot
from .integrations import cloudwatch, cost, costhub, github, prometheus, wazuh
from .model import is_complete


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scamallscope")
    sub = parser.add_subparsers(dest="command", required=True)

    c = sub.add_parser("collect", help="Collect resources and write a JSON snapshot")
    c.add_argument("--profile", help="AWS profile (default: normal boto3 lookup)")
    c.add_argument("--region", action="append", dest="regions",
                   help="Region to collect; repeat for more (default: profile region)")
    c.add_argument("--output", type=Path,
                   help="Output file (default: snapshots/<account>-<UTC time>.snapshot.json)")

    g = sub.add_parser("graph", help="Convert a snapshot to graph JSON for the frontend")
    g.add_argument("snapshot", type=Path, help="Snapshot file from 'collect'")
    g.add_argument("--output", type=Path, help="Output file (default: <snapshot>.graph.json)")

    def table_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--table", required=True, help="DynamoDB table name (infra/inventory-table.yaml)")
        p.add_argument("--profile", help="AWS profile for DynamoDB (default: normal boto3 lookup)")
        p.add_argument("--region", help="Region of the table (default: profile region)")

    i = sub.add_parser("inventory", help="Update the DynamoDB inventory from a snapshot")
    i.add_argument("snapshot", type=Path, help="Snapshot file from 'collect'")
    table_args(i)

    ch = sub.add_parser("changes", help="List the changes recorded on one day")
    ch.add_argument("--date", required=True, help="YYYY-MM-DD (UTC)")
    table_args(ch)

    h = sub.add_parser("history", help="List the change history of one resource")
    h.add_argument("--arn", required=True)
    table_args(h)

    e = sub.add_parser("enrich", help="Build graph JSON v2 from a snapshot and integration files")
    e.add_argument("snapshot", type=Path, help="Snapshot file from 'collect'")
    e.add_argument("--integrations", type=Path, default=Path("integrations"),
                   help="Folder with raw integration files (default: integrations/)")
    e.add_argument("--required-tags", default="owner,env", help="Comma-separated tags every resource needs")
    e.add_argument("--env-tag", default=rules.DEFAULT_ENV_TAG,
                   help="Tag key that holds the environment; prod, production or prd (or no tag) is prod (default env)")
    e.add_argument("--app-tag", default=rules.DEFAULT_APP_TAG,
                   help="Tag key that groups instances into one workload (default app)")
    e.add_argument("--ansible-mode", choices=["check", "apply"], default="check",
                   help="Was the Ansible run in check mode (default) or a real apply?")
    e.add_argument("--output", type=Path, help="Output file (default: <snapshot>.graph.json)")

    f = sub.add_parser("fetch", help="Fetch raw data from an integration into integrations/<source>.json")
    f.add_argument("source", choices=["wazuh", "github", "cloudwatch", "prometheus", "cost", "costhub"])
    f.add_argument("--snapshot", type=Path, help="Snapshot (needed by github and cloudwatch)")
    f.add_argument("--url", help="wazuh: server API URL (https://host:55000); prometheus: base URL")
    f.add_argument("--indexer-url", help="wazuh: indexer URL (https://host:9200)")
    f.add_argument("--ca-file", help="Extra CA certificate file for TLS (verification is always on)")
    f.add_argument("--profile", help="AWS profile (cloudwatch, cost, costhub)")
    f.add_argument("--tag-key", default="env", help="cost: cost allocation tag to group by (default env)")
    f.add_argument("--output-dir", type=Path, default=Path("integrations"))

    args = parser.parse_args(argv)
    commands = {"collect": _collect, "graph": _graph, "inventory": _inventory,
                "changes": _changes, "history": _history, "enrich": _enrich, "fetch": _fetch}
    return commands[args.command](args)


def _table(args: argparse.Namespace) -> Any:
    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    dynamodb: Any = session.resource("dynamodb")  # boto3's own hints do not cover resources
    return dynamodb.Table(args.table)


def _inventory(args: argparse.Namespace) -> int:
    snap = json.loads(args.snapshot.read_text(encoding="utf-8"))
    run = inventory.apply(_table(args), snap)
    print(f"{run['created']} created, {run['changed']} changed, {run['deleted']} deleted, "
          f"{run['unchanged']} unchanged ({run['resources']} resources)")
    if not is_complete(snap):
        print("Snapshot is partial: resources in failed units were kept, not marked deleted", file=sys.stderr)
        return 2
    return 0


def _print_changes(items: list[dict]) -> None:
    for c in items:
        fields = f" [{', '.join(c['changed_fields'])}]" if c.get("changed_fields") else ""
        print(f"{c['at']}  {c['kind']:<8} {c['region']:<12} {c['type']:<16} {c.get('name') or '-':<20} {c['arn']}{fields}")


def _changes(args: argparse.Namespace) -> int:
    items = inventory.changes_on(_table(args), args.date)
    _print_changes(items)
    print(f"{len(items)} changes on {args.date}")
    return 0


def _history(args: argparse.Namespace) -> int:
    items = inventory.history(_table(args), args.arn)
    _print_changes(items)
    if not items:
        print("No changes recorded for this ARN")
    return 0


def _graph(args: argparse.Namespace) -> int:
    data = json.loads(args.snapshot.read_text(encoding="utf-8"))
    result = graph.to_graph(data)
    name = args.snapshot.name.removesuffix(".json").removesuffix(".snapshot")
    out = args.output or args.snapshot.with_name(f"{name}.graph.json")
    snapshot.write_json(result, out)

    meta = result["meta"]
    nodes = sum(1 for e in result["elements"] if e["group"] == "nodes")
    print(f"{nodes} nodes, {len(result['elements']) - nodes} edges -> {out}")
    if meta["dropped_edges"]:
        print(f"Dropped {meta['dropped_edges']} edges to resources not in the snapshot", file=sys.stderr)
    if not meta["complete"]:
        print(f"Snapshot is partial: {len(meta['failed_units'])} failed units", file=sys.stderr)
        return 2
    return 0


def _collect(args: argparse.Namespace) -> int:
    session = boto3.Session(profile_name=args.profile)
    regions = args.regions or ([session.region_name] if session.region_name else [])
    if not regions:
        print("No region. Use --region or set one in your AWS profile.", file=sys.stderr)
        return 1

    try:
        snap = snapshot.collect(session, regions)
    except (ClientError, BotoCoreError) as exc:  # no or expired credentials: sts:GetCallerIdentity fails first
        print(f"Cannot identify the AWS account: {exc}", file=sys.stderr)
        return 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.output or Path("snapshots") / f"{snap['account_id']}-{stamp}.snapshot.json"
    snapshot.write_json(snap, out)

    for u in snap["units"]:
        detail = f"{u['count']}" if u["status"] == "ok" else u["error"]
        print(f"{u['region']:<15} {u['service']}:{u['resource_type']:<15} {u['status']:<6} {detail}")
    print(f"{len(snap['resources'])} resources, {len(snap['links'])} links -> {out}")

    # Exit 2 on a partial snapshot so a scheduler can tell it apart from success.
    return 0 if is_complete(snap) else 2


def _enrich(args: argparse.Namespace) -> int:
    try:
        snap = json.loads(args.snapshot.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read snapshot: {exc}", file=sys.stderr)
        return 1
    tags = tuple(t.strip() for t in args.required_tags.split(",") if t.strip())
    g = enrich.build(snap, enrich.load_raw(args.integrations), tags, args.ansible_mode,
                     env_tag=args.env_tag, app_tag=args.app_tag)
    name = args.snapshot.name.removesuffix(".json").removesuffix(".snapshot")
    out = args.output or args.snapshot.with_name(f"{name}.graph.json")
    snapshot.write_json(g, out)
    for source, m in g["meta"]["integrations"].items():
        if m.get("loaded"):
            extra = f", unmatched: {', '.join(m['unmatched'])}" if m["unmatched"] else ""
            print(f"{source:<11} loaded   {m['findings']} findings, {m['matched']} matched{extra}")
        else:
            print(f"{source:<11} {'ERROR ' + m['error'] if m.get('error') else 'not loaded'}")
    sev = {s: sum(1 for x in g["findings"] if x["severity"] == s) for s in ("critical", "high", "medium", "low", "info")}
    print(f"{len(g['findings'])} findings ({', '.join(f'{n} {s}' for s, n in sev.items())}) -> {out}")
    for pillar, p in g["posture"].items():
        s = p["summary"]
        print(f"  {pillar:<12} {s['issues']} with issues, {s['clear']} clear, {s['not_checked']} not checked")
    return 2 if enrich.failed_sources(g) or not g["meta"]["complete"] else 0


def _env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Set {name} in the environment (credentials are never taken as arguments)")
    return value


def _fetch(args: argparse.Namespace) -> int:
    snap = json.loads(args.snapshot.read_text(encoding="utf-8")) if args.snapshot else None
    if args.source in ("github", "cloudwatch") and snap is None:
        print(f"{args.source} needs --snapshot", file=sys.stderr)
        return 1
    try:
        if args.source == "wazuh":
            if not args.url or not args.indexer_url:
                print("wazuh needs --url and --indexer-url", file=sys.stderr)
                return 1
            raw = wazuh.fetch(args.url, args.indexer_url, _env("WAZUH_API_USER"), _env("WAZUH_API_PASSWORD"),
                              _env("WAZUH_INDEXER_USER"), _env("WAZUH_INDEXER_PASSWORD"), args.ca_file)
        elif args.source == "github":
            repos = github.repos_from_snapshot(snap)  # type: ignore[arg-type]
            if not repos:
                print(f"No resources tagged {github.REPO_TAG}; nothing to fetch", file=sys.stderr)
                return 1
            raw = github.fetch(repos, _env("GITHUB_TOKEN"))
        elif args.source == "prometheus":
            if not args.url:
                print("prometheus needs --url", file=sys.stderr)
                return 1
            raw = prometheus.fetch(args.url, os.environ.get("PROMETHEUS_BEARER_TOKEN"), args.ca_file)
        elif args.source == "cloudwatch":
            raw = cloudwatch.fetch(boto3.Session(profile_name=args.profile), snap)  # type: ignore[arg-type]
        elif args.source == "costhub":
            raw = costhub.fetch(boto3.Session(profile_name=args.profile))
        else:
            raw = cost.fetch(boto3.Session(profile_name=args.profile), args.tag_key)
    except (httpjson.HttpError, ValueError, ClientError, BotoCoreError) as exc:
        print(f"{args.source}: {exc}", file=sys.stderr)
        return 1
    out = args.output_dir / f"{args.source}.json"
    snapshot.write_json(raw, out)
    print(f"{args.source} -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
