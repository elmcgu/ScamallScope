"""Command line: scamallscope collect | graph | inventory | changes | history."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3

from . import graph, inventory, snapshot
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

    args = parser.parse_args(argv)
    commands = {"collect": _collect, "graph": _graph, "inventory": _inventory,
                "changes": _changes, "history": _history}
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

    snap = snapshot.collect(session, regions)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = args.output or Path("snapshots") / f"{snap['account_id']}-{stamp}.snapshot.json"
    snapshot.write_json(snap, out)

    for u in snap["units"]:
        detail = f"{u['count']}" if u["status"] == "ok" else u["error"]
        print(f"{u['region']:<15} {u['service']}:{u['resource_type']:<15} {u['status']:<6} {detail}")
    print(f"{len(snap['resources'])} resources, {len(snap['links'])} links -> {out}")

    # Exit 2 on a partial snapshot so a scheduler can tell it apart from success.
    return 0 if is_complete(snap) else 2


if __name__ == "__main__":
    sys.exit(main())
