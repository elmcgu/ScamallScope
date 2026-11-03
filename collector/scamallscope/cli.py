"""Command line: scamallscope collect."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3

from . import graph, snapshot


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

    args = parser.parse_args(argv)
    return _collect(args) if args.command == "collect" else _graph(args)


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
    out = args.output or Path("snapshots") / f"{snap.account_id}-{stamp}.snapshot.json"
    snapshot.write(snap, out)

    for u in snap.units:
        detail = f"{u.count}" if u.status == "ok" else u.error
        print(f"{u.region:<15} {u.service}:{u.resource_type:<15} {u.status:<6} {detail}")
    print(f"{len(snap.resources)} resources, {len(snap.links)} links -> {out}")

    # Exit 2 on a partial snapshot so a scheduler can tell it apart from success.
    return 0 if snap.ok else 2


if __name__ == "__main__":
    sys.exit(main())
