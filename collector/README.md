# scamallscope collector

Read-only AWS collector. It writes a JSON snapshot of resources and the links between them.

## Run

```bash
cd collector
uv sync
uv run scamallscope collect --profile <read-only-profile> --region eu-west-1
uv run scamallscope graph snapshots/<file>.snapshot.json   # -> <file>.graph.json
uv run pytest
```

The snapshot goes to `snapshots/` (git-ignored) with mode `0600`. Exit code `0` = all units
collected, `2` = partial snapshot (see the `units` list for errors).

## Permissions

Only these read-only actions:

- `sts:GetCallerIdentity`
- `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`
- `ec2:DescribeRouteTables`, `ec2:DescribeInternetGateways`

## Snapshot shape

- `units`: one entry per (service, resource type, region), `status` `ok` or `error`. A unit with
  `error` means "unknown", never "nothing there".
- `resources`: `arn`, `account_id`, `region`, `service`, `type`, `id`, `name`, `tags`, `config` (raw API item).
- `links`: `source` ARN, `target` ARN, `type` (`contains`, `uses`, `attached`, `routes`, `routes_to`).

## Graph JSON

`scamallscope graph` converts a snapshot into Cytoscape.js `elements` for the frontend.
Nodes keep only the fields the views need (no raw config, no IP addresses). Edges to a
resource that is not in the snapshot are dropped and counted in `meta.dropped_edges`.
`meta.complete` is false, and the exit code is `2`, when the snapshot is partial.

## Internet exposure

Each instance node in the graph has `exposure` (`exposed`, `not_exposed` or `unknown`),
`exposure_reason` and `exposed_ports`. A port is exposed when, on the same network interface:

1. the interface has a public IPv4 or IPv6 address,
2. its subnet's route table (or the VPC main table) has `0.0.0.0/0` or `::/0` to an
   internet gateway attached to the VPC, and
3. one of its security groups allows inbound traffic from `0.0.0.0/0` or `::/0`.

`unknown` means a collection unit the check needs failed. Not checked yet: network ACLs,
prefix lists, split default routes, load balancers.
