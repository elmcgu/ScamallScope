# scamallscope collector

Read-only AWS collector. It writes a JSON snapshot of resources and the links between them.

## Run

```bash
cd collector
uv sync
uv run scamallscope collect --profile <read-only-profile> --region eu-west-1
uv run pytest
```

The snapshot goes to `snapshots/` (git-ignored) with mode `0600`. Exit code `0` = all units
collected, `2` = partial snapshot (see the `units` list for errors).

## Permissions

Only these read-only actions:

- `sts:GetCallerIdentity`
- `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`

## Snapshot shape

- `units`: one entry per (service, resource type, region), `status` `ok` or `error`. A unit with
  `error` means "unknown", never "nothing there".
- `resources`: `arn`, `account_id`, `region`, `service`, `type`, `id`, `name`, `tags`, `config` (raw API item).
- `links`: `source` ARN, `target` ARN, `type` (`contains` or `uses`).
