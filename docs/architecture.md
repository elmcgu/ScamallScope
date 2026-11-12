# Architecture

How ScamallScope is built. What it does and why: [PROJECT.md](PROJECT.md). Behaviour and tests:
[specs/](specs/). Reference numbers like [R14]: [references.md](references.md).

## Components

```
collector/scamallscope/
  cli.py             commands: collect, graph, inventory, changes, history, fetch, enrich, run
  model.py           Resource, Link, Snapshot shapes; ARNs and settings
  snapshot.py        run every collector -> snapshot dict; one unit per API listing
  collectors/        AWS read-only collectors, one module per service family
    base.py          Context, Result and the shared list helper
    ec2.py           VPCs, subnets, security groups, instances, route tables, gateways, ACLs,
                     volumes, snapshots, Elastic IPs, NAT gateways, endpoints, flow logs
    lambda_.py iam.py s3.py rds.py elbv2.py autoscaling.py
    account.py       CloudTrail, credential report, GuardDuty, Backup, SSM, ACM
  exposure.py        internet exposure of instances, buckets and functions
  network_acl.py     network ACL evaluation for exposure
  iam_analysis.py    admin principals
  graph.py           snapshot -> graph elements for the map
  inventory.py       DynamoDB current state + change log
  findings.py        Finding shape, severity, Well-Architected catalogue
  data/well_architected.json   177 SEC, REL and COST best practices
  hosts.py           match host names from other tools to EC2 instances
  httpjson.py        small JSON-over-HTTPS client (urllib, TLS verified, no redirects)
  integrations/      one module per source: parse() pure, fetch() network
    prowler.py wazuh.py github.py ansible.py cloudwatch.py prometheus.py cost.py costhub.py
  rules/             rules over the inventory and loaded sources -> findings
    engine.py        Ctx, Rule, GroupRule, NA and helpers
    spec08.py security.py cost.py availability.py   one group of rules each
  rank.py            duplicates, priority, summary totals
  availability.py    workloads for the Availability view
  posture.py         Well-Architected scorecard
  enrich.py          snapshot + raw files -> graph v2
infra/
  collector-read-only-policy.json   every AWS permission the collector needs
  inventory-table.yaml              DynamoDB table for the inventory
frontend/src/
  model.js           graph data logic for the map
  views.js           data logic for Overview, Findings, Hosts, Cost, Availability, Well-Architected
  layout.js          map layout options
  icons.js           AWS Architecture Icons per node kind (optional files)
  main.js            DOM and Cytoscape
```

## Data flow

`run` does steps 1 to 3 into one folder (spec 15); each step is also its own command.

1. `collect` writes `snapshot.json`.
2. `fetch <source>` writes `integrations/<source>.json`: `{"fetched_at": ..., ...raw response...}`.
3. `enrich` does, in order:
   1. `graph.to_graph(snapshot)`: nodes, edges, exposure, admin.
   2. For each raw file present: `integrations/<source>.parse(raw, index)` returns
      `{"findings": [...], "resources": {arn: {...}}, "coverage": {...}, "unmatched": [...]}`.
   3. `rules.run(snapshot, graph nodes, loaded sources)` adds findings from rules.
   4. Exposure and admin results become findings too, so all issues are in one list.
   5. `posture.scorecard(findings, coverage)` builds the per-pillar table.
   6. `rank.apply(findings, nodes)` marks duplicates (same resource, pillar and a shared BP), sets
      `priority` and returns `summary` (spec 13). `availability.workloads(...)` builds `workloads`.
   7. Per-resource data is put on the graph node under a key per source (`wazuh`, `deploy`,
      `config_run`, `metrics`, `cost`), plus `finding_counts`.
4. The UI loads `graph.json`.

## Graph JSON, schema version 2

Version 1 plus these top-level keys. The UI accepts 1 and 2.

```jsonc
{
  "schema_version": 2,
  "meta": { "...": "as v1", "integrations": { "wazuh": { "loaded": true, "fetched_at": "...", "matched": 4, "unmatched": ["old-host"] } } },
  "elements": [ { "group": "nodes", "data": { "...": "as v1",
      "finding_counts": { "critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0 },
      "finding_counts_by_pillar": { "security": { "high": 1 }, "cost": {}, "reliability": { "medium": 2 } },
      "wazuh":      { "agent_id": "003", "status": "active", "os_name": "Ubuntu", "os_version": "22.04.4 LTS", "vulns": { "critical": 1, "high": 3, "medium": 0, "low": 2 }, "top_packages": [ { "name": "openssl", "version": "3.0.2", "count": 2 } ] },
      "deploy":     { "repo": "o/r", "environment": "production", "state": "success", "sha": "abc1234", "created_at": "...", "url": "..." },
      "config_run": { "ok": 12, "changed": 1, "failures": 0, "unreachable": 0, "mode": "check" },
      "metrics":    { "cpu_avg": 1.8, "cpu_max": 9.0, "days": 14, "alarms": 0, "prom_up": 1 },
      "cost":       { "monthly_usd": 41.2, "basis": "last 14 days x 30/14" } } } ],
  "findings": [ /* Finding, see spec 01, with savings_usd, priority, duplicate_of, also_reported_by (specs 12, 13) */ ],
  "posture":  { "security": { "best_practices": [ { "id": "SEC06-BP01", "title": "...", "url": "...", "status": "issues", "findings": 3, "checked_by": ["wazuh", "hygiene"] } ], "summary": { "issues": 4, "clear": 6, "not_checked": 47 } }, "reliability": {}, "cost": {} },
  "summary":  { "open": { "critical": 1, "high": 4, "medium": 9, "low": 6, "info": 0 }, "by_pillar": { "security": 8, "cost": 6, "reliability": 6 }, "savings_usd": 78.79, "savings_estimated": true, "single_points_of_failure": 3 },
  "workloads": [ { "id": "...", "name": "app shop-web", "kind": "app", "region": "eu-west-1", "vpc": "prod", "azs": ["eu-west-1a"], "members": ["arn:..."], "prod": true, "healing": "none", "backup": "n/a", "monitoring": "alarm", "findings": 2 } ],
  "cost":     { "currency": "USD", "months": [ { "start": "2026-08-01", "total": 120.5, "by_service": { "Amazon Elastic Compute Cloud - Compute": 80.1 } } ], "by_tag": { "key": "env", "values": { "prod": 90.0, "": 12.0 } }, "idle_monthly_usd": 41.2, "coverage": { "savings_plans_pct": 0.0, "reservations_pct": 0.0, "on_demand_usd": 168.4, "days": 30 } }
}
```

## Interfaces

Each integration module has the same two functions:

```python
def parse(raw: dict, index: hosts.Index) -> Parsed: ...        # pure, tested with fixtures
def fetch(...) -> dict: ...                                    # network; returns raw to save
```

`Parsed` is a TypedDict: `findings`, `resources` (ARN to per-source data), `coverage`
(Well-Architected BP ID to `{"pass": n, "fail": n}` for what this source checked), `unmatched`
(names it could not tie to a resource).

`hosts.Index` is built once from the snapshot. `index.match(name)` returns one instance ARN or
`None` (none or more than one).

## Error handling

| Situation | Result |
|---|---|
| Raw file missing | Source "not loaded"; its checks are "not checked" |
| Raw file present but wrong shape | Error printed with the file name; source "not loaded"; exit code 2 |
| Name matches no or several instances | Listed in `meta.integrations.<source>.unmatched`; no data attached |
| Fetch: HTTP error, TLS error, timeout | Error printed (no credentials, no response body over 200 characters); exit 1; file not written |
| Snapshot partial | As today: `meta.complete` false, exit 2 |

## Security design

- **Least privilege per source.** AWS: `infra/collector-read-only-policy.json`, one statement per
  command (tested against the code: POL-1, POL-2). Wazuh: an API user with a read-only role for agents, and an
  indexer user with read on `wazuh-states-vulnerabilities-*`. GitHub: fine-grained token,
  "Deployments: read" and "Metadata: read" on the listed repos only [R20].
- **Credentials** from environment variables only: `WAZUH_API_USER`, `WAZUH_API_PASSWORD`,
  `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`, `GITHUB_TOKEN`, `PROMETHEUS_BEARER_TOKEN`
  (optional). Never accepted as command-line arguments (they would show in shell history and `ps`).
- **TLS:** `httpjson.py` uses the default SSL context and follows no redirects (urllib would re-send the
  credential header to the new address). `--ca-file` adds a private CA. There is no
  option to skip verification.
- **Least data:** Wazuh vulnerability query asks only for the fields it uses (`_source` list).
  GitHub reads only repos named in resource tags. Cost Explorer reads only aggregate cost.
- **Output:** raw files and graphs `0600`, git-ignored. No host IPs (CIDR ranges stay), environment values, package
  paths or full CVE descriptions in the graph.
- **UI:** unchanged rules: `textContent` only, CSP `script-src 'self'`. Links to external pages
  (AWS docs, GitHub) are built only from `https://` URLs and opened with `rel="noopener noreferrer"`.

## Tests

| Layer | Tool | What |
|---|---|---|
| Parsers, rules, scorecard | pytest, fixture files | Every row in the specs' test tables |
| AWS fetchers | moto (CloudWatch), botocore `Stubber` (Cost Explorer; moto does not cover it) | Request shape, pagination |
| HTTP fetchers | pytest with a fake `urlopen` | Auth header, query body, no credentials in errors |
| End to end | `scripts/make_sample.py` | moto estate + fake raw files -> `samples/demo.graph.json` |
| Frontend logic | vitest on `views.js` | Filtering, sorting, totals, scorecard grouping |
| Types | pyright | TypedDict shapes |
| Lint | ruff | Unused names, import order, common bug patterns (`uv run ruff check`) |
