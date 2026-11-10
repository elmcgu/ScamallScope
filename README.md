# ScamallScope

*Scamall* is Irish for "cloud". ScamallScope maps an AWS estate and shows it from different angles: security, networking, cost and hygiene.

> Status (2026-11-04): roadmap 1 to 3 and the integrations demo work locally with made-up data
> (moto and fake raw files); not yet run against a real account or deployed. Starts with one AWS
> account; the account ID is kept on every resource so more accounts can be added later.

**Docs:** [what it is and why](docs/PROJECT.md) (including how it maps to AWS Well-Architected) ·
[architecture](docs/architecture.md) · [specs and tests](docs/specs/) · [plan](docs/plan.md) ·
[references](docs/references.md)

## Try the demo

```bash
cd collector && uv sync && uv run python scripts/make_sample.py   # made-up estate + integration data
cd ../frontend && npm ci && npm run dev                            # http://localhost:5173, "Load sample"
```

## What it does

- **Collects** resources in an AWS account using read-only Python (boto3) calls: EC2 networking
  and instances, Lambda, IAM and S3 so far.
- **Keeps an inventory** in DynamoDB and records what is new, changed or deleted each day.
- **Links** resources into a graph (VPC → subnet → EC2 → security group, and so on).
- **Shows** the graph in a web frontend, with views and filters:
  - **Networking:** VPCs, subnets, routes, gateways, what can reach what.
  - **Security:** public exposure, IAM, findings from integrations.
  - **Cost:** spend per resource, service and tag.
  - **Hygiene:** untagged resources, unused volumes, old snapshots, idle resources.
  - **Changes:** what is new, changed or deleted since the last run.
  - **Filters:** show or hide resource types, regions and tags.
- **Enriches** resources with data from integrations (each optional; spec per source in [docs/specs/](docs/specs/)):
  - [Prowler](https://github.com/prowler-cloud/prowler): AWS security checks, with their Well-Architected IDs.
  - [Wazuh](https://wazuh.com/): agent OS version and status, vulnerable packages on EC2.
  - GitHub: which commit is deployed where, and whether the last deployment worked.
  - Ansible: per host failed, unreachable, or drifted (check mode).
  - CloudWatch and Prometheus: idle instances, instances with no alarm or no monitoring.
  - Cost Explorer: cost by service, tag and instance. Planned: Loki error counts, Grafana links.
- **Scores** findings against AWS Well-Architected best practices (security, reliability, cost):
  issues, clear, or not checked.

## Layout

| Folder | What goes there |
|---|---|
| `collector/` | Python package: AWS collectors, integrations, graph builder |
| `frontend/` | Web UI for the views and filters |
| `infra/` | CloudFormation templates to deploy ScamallScope |
| `docs/decisions/` | Design decision records |
| `samples/` | Made-up example data for development (never real account data) |

## Roadmap

1. **Inventory:** collector runs locally and writes a JSON snapshot of resources and links.
2. **Network view:** frontend (Cytoscape.js) shows the graph from a snapshot, with filters.
3. **Daily inventory:** current state and change log in DynamoDB ([decision 0001](docs/decisions/0001-inventory-in-dynamodb.md)).
4. **Deploy:** CloudFormation stack runs the collector on a schedule and hosts the UI, with sign-in.
5. **Security, cost, hygiene views** and the Well-Architected scorecard (demo done; changes view later).
6. **Integrations:** Prowler, Wazuh, GitHub, Ansible, CloudWatch, Prometheus, Cost Explorer (demo
   done with made-up data; next: real data one source at a time, see [plan](docs/plan.md)).

## Security

ScamallScope builds a map of an AWS estate, so its output is sensitive.

- The collector uses a **read-only** IAM role.
- Snapshots and raw integration files stay out of this repo (git-ignored, mode `0600`).
  `samples/` holds made-up data only.
- Integration credentials come from environment variables only; TLS is always verified.
- The deployed UI must require sign-in.
- The DynamoDB table and S3 bucket are encrypted and private.
