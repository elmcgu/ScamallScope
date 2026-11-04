# ScamallScope

*Scamall* is Irish for "cloud". ScamallScope maps an AWS estate and shows it from different angles: security, networking, cost and hygiene.

> Status: roadmap items 1 to 3 work locally (tested with moto); not yet run against a real account
> or deployed. Starts with one AWS account; the account ID is kept on every resource so more
> accounts can be added later.

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
- **Enriches** resources with data from integrations:
  - [Prowler](https://github.com/prowler-cloud/prowler): AWS security checks.
  - [Wazuh](https://wazuh.com/): OS-level data such as vulnerable packages on EC2.
  - GitHub: which code runs where, and recent pipeline deployments.
  - Ansible (later): what configuration was applied where.

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
5. **Security, cost, hygiene and changes views.**
6. **Integrations:** Prowler, then Wazuh, then GitHub, then Ansible.

## Security

ScamallScope builds a map of an AWS estate, so its output is sensitive.

- The collector uses a **read-only** IAM role.
- Snapshots stay out of this repo. `samples/` holds made-up data only.
- The deployed UI must require sign-in.
- The DynamoDB table and S3 bucket are encrypted and private.
