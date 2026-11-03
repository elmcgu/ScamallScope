# ScamallScope

*Scamall* is Irish for "cloud". ScamallScope maps an AWS estate and shows it from different angles: security, networking, cost and hygiene.

> Status: early design. Nothing works yet.

## What it does

- **Collects** every resource in an AWS account using read-only Python (boto3) calls.
- **Links** resources into a graph (VPC → subnet → EC2 → security group, and so on).
- **Shows** the graph in a web frontend, with views and filters:
  - **Networking:** VPCs, subnets, routes, gateways, what can reach what.
  - **Security:** public exposure, IAM, findings from integrations.
  - **Cost:** spend per resource, service and tag.
  - **Hygiene:** untagged resources, unused volumes, old snapshots, idle resources.
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
2. **Network view:** frontend shows the graph from a snapshot, with filters.
3. **Deploy:** CloudFormation stack runs the collector on a schedule and hosts the UI, with sign-in.
4. **Security, cost and hygiene views.**
5. **Integrations:** Prowler, then Wazuh, then GitHub, then Ansible.

## Security

ScamallScope builds a map of an AWS estate, so its output is sensitive.

- The collector uses a **read-only** IAM role.
- Snapshots stay out of this repo. `samples/` holds made-up data only.
- The deployed UI must require sign-in.
