# Plan

From the state on 2026-11-04 (roadmap 1 to 3 done, tested with moto) to a working demo, then real
data, then deployed.

## Where the repo was

| Done | Proof |
|---|---|
| Inventory collector: EC2 networking and instances, Lambda, IAM, S3 | `collector/tests/test_snapshot.py`, `test_global_services.py` |
| Internet exposure and admin checks | `test_exposure.py`, `test_network_acl.py` |
| Graph JSON and network view (Cytoscape.js) | `test_graph.py`, `frontend/tests/` |
| Daily inventory in DynamoDB | `test_inventory.py`, decision 0001 |

## Phase A: demo with made-up data (this change)

| Step | Output | Done when |
|---|---|---|
| A1 Docs | PROJECT.md, architecture.md, specs/, references.md, decision 0002 | Reviewed by Ellis |
| A2 Findings model and Well-Architected catalogue | `findings.py`, `data/well_architected.json` | FND tests pass |
| A3 Host matching | `hosts.py` | HST tests pass |
| A4 Parsers: Prowler, Wazuh, GitHub, Ansible, CloudWatch, Prometheus, Cost | `integrations/*.py` `parse()` | PRW, WAZ, GHB, ANS, CWM, PRM, CST tests pass |
| A5 Fetchers | `integrations/*.py` `fetch()`, `http.py`, CLI `fetch` | Fetch tests pass (fake HTTP, moto, Stubber) |
| A6 Hygiene rules and scorecard | `hygiene.py`, `posture.py` | HYG, POS tests pass |
| A7 Enrich and CLI | `enrich.py`, `scamallscope enrich` | ENR tests pass |
| A8 Fake data | `scripts/make_sample.py` writes fake raw files and `samples/demo.graph.json` | Demo graph has findings from every source |
| A9 UI views | `views.js`, `main.js`, `index.html` | VIEW tests pass; `npm run build` works; views checked in a browser |

## Phase B: real data, one source at a time (with Ellis)

Order: lowest risk and least access first. For each source: create the read-only identity, run
fetch, run enrich, compare 3 to 5 values with the source's own UI, write down what did not match.

1. AWS inventory against a real account (`collect`, read-only role). Check exposure on 2 instances by hand.
2. Prowler: run with the same read-only role. Compare the failed count with Prowler's HTML report.
3. CloudWatch and Cost Explorer: add the 4 read actions to the role. Compare one instance's CPU with the console.
4. Wazuh: read-only API user and indexer user. Check host name matching; add `scamallscope:host` tags where names differ.
5. GitHub: fine-grained token, Deployments read. Tag resources with `scamallscope:repo`.
6. Ansible: run the main playbook in check mode with the JSON callback.
7. Prometheus: confirm the `instance_id` relabel exists, or match by host name.

Expected tuning: hygiene thresholds, required tags, host-name matching rules, normalisation of
Wazuh OS names.

## Phase C: deploy (roadmap 4)

Needs its own change request and decision record. To decide:

- Where it runs: a scheduled container or Lambda in the account, or a small host that can also
  reach Wazuh and Prometheus (they are often private).
- Secrets: Wazuh and GitHub credentials in AWS Secrets Manager, read by the job's role.
- UI hosting: private S3 bucket with CloudFront and sign-in (Cognito or IAM Identity Center).
- Graph files: S3 with encryption, versioning and a lifecycle rule.

## Phase D: later

- Loki error counts and Grafana links (spec 06, planned sections).
- Changes view from the DynamoDB change log.
- More collectors: EBS volumes and snapshots (unattached volumes, old snapshots), RDS, load balancers.
- Several accounts (the account ID is already on every resource).
- Replace HYG-EC2-002 with AWS Compute Optimizer recommendations [R8].
