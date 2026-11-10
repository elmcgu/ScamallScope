# Plan

Goal: an app that shows an engineer, for one AWS account, three ranked lists:

1. **Security concerns** to fix first (worst severity on the most exposed resources first).
2. **Places to cut cost**, with an estimated saving in USD a month.
3. **Availability risks**: single points of failure, missing backups, no automatic healing.

Every item says what is wrong, why it matters, how to fix it, and links to the AWS
Well-Architected best practice it breaks. Availability is the Reliability pillar in
Well-Architected terms; the UI says "Availability (Reliability)".

Updated 2026-11-10. Research for this plan: [references.md](references.md) R41 to R59.

## Where the repo is (2026-11-10, commit 8a3be9b)

| Done | Proof |
|---|---|
| Inventory through boto3: EC2 networking and instances, Lambda, IAM, S3 | `test_snapshot.py`, `test_global_services.py` |
| Exposure and admin checks | `test_exposure.py`, `test_network_acl.py` |
| Daily inventory and change log in DynamoDB | `test_inventory.py`, decision 0001 |
| Phase A: findings model, Well-Architected catalogue (177 BPs), host matching, 7 integrations (parse and fetch), 13 hygiene rules, scorecard, `enrich`, made-up demo, UI views | 156 pytest and 44 vitest tests pass; `npm run build` works |

Not done from Phase A: A1 (Ellis reviews the docs) and the A9 browser check.

## Phase B status (2026-11-10)

| Step | Commit | Proof |
|---|---|---|
| B1 Docs | a55bd0e | Decision 0003, specs 10 to 14 |
| B2 Storage and network collectors | 83d8a39 | `test_inventory_b.py` INV-1 to INV-6, INV-15, INV-16 |
| B3 RDS, ELB, Auto Scaling | c0e9912 | INV-7 to INV-9 |
| B4 Account controls | 93c930b | INV-10 to INV-14 |
| B5 Cost Optimization Hub | 4f9ec22, 8f4a677 | `test_costhub.py` COH-1 to COH-7 |
| B6 Commitment coverage | 93ac716 | `test_cost.py` CST-8, CST-9 |
| B7 32 rules | 7bb310b | `test_rules_b.py`: one hit and one clean case per rule, RUL-1 to RUL-4 |
| B8 Ranking | 7abdf8e | `test_rank.py` RNK-1 to RNK-6 |
| B9 Demo | 7adf79b | `make_sample.py` prints "rules with no example in the demo: none" |
| B10 Overview | c4c0aa3 | `views.test.js` VIEW-9 to VIEW-11 |
| B11 Availability, map | 4eb7ead | `test_availability.py` AVL-1 to AVL-3, VIEW-12, VIEW-13 |
| B12 Finish | this commit | Clean clone: `make_sample.py`, `npm ci`, 52 vitest tests, `npm run build`; 250 pytest tests and pyright clean in the working copy |

Open, for Ellis:

- **Browser check (A9, B10, B11).** No browser in this WSL. Run `npm run dev`, "Load sample", and
  look at Overview, Availability and Map "Colour by" (worst security, cost, availability finding).
- **A1 doc review.**
- Known: rebuilding the sample changes moto's random resource IDs in `samples/`, so commit the
  sample only when its content changed on purpose.

## What the research changed

1. **Use the AWS services that already compute the answer, and read them through boto3.**
   - Cost Optimization Hub gives rightsizing, idle, Savings Plans and Reserved Instance
     recommendations, with estimated monthly savings that take account of your discounts. It
     covers EC2, Auto Scaling groups, EBS, Lambda, RDS, NAT gateways and more [R41, R42]. It is
     better than our own CPU threshold (HYG-EC2-002), which stays only as a fallback when the hub
     is not loaded.
   - Compute Optimizer is the source of the hub's rightsizing and idle recommendations. It needs
     an opt-in and 14 days of metrics [R43]. We read its enrolment status so the UI can say
     "not enabled" instead of "nothing to save".
   - Trusted Advisor is **not** used. Its API needs a Business Support+, Enterprise or Unified
     Operations plan [R44]; most small accounts do not have one.
   - Prowler stays the main security checker. Security Hub CSPM is optional later.
2. **The inventory must include what availability and cost depend on.** The best practices
   name specific resources and settings: Multi-AZ RDS, load balancers in several AZs, Auto
   Scaling groups for self-healing (REL10-BP01, REL11-BP03 [R45, R46]); automatic backups and
   EBS snapshots (REL09-BP03 [R47]); unattached volumes and idle resources (COST04-BP03 [R48]);
   NAT gateways and VPC endpoints (COST08-BP02 [R49]); EBS default encryption and RDS encryption
   (SEC08-BP02 [R50]); HTTPS listeners and certificate expiry (SEC09-BP02 [R51]); CloudTrail, VPC
   Flow Logs and GuardDuty (SEC04-BP01 [R52]); SSH and RDP open, SSM-managed instances
   (SEC06-BP03 [R53]); access keys older than 90 days (SEC02-BP05 [R54]).
3. **Rank by impact, not by source.** Security by severity and exposure; cost by USD a month;
   availability by severity and whether the resource is in production (`env` tag).

## Phase B: build (Claude builds; tests with moto, Stubber for APIs moto lacks)

Each step gets a spec in `docs/specs/` with a test table, as in Phase A. "Done when" is the
check. All new AWS calls are read-only and are added to the permissions list in
`collector/README.md`.

| Step | Output | Done when |
|---|---|---|
| B1 Docs | This plan; R41 to R59; decision 0003 (use AWS recommenders, keep own rules as fallback); specs 10 to 14 | Specs exist with test tables |
| B2 Collectors: storage and network | `collectors/ec2.py` adds EBS volumes, own EBS snapshots, Elastic IPs, NAT gateways, VPC endpoints, flow logs, EBS encryption by default, IMDS setting per instance | SNAP tests pass in moto; graph shows volumes and NAT gateways |
| B3 Collectors: data and compute | New `rds.py` (Multi-AZ, encryption, public, backup retention), `elbv2.py` (AZs, listeners, TLS policy, target health), `autoscaling.py` (AZs, health check type, instances) | RDS, ELB, ASG tests pass in moto; links ASG to instances and target group to instances |
| B4 Collectors: account controls | New `account.py`: CloudTrail trails and status, GuardDuty detectors, IAM credential report (root MFA, root keys, key age, last used, user MFA), AWS Backup protected resources, SSM managed instances, ACM certificate expiry | ACC tests pass (moto; credential report CSV from a fixture) |
| B5 Integration: Cost Optimization Hub | `integrations/costhub.py`: `fetch()` with `ListRecommendations` (us-east-1, paginated) and Compute Optimizer `GetEnrollmentStatus`; `parse()` to findings with `estimated_monthly_savings` | COH tests pass (Stubber; moto does not cover these services) |
| B6 Integration: commitment coverage | `integrations/cost.py` adds `GetSavingsPlansCoverage` and `GetReservationCoverage` | CST tests pass (Stubber) |
| B7 Rules | `hygiene.py` adds the rules in the three tables below; each finding gets `remediation` and, for cost, `estimated_monthly_savings` | HYG tests pass: one per rule, plus a "not checked" test per rule |
| B8 Ranking | `rank.py`: one priority score per finding within its pillar; merge the same issue from Prowler and our rules (same resource and BP) | RNK tests pass |
| B9 Demo | `make_sample.py` builds a moto estate with at least one example of every rule; fake hub and coverage files | Demo graph has findings from every rule and source |
| B10 UI: Overview | New default view "Overview": three columns (Security, Cost, Availability), top 10 each with what, why, fix, BP link and saving; totals at the top (open issues by severity, savings a month, single points of failure) | VIEW tests pass; checked in a browser |
| B11 UI: Availability view and Map | "Availability" view per workload (VPC and `app` tag): AZ spread, backup, healing, monitoring. Map "Colour by" adds pillar | VIEW tests pass; checked in a browser |
| B12 Finish | README run-through from a clean clone; pyright clean; all tests pass | Ellis runs the demo from the README |

### New rules: security

| Rule | When | Severity | BP |
|---|---|---|---|
| SEC-NET-001 | Security group allows 0.0.0.0/0 or ::/0 on 22 or 3389, attached to a running instance | high (exposed: critical) | SEC06-BP03, SEC05-BP02 |
| SEC-EC2-001 | Instance allows IMDSv1 (`HttpTokens` not `required`) | medium | SEC06-BP02 |
| SEC-EC2-002 | Running instance not managed by SSM | low | SEC06-BP03 |
| SEC-EBS-001 | Volume not encrypted, or EBS encryption by default off in a Region with instances | medium | SEC08-BP02 |
| SEC-RDS-001 | DB instance not encrypted | high | SEC08-BP02 |
| SEC-RDS-002 | DB instance `PubliclyAccessible` and reachable from the internet | critical | SEC05-BP01 |
| SEC-ELB-001 | Internet-facing load balancer has an HTTP listener that does not redirect to HTTPS | medium | SEC09-BP02 |
| SEC-ELB-002 | HTTPS listener uses a TLS policy that allows TLS 1.0 or 1.1 | medium | SEC09-BP02 |
| SEC-ACM-001 | Certificate in use expires within 30 days, or is not eligible for renewal | medium | SEC09-BP01 |
| SEC-IAM-002 | Active access key older than 90 days, or unused for 90 days | medium | SEC02-BP05 |
| SEC-IAM-003 | Console user without MFA | high | SEC02-BP01 |
| SEC-IAM-004 | Root user without MFA, or root has access keys | critical | SEC01-BP02 |
| SEC-LOG-001 | No multi-Region CloudTrail trail that is logging | high | SEC04-BP01 |
| SEC-LOG-002 | VPC with running instances and no flow log | low | SEC04-BP01 |
| SEC-DET-001 | GuardDuty not enabled in a Region with resources | medium | SEC04-BP01, SEC10-BP06 |

Kept: EXP-001, IAM-ADMIN-001, HYG-IAM-001, HYG-S3-002, HYG-LAM-001, HYG-AGT-001, Prowler, Wazuh.

### New rules: cost

| Rule | When | Saving shown | BP |
|---|---|---|---|
| COST-HUB-* | One finding per Cost Optimization Hub recommendation (Delete, Stop, Rightsize, Upgrade, purchase Savings Plans or RI) | Hub's `estimatedMonthlySavings` | COST04-BP03, COST06-BP02 or COST07-BP04 by action type |
| COST-EBS-001 | Volume `available` (unattached) | Size x price per GB-month | COST04-BP03 |
| COST-EBS-002 | `gp2` volume (gp3 costs less per GB) | Price difference x size | COST06-BP02 |
| COST-SNAP-001 | Own snapshot older than 180 days, not made by AWS Backup or Data Lifecycle Manager | Size x snapshot price (upper bound: snapshots are incremental) | COST04-BP05 |
| COST-EIP-001 | Elastic IP not associated | $0.005 x 730 = $3.65 a month [R55] | COST04-BP03 |
| COST-NAT-001 | NAT gateway in a VPC with no S3 or DynamoDB gateway endpoint | None; shows NAT cost if Cost Explorer is loaded | COST08-BP02 |
| COST-COV-001 | Savings Plans and RI coverage under 50% of eligible on-demand spend over 30 days | Hub's purchase recommendation, if any | COST07-BP04 [R56] |

Kept: HYG-EC2-001, HYG-TAG-001; HYG-EC2-002 only when the hub is not loaded. When Compute
Optimizer is not enabled, the Cost view says so at the top, with the link to opt in. Prices are a
dated table in the code (us-east-1) and the UI says "estimate".

### New rules: availability (Reliability)

| Rule | When | Severity | BP |
|---|---|---|---|
| REL-AZ-001 | Workload (VPC and `app` tag, ASG or target group) runs in one AZ only | high if prod, else medium | REL10-BP01 |
| REL-AZ-002 | RDS instance not Multi-AZ | high if prod, else low | REL10-BP01 |
| REL-AZ-003 | Load balancer or ASG uses one AZ | high | REL10-BP01 |
| REL-AZ-004 | Private subnets in several AZs route through one NAT gateway | medium | REL10-BP01, COST08-BP02 |
| REL-HEAL-001 | Running instance not in an ASG and no CloudWatch alarm with an EC2 recover action | medium | REL11-BP03 |
| REL-HEAL-002 | ASG behind a load balancer with health check type `EC2` (should be `ELB`) | low | REL11-BP01 |
| REL-HEAL-003 | Target group has unhealthy targets | high | REL11-BP01 |
| REL-BAK-001 | EBS volume or RDS instance with no AWS Backup recovery point and no own snapshot in 7 days | high if prod, else medium | REL09-BP03 |
| REL-BAK-002 | RDS backup retention 0 | high | REL09-BP03 |
| REL-BAK-003 | RDS or EBS snapshot not encrypted | medium | REL09-BP02 |

Kept: HYG-S3-001, HYG-MON-001, HYG-MON-002, HYG-CFG-001.

## Phase C: real data (with Ellis)

Lowest risk and least access first. For each source: create the read-only identity, run
`collect` or `fetch`, run `enrich`, compare 3 to 5 values with the AWS console or the source's own
UI, and write down what did not match.

1. AWS inventory with a read-only role (all collectors, including B2 to B4). Check 2 exposure and
   2 availability results by hand.
2. Cost Optimization Hub and Compute Optimizer (enable them if needed; Compute Optimizer needs
   14 days of metrics). Compare total savings with the console.
3. Cost Explorer cost and coverage. Compare last month's total.
4. Prowler with the same role. Compare the failed count with Prowler's HTML report.
5. CloudWatch. Compare one instance's CPU with the console.
6. Wazuh, GitHub, Ansible, Prometheus.

Expected tuning: severities, the prod rule, prices, required tags, host-name matching.

## Phase D: deploy

Needs its own change request and decision record. Decide: where it runs (scheduled container or
Lambda, or a host that can reach Wazuh and Prometheus), secrets in AWS Secrets Manager, UI on a
private S3 bucket with CloudFront and sign-in, graph files in S3 with encryption, versioning and
a lifecycle rule.

## Phase E: later

- Price List API for savings estimates.
- Security Hub CSPM and GuardDuty findings as integrations.
- Changes view from the DynamoDB change log.
- More collectors: ECS and EKS, ElastiCache, DynamoDB tables (PITR), EFS, CloudFront.
- Several accounts (the account ID is already on every resource).
- Loki error counts and Grafana links.

## Decisions (Ellis, 2026-11-10)

1. A resource with no `env` tag is ranked as prod.
2. Savings estimates come from a dated price table in the code; the Price List API is Phase E.
3. One commit per Phase B step.
