# 12 Security, cost and availability rules

Rules in `hygiene.py`, same engine as spec 08: a rule runs only when its inputs are loaded, and
covers its best practice only when it checked at least one resource. Every finding now has
`remediation` (one line) and `savings_usd` (cost rules; null otherwise).

**Prod:** a resource is prod when its `env` tag is `prod`, `production` or `prd`, or when it
has no `env` tag (decision by Ellis, 2026-11-10: unknown is treated as prod). Rules that say
"high if prod" use this.

## Security

| Rule | Types | When | Severity | BP |
|---|---|---|---|---|
| SEC-NET-001 | instance | Running, uses a security group with an ingress rule from `0.0.0.0/0` or `::/0` that covers 22 or 3389 | high; critical if `exposure` = exposed | SEC06-BP03 |
| SEC-EC2-001 | instance | Running, `MetadataOptions.HttpTokens` is not `required` | medium | SEC06-BP02 |
| SEC-EC2-002 | instance | Running, not in setting `ssm-managed` for its Region (needs that unit ok) | low | SEC06-BP03 |
| SEC-EBS-001 | volume | `Encrypted` false | medium | SEC08-BP02 |
| SEC-EBS-002 | setting `ebs-encryption-by-default` | `Enabled` false and the Region has instances or volumes | medium | SEC08-BP02 |
| SEC-RDS-001 | db-instance | `StorageEncrypted` false | high | SEC08-BP02 |
| SEC-RDS-002 | db-instance | `PubliclyAccessible` true | high; critical if in a subnet with an internet route | SEC05-BP01 |
| SEC-ELB-001 | load-balancer | `internet-facing`, has an HTTP listener whose default action is not a redirect to HTTPS | medium | SEC09-BP02 |
| SEC-ELB-002 | load-balancer | Has an HTTPS or TLS listener whose `SslProtocols` include `TLSv1` or `TLSv1.1` | medium | SEC09-BP02 |
| SEC-ACM-001 | certificate | In use and `NotAfter` within 30 days, or in use, imported and `NotAfter` within 30 days | medium; high within 7 days | SEC09-BP01 |
| SEC-IAM-002 | credential-report row (not root) | An active key last rotated > 90 days ago, or active and not used for 90 days | medium | SEC02-BP05 |
| SEC-IAM-003 | credential-report row (not root) | `password_enabled` true and `mfa_active` false | high | SEC02-BP01 |
| SEC-IAM-004 | credential-report root row | `mfa_active` false, or any root access key active | critical | SEC01-BP02 |
| SEC-LOG-001 | account (trails unit) | No trail with `IsMultiRegionTrail` and `IsLogging` | high | SEC04-BP01 |
| SEC-LOG-002 | vpc | Has running instances and no flow log on the VPC or all of its subnets (needs flow-log unit ok) | low | SEC04-BP01 |
| SEC-DET-001 | setting `guardduty` | No detector with `Status` `ENABLED`, in a Region with instances, functions or DB instances | medium | SEC04-BP01 |

## Cost

Prices: `PRICES` in `hygiene.py`, `PRICES_AS_OF = "2026-11-10"`, from the worked examples on
the EBS pricing page and the VPC pricing page [R55, R59]. They are not Region-specific; the UI
says "estimate".

| Rule | Types | When | `savings_usd` | Severity | BP |
|---|---|---|---|---|---|
| COST-EBS-001 | volume | `State` `available` | size x price for its type | by saving (spec 11) | COST04-BP03 |
| COST-EBS-002 | volume | `VolumeType` `gp2` | size x (0.10 - 0.08) | by saving | COST06-BP02 |
| COST-SNAP-001 | snapshot | `StartTime` > 180 days ago, no `aws:backup:source-resource` or `aws:dlm:lifecycle-policy-id` tag | size x 0.05 (upper bound) | by saving | COST04-BP05 |
| COST-EIP-001 | elastic-ip | Not associated | 3.65 | low | COST04-BP03 |
| COST-NAT-001 | nat-gateway | `available`, and its VPC has no gateway endpoint for S3 or DynamoDB | null | low | COST08-BP02 |
| COST-COV-001 | account (cost loaded) | `cost.coverage.savings_plans_pct` + `reservations_pct` < 50 and on-demand spend > 100 a month | null | medium | COST07-BP04 |

HYG-EC2-002 (idle by CPU) does not run when `costhub` is loaded and enabled (decision 0003).

## Availability (Reliability)

| Rule | Types | When | Severity | BP |
|---|---|---|---|---|
| REL-AZ-001 | instance group | Running instances tagged `app` in the same Region and VPC are all in one AZ (finding on the group: `resource` null, name `app <name> (<vpc>)`); or a running instance with no `app` tag, not in an ASG and not a target, alone | high if prod, else medium; standalone instance: medium if prod, else low | REL10-BP01 |
| REL-AZ-002 | db-instance | `MultiAZ` false and not part of an Aurora cluster | high if prod, else low | REL10-BP01 |
| REL-AZ-003 | load-balancer, autoscaling-group | One AZ | high | REL10-BP01 |
| REL-AZ-004 | nat-gateway | Route tables of private subnets in 2 or more AZs route `0.0.0.0/0` to this one NAT gateway | medium | REL10-BP01 |
| REL-HEAL-001 | instance | Running, not in an ASG, `MaintenanceOptions.AutoRecovery` `disabled`, and (CloudWatch loaded) no alarm with an EC2 recover action [R58] | medium | REL11-BP03 |
| REL-HEAL-002 | autoscaling-group | Has target groups and `HealthCheckType` `EC2` | low | REL11-BP01 |
| REL-HEAL-003 | target-group | Any target `unhealthy` | high | REL11-BP01 |
| REL-BAK-001 | volume (attached), db-instance | No `LastBackupTime` in `backup-protected` within 7 days and (volumes) no own snapshot within 7 days; RDS with retention > 0 counts as backed up | high if prod, else medium | REL09-BP03 |
| REL-BAK-002 | db-instance | `BackupRetentionPeriod` 0 | high | REL09-BP03 |
| REL-BAK-003 | snapshot | `Encrypted` false | medium | REL09-BP02 |

## Tests

One test per rule ID (hit and no hit), named `test_<RULE>_...`, plus:

| ID | Given | Then |
|---|---|---|
| RUL-1 | A rule's input unit failed (for example `ssm-managed` error) | No finding and no coverage for that rule |
| RUL-2 | No `env` tag | Treated as prod |
| RUL-3 | costhub loaded and enabled | HYG-EC2-002 does not run |
| RUL-4 | Every finding | Has `remediation`; cost rule findings have `savings_usd` |
