# 08 Hygiene rules

Rules that need the inventory, often with another source, in `collector/scamallscope/rules/spec08.py`
(engine in `rules/engine.py`). Each rule runs only when all its
inputs are loaded; otherwise its BP is not covered by it. Rules apply to the resource types listed.
A resource the rule does not apply to, or cannot judge, is not counted (spec 12, "Judged, passed
or not applicable").

| Rule | Applies to | Inputs | When | Severity | Pillar, BP |
|---|---|---|---|---|---|
| HYG-TAG-001 | instance, bucket, function, vpc | inventory | Missing any required tag (default `owner`, `env`; `--required-tags`) | low | cost, COST03-BP02 |
| HYG-EC2-001 | instance | inventory | State `stopped` (EBS volumes still charged) | low | cost, COST04-BP03 |
| HYG-EC2-002 | instance | inventory, cloudwatch | Running, `cpu_avg` < 5 and `cpu_max` < 20 over 14 days | medium | cost, COST06-BP02 |
| HYG-S3-001 | bucket | inventory | Versioning not `Enabled` | low | reliability, REL09-BP01 |
| HYG-S3-002 | bucket | inventory | No default encryption configuration (rare since 2023 [R39]) | medium | security, SEC08-BP02 |
| HYG-LAM-001 | function | inventory | Runtime in the deprecated list [R38] | medium | security, SEC06-BP01 |
| HYG-IAM-001 | user | inventory | IAM user exists (long-term credentials) | low | security, SEC02-BP02 |
| HYG-AGT-001 | instance | inventory, wazuh | Running and no matched Wazuh agent | medium | security, SEC06-BP01 |
| HYG-MON-001 | instance | inventory, prometheus | Running and no `up` series, or `prom_up` 0 | medium (0: high) | reliability, REL06-BP01 |
| HYG-MON-002 | instance | inventory, cloudwatch | Running and no CloudWatch alarm | low | reliability, REL06-BP03 |
| HYG-CFG-001 | instance | inventory, ansible | Running and not in the Ansible run | low | reliability, REL08-BP05 |
| EXP-001 | instance, bucket, function | inventory | `exposure` = `exposed` | high | security, SEC05-BP01 |
| IAM-ADMIN-001 | user, group, role | inventory | `admin` true (not service-linked roles) | medium | security, SEC03-BP02 |

Deprecated Lambda runtimes (from [R38], 2026-11-04): `python3.10`, `provided.al2`, `nodejs20.x`,
`ruby3.2`, `python3.9`, `nodejs18.x`, `dotnet6`, `python3.8`, `nodejs16.x`, `dotnet7`, `java8`,
`go1.x`, `provided`, `ruby2.7`, `nodejs14.x`, `python3.7`, `dotnetcore3.1`, `nodejs12.x`,
`python3.6`, `dotnet5.0`, `dotnetcore2.1`, `nodejs10.x`, `ruby2.5`, `python2.7`, `nodejs8.10`,
`nodejs4.3`, `nodejs4.3-edge`, `nodejs6.10`, `dotnetcore1.0`, `dotnetcore2.0`, `nodejs`. Update
this list when AWS deprecates more; the list and its date are in `rules/spec08.py`.

Thresholds (5% average, 20% peak, 14 days) are a starting point, not an AWS number. AWS Compute
Optimizer [R8] gives better rightsizing advice and could replace HYG-EC2-002 later.

## Tests

| ID | Given | Then |
|---|---|---|
| HYG-1 | Instance with `owner` but no `env` | HYG-TAG-001, detail names `env` |
| HYG-2 | `--required-tags team` | Only `team` checked |
| HYG-3 | Stopped instance | HYG-EC2-001 |
| HYG-4 | Running, cpu avg 2, max 9 | HYG-EC2-002 |
| HYG-5 | Running, cpu avg 2, max 60 | No HYG-EC2-002 |
| HYG-6 | CloudWatch not loaded | No HYG-EC2-002 or HYG-MON-002; COST06-BP02 not covered |
| HYG-7 | Function `python3.9` | HYG-LAM-001; `python3.12` none |
| HYG-8 | Wazuh loaded, running instance not matched | HYG-AGT-001; stopped instance none |
| HYG-9 | Prometheus loaded, `prom_up` 0 | HYG-MON-001 high |
| HYG-10 | Bucket versioning `Suspended` | HYG-S3-001 |
| HYG-11 | Exposed instance and admin group | EXP-001 high, IAM-ADMIN-001 medium |
| HYG-12 | Service-linked admin role | No IAM-ADMIN-001 |
| HYG-13 | Coverage | Each rule whose inputs are loaded adds its BP to coverage |
