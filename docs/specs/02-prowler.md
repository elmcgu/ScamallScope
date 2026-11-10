# 02 Prowler

## Input

Prowler JSON-OCSF output [R10, R11]: a JSON list of OCSF Detection Findings [R9]. Run Prowler
with its read-only role, then copy the file:

```bash
prowler aws --output-formats json-ocsf --output-directory ./prowler-output
cp prowler-output/prowler-output-*.ocsf.json collector/integrations/prowler.ocsf.json
```

Several files are allowed (`integrations/prowler*.ocsf.json`), for example one per region set.

## Fields used

| OCSF field | Used for |
|---|---|
| `status_code` | `FAIL` becomes a finding; `PASS` counts as coverage; `MANUAL` and others ignored |
| `severity` | Finding severity (spec 01) |
| `metadata.event_code` | `check_id` (for example `iam_root_mfa_enabled`) |
| `finding_info.title`, `finding_info.uid` | Title; uid used only for de-duplication |
| `status_detail` | `detail` (cut to 300 characters) |
| `resources[0].uid`, `resources[0].region` | Resource ARN and region |
| `remediation.desc` | Remediation (cut to 300 characters) |
| `unmapped.compliance` | Keys starting `AWS-Well-Architected-Framework-`: BP IDs [R12, R13] |
| `cloud.account.uid` | Must equal the snapshot account, or the finding is skipped and counted |

Pillar: from the first BP ID (`SEC` security, `REL` reliability). No BP: `security`.

The resource ARN is used as is when it is in the snapshot. When it is not (Prowler checks more
services than ScamallScope collects), the finding keeps the ARN as `resource_name` and
`resource` is null. It still counts on the scorecard.

## Tests

| ID | Given | Then |
|---|---|---|
| PRW-1 | Fixture with 4 FAIL, 1 PASS, 1 MANUAL | 4 findings |
| PRW-2 | FAIL with compliance `AWS-Well-Architected-Framework-Security-Pillar: [SEC01-BP02]` and `CIS-3.0: [1.5]` | `best_practices` = `[SEC01-BP02]`, pillar security |
| PRW-3 | PASS on SEC01-BP02 | coverage SEC01-BP02 pass 1 |
| PRW-4 | FAIL whose `resources[0].uid` is a bucket ARN in the snapshot | `resource` = that ARN |
| PRW-5 | FAIL for a resource not in the snapshot | `resource` null, `resource_name` = the uid |
| PRW-6 | Finding for account `999999999999` | Skipped; counted in `skipped_other_account` |
| PRW-7 | File that is not a list, or items without `status_code` | `ValueError` naming the file |
| PRW-8 | Two files with the same `finding_info.uid` | One finding |
