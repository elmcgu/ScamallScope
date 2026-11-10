# 01 Findings and Well-Architected scorecard

## Finding

Every issue from every source is one Finding (a plain dict, TypedDict `findings.Finding`):

| Field | Type | Notes |
|---|---|---|
| `id` | str | Stable: `<source>:<check_id>:<resource ARN or name>`. Same input, same id |
| `source` | str | `prowler`, `wazuh`, `github`, `ansible`, `cloudwatch`, `prometheus`, `cost`, `inventory`, `hygiene` |
| `check_id` | str | Source's check (Prowler `metadata.event_code`, or a rule ID like `HYG-EC2-002`) |
| `title` | str | One line |
| `severity` | str | `critical`, `high`, `medium`, `low`, `info` |
| `pillar` | str | `security`, `reliability` or `cost` |
| `best_practices` | list[str] | Well-Architected IDs like `SEC06-BP01`; only IDs in the catalogue |
| `resource` | str or null | ARN of the matched resource; null if not matched |
| `resource_name` | str | Label to show (resource name, host name, or ARN) |
| `region` | str | Region, or `global` |
| `detail` | str | Short text: counts, ports, versions. No secrets, no IPs |
| `remediation` | str or null | One line or a URL |

Severity mapping: Prowler `Critical/High/Medium/Low/Informational` and Wazuh
`Critical/High/Medium/Low` map to the lower-case values; anything else is `info`.

## Scorecard

For each pillar and each best practice in `data/well_architected.json`:

- **issues**: at least one finding lists this BP.
- **clear**: no finding lists it, and at least one loaded source checks it (Prowler PASS results
  for that BP, or a hygiene rule mapped to it whose inputs were loaded).
- **not checked**: nothing loaded checks it.

`summary` counts each status. The scorecard never shows "clear" for a BP that was not checked.

## Tests

| ID | Given | Then |
|---|---|---|
| FND-1 | Prowler severity `Critical`, Wazuh `High`, unknown `Fatal` | `critical`, `high`, `info` |
| FND-2 | Best-practice list with `SEC06-BP01` and `XYZ` | Only `SEC06-BP01` kept |
| FND-3 | Same finding made twice | Same `id` |
| FND-4 | Catalogue | 177 BPs; every BP has pillar, title, `https://docs.aws.amazon.com/` URL |
| POS-1 | One finding on SEC06-BP01 | SEC06-BP01 `issues`, findings = 1 |
| POS-2 | Prowler coverage PASS on SEC01-BP02, no findings | SEC01-BP02 `clear`, `checked_by` = `["prowler"]` |
| POS-3 | Nothing loaded | Every BP `not checked`; summary issues 0, clear 0 |
| POS-4 | Coverage for a BP and a finding on it | `issues` (issues beat clear) |
| POS-5 | Summary | issues + clear + not_checked = number of BPs in the pillar |
