# 13 Ranking and duplicates

`rank.py`, run in `enrich` after all findings are made. Pure functions.

## Duplicates

Two findings are the same issue when they have the same `resource` (not null), the same pillar,
and share at least one best practice. Keep one as primary:

1. `costhub` (cost pillar: its saving is the better number),
2. `inventory` and `hygiene` (they have a remediation line),
3. any other source (Prowler, Wazuh, ...).

The others get `duplicate_of: <primary id>`; the primary gets `also_reported_by: [sources]`.
Duplicates stay in the Findings table (marked) and are left out of totals and the Overview.

## Priority

`priority` is a number; higher is first. Only compared within one pillar.

| Pillar | Priority |
|---|---|
| security | severity weight + 20 if the resource is `exposed` + 10 if prod |
| cost | `savings_usd` (null = 0) x 10 + severity weight / 10 |
| reliability | severity weight + 20 if prod |

Severity weights: critical 100, high 70, medium 40, low 15, info 5.

## Totals (`g["summary"]`)

Primary findings only: `open` by severity and by pillar; `savings_usd` (sum of cost
`savings_usd`, rounded to 0.01); `single_points_of_failure` (REL-AZ-* count).

## Tests

| ID | Given | Then |
|---|---|---|
| RNK-1 | Prowler and HYG-S3-002 on the same bucket, both SEC08-BP02 | Prowler `duplicate_of` the hygiene id; hygiene `also_reported_by` ["prowler"] |
| RNK-2 | COST-HUB-Delete and COST-EBS-001 on one volume | COST-EBS-001 duplicate of the hub finding |
| RNK-3 | Same resource, different pillars | Not duplicates |
| RNK-4 | Exposed high vs private high | Exposed first |
| RNK-5 | Savings 50 low vs 10 high | 50 first |
| RNK-6 | Summary | Duplicates not counted; savings summed once |
