# 07 Cost

## Input

Cost Explorer, endpoint region `us-east-1` [R32]. Three requests a run ($0.03 [R34]):

1. `GetCostAndUsage`, `MONTHLY`, last 3 full months plus this month up to yesterday, metric
   `UnblendedCost`, `GroupBy` `DIMENSION SERVICE`.
2. Same period and metric, `GroupBy` `TAG <cost tag>` (default `env`). The tag must be activated
   as a cost allocation tag [R31]; group keys come back as `env$prod`, and `env$` for untagged.
3. `GetCostAndUsageWithResources` [R33], `DAILY`, last 14 days, filter `SERVICE` =
   `Amazon Elastic Compute Cloud - Compute`, `GroupBy` `DIMENSION RESOURCE_ID`. Opt-in [R35]: if
   it fails with `DataUnavailableException` (not enabled) or `AccessDeniedException` (missing
   permission), store `null`, record which in `unavailable`, and go on. Any other error fails the
   fetch.

The raw file's `unavailable` maps each optional part (`by_resource`, `sp_coverage`,
`ri_coverage`) to `not_enabled` or `access_denied`. Each becomes a note in
`meta.integrations.cost.notes`, `<state>: <part> (<IAM action>)`; the Overview shows the
`access_denied` ones.

All three are paged with `NextPageToken`. Raw `integrations/cost.json`:
`{"fetched_at", "tag_key", "by_service": [ResultsByTime...], "by_tag": [...], "by_resource": [...] | null}`.

## Output

- Top-level `cost`: `months` (start, total, `by_service`), `by_tag` (`key`, values by tag value,
  `""` = untagged), `estimated` (true if any month is estimated).
- Per instance `cost.monthly_usd`: sum of the 14 days x 30 / days with data, rounded to 0.01;
  `basis` says so.
- `idle_monthly_usd`: sum of `cost.monthly_usd` of instances with finding `HYG-EC2-002` (added in
  enrich after hygiene).

## Findings

| Check | When | Severity | BP |
|---|---|---|---|
| `cost-untagged-spend` | Untagged spend in the last full month > 10% of the total | low | COST03-BP02 |

Coverage: COST03-BP05 (cost tools are configured and read) whenever the file is loaded.

## Tests

| ID | Given | Then |
|---|---|---|
| CST-1 | By-service fixture, 2 months | `months` with totals = sum of services |
| CST-2 | By-tag groups `env$prod`, `env$` | `by_tag.values` {prod, ""} |
| CST-3 | By-resource 14 days for i-1 at 1.00 a day | `monthly_usd` 30.0 |
| CST-4 | `by_resource` null | No per-instance cost; no error |
| CST-5 | Untagged 20% of last full month | Finding `cost-untagged-spend` |
| CST-6 | fetch with botocore Stubber, `WithResources` raises `DataUnavailableException`, coverage calls `AccessDeniedException` | `by_resource` null; other two kept; `unavailable` says which; note `access_denied: sp_coverage (ce:GetSavingsPlansCoverage)` |
| CST-7 | `periods(2026-11-04)` | Months `2026-08-01` to `2026-11-04`; resources `2026-10-21` to `2026-11-04` (end dates exclusive) |
