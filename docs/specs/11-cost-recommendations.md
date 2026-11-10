# 11 Cost Optimization Hub and commitment coverage

## Cost Optimization Hub (`fetch costhub`)

boto3 client `cost-optimization-hub`, Region `us-east-1`. `ListRecommendations` [R42],
`includeAllRecommendations` false (one recommendation per resource, the hub's best), paged with
`nextToken`. Also Compute Optimizer `GetEnrollmentStatus` (any Region) [R43].

If the hub is not enabled the call fails with `AccessDeniedException` or a validation error
that says so: store `"enabled": false` and no recommendations, and exit 0. Other errors fail the
fetch (exit 1, no file written).

Raw `integrations/costhub.json`:
`{"fetched_at", "enabled": bool, "compute_optimizer": "Active" | "Inactive" | ..., "recommendations": [items]}`.

## Findings

One per recommendation, source `costhub`, check `COST-HUB-<actionType>`.

| actionType | BP | Title |
|---|---|---|
| `Delete` | COST04-BP03 | Delete unused `<resource type>` `<id>` |
| `Stop` | COST04-BP03 | Stop idle `<resource type>` `<id>` |
| `Rightsize`, `Upgrade`, `MigrateToGraviton` | COST06-BP02 | Rightsize `<id>`: `<current>` to `<recommended>` |
| `PurchaseSavingsPlans`, `PurchaseReservedInstances` | COST07-BP04 | Buy `<recommended resource type>` commitment |
| other | COST06-BP02 | `<actionType>` `<id>` |

- `savings_usd` = `estimatedMonthlySavings` (rounded to 0.01). Severity by saving: >= 100
  `high`, >= 20 `medium`, >= 1 `low`, else `info`.
- `resource` = `resourceArn` when it is a node in the graph, else null with `resource_name` =
  `resourceId`.
- `detail`: effort, restart needed, rollback possible, lookback days.
- `remediation`: "Review in Cost Optimization Hub" with the console URL
  `https://console.aws.amazon.com/costmanagement/home#/cost-optimization-hub`.

Coverage: COST04-BP03, COST06-BP02, COST07-BP04 checked whenever the hub is enabled.
`meta.integrations.costhub` adds `enabled` and `compute_optimizer`.

## Commitment coverage (part of `fetch cost`)

`GetSavingsPlansCoverage` and `GetReservationCoverage`, last 30 days, `MONTHLY`, total only.
Both $0.01 a request [R34]. Raw: added to `cost.json` as `sp_coverage` and `ri_coverage`
(`null` if the call fails with the optional errors in spec 07).

`cost.coverage` in the graph: `{"savings_plans_pct", "reservations_pct", "on_demand_usd"}`.

## Tests

Stubber for every call (moto 5.2.5 has neither service).

| ID | Given | Then |
|---|---|---|
| COH-1 | Two pages of recommendations | Both pages in the raw file |
| COH-2 | Hub not enabled (AccessDeniedException) | `enabled` false, no error |
| COH-3 | Other ClientError | Fetch raises |
| COH-4 | Delete EBS volume, saving 12.5 | Finding COST-HUB-Delete, COST04-BP03, `savings_usd` 12.5, severity low |
| COH-5 | Rightsize instance, saving 150 | COST06-BP02, high, detail has effort |
| COH-6 | PurchaseSavingsPlans | COST07-BP04, `resource` null |
| COH-7 | `enabled` false | No findings, no coverage; meta says not enabled |
| CST-8 | Coverage responses | `cost.coverage` with both percentages |
| CST-9 | Coverage call fails with DataUnavailableException | `sp_coverage` null; rest of cost loaded |
