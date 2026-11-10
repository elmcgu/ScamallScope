# 0003: Read AWS's own recommenders for cost; keep our rules as a fallback and for joins

- Status: accepted (2026-11-10, Ellis)
- Date: 2026-11-10

## Context

Phase B adds cost savings and availability risks to the security findings. Some of these
answers are already computed by AWS from data we cannot see (billing discounts, memory and
network metrics, 14 days of utilisation): Cost Optimization Hub, Compute Optimizer and Trusted
Advisor [R41, R43, R44]. Others need joins across sources that no AWS service makes, for example
"single instance, not in an Auto Scaling group, tagged prod, no backup in 7 days".

## Options

1. **Write all rules ourselves** from the inventory and CloudWatch. One code path, but our
   savings estimates ignore discounts and our idle rule sees only CPU.
2. **Read Cost Optimization Hub (which includes Compute Optimizer) through boto3, and keep our
   own rules where AWS has no answer or as a fallback.** Two code paths for cost, but the savings
   numbers match what the AWS console shows.
3. **Read Trusted Advisor.** It covers security, fault tolerance and cost in one API, but the API
   needs a Business Support+, Enterprise or Unified Operations plan [R44].

## Decision

Option 2.

- `fetch costhub` reads `ListRecommendations` [R42] and Compute Optimizer's enrolment status.
  Each recommendation becomes a cost finding with the hub's estimated monthly saving.
- When the hub is loaded, our CPU idle rule (HYG-EC2-002) does not run, and our own cost rules
  that find the same resource (for example an unattached volume) are marked as duplicates of the
  hub finding.
- When the hub is not loaded, our cost rules run and show savings from a dated price table in
  the code, labelled "estimate".
- Trusted Advisor is not used. Security stays with Prowler and our rules (decision 0002).

## Consequences

- Savings shown match the console when the hub is enabled. With it off, they are rough.
- Compute Optimizer needs an opt-in and 14 days of metrics before it recommends anything [R43].
  The UI shows "not enabled" so an empty list is never read as "nothing to save".
- One more read-only identity permission set: `cost-optimization-hub:ListRecommendations`,
  `compute-optimizer:GetEnrollmentStatus`.
- The price table must be updated by hand. Phase E replaces it with the Price List API.
