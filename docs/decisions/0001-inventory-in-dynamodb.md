# 0001: Keep the inventory in DynamoDB as current state plus a change log

- Status: proposed
- Date: 2026-11-03

## Context

ScamallScope is also an inventory. It runs once a day and must answer:

- What exists now?
- What is new, changed or deleted since yesterday?
- What is the history of one resource?

## Options

1. **Full daily snapshot per resource in DynamoDB.** Simple to write, but storage grows by
   (resources × days), and most days nothing changes.
2. **Current state plus a change log in DynamoDB.** Store each resource once, and write a
   change event only when something is created, changed or deleted.
3. **Daily JSON snapshot files in S3**, diffed by the collector. Cheapest and simplest, but
   "what changed" needs a diff or Athena query every time.
4. **AWS Config.** Already records configuration history, but costs per recorded item and
   covers only what Config supports. Leaves less to learn.

## Decision

Option 2, in one DynamoDB table (on-demand capacity):

| Item | PK | SK | Holds |
|---|---|---|---|
| Current resource | `RES#<arn>` | `CURRENT` | type, region, tags, config, `hash`, `first_seen`, `last_seen` |
| Change event | `DAY#<YYYY-MM-DD>` | `<arn>#<created\|changed\|deleted>` | old and new `hash`, list of changed fields |
| Run record | `RUN#<YYYY-MM-DD>` | `<timestamp>` | counts, errors, which services and regions succeeded |

- "What changed today": query `PK = DAY#<date>`.
- "History of one resource": a GSI on the ARN of change events.
- The daily graph JSON for the frontend goes to S3, built from the current items.

## Rules for the collector

- **Hash a normalised config:** sort keys and remove fields that change without a real
  change (timestamps, counters, `LastModified`), or every day shows false "changed" events.
- **Mark "deleted" only when that service and region collected without errors.** A failed
  API call must not look like every resource was deleted.
- **Items over 400 KB** (DynamoDB's limit, e.g. big IAM policies): put the config in S3 and
  store the S3 key in the item.
- **TTL on change events** (e.g. 365 days) to cap storage.

## Consequences

- Cheap: writes only on change, reads are single-key queries.
- Daily diffs come for free; no full diff of two snapshots.
- Normalisation rules need tuning per service before "changed" is trustworthy.
