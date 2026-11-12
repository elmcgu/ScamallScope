# 0001: Keep the inventory in DynamoDB as current state plus a change log

- Status: accepted (2026-11-04)
- Date: 2026-11-03
- Updated: 2026-11-04 (keys, storage format and write rules refined while building it);
  2026-11-12 (account ID in the day and run keys, collection time in the change sort key)

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

Option 2, in one DynamoDB table (on-demand capacity), defined in `infra/inventory-table.yaml`:

| Item | pk | sk | Holds |
|---|---|---|---|
| Current resource | `CUR#<account>#<region>` | `<arn>` | type, region, name, tags, `config_json`, `hash`, `first_seen`, `last_changed` |
| Change event | `DAY#<account>#<YYYY-MM-DD>` | `<collected_at>#<arn>#<created\|changed\|deleted>` | old and new `hash`, `changed_fields`, `gsi1pk`/`gsi1sk`, `expires_at` |
| Run record | `RUN#<account>#<YYYY-MM-DD>` | `<collected_at>` | counts, units (which services and regions succeeded) |

- "Current state of a region": query `pk = CUR#<account>#<region>`. (First draft used
  `RES#<arn>` per resource, which can only be listed with a full Scan.)
- "What changed today": query `pk = DAY#<account>#<date>`. Results come back in time order.
- The account ID is in every partition key, so several accounts can share one table.
  (First draft used `DAY#<date>` and `RUN#<date>`, which mix accounts.)
- `collected_at` is in the change sort key, so two runs on one day keep both events. (First
  draft used `<arn>#<kind>`, so a second "changed" on the same day replaced the first.) The
  key is still deterministic: the same snapshot run again writes the same keys.
- "History of one resource": the sparse GSI `by-arn` (`gsi1pk = ARN#<arn>`). Only change
  events set `gsi1pk`, so the index holds history and nothing else.
- The daily graph JSON for the frontend goes to S3, built from the current items.

### Storage format

- `config` is stored as one JSON string (`config_json`), not a DynamoDB map. It is always read
  or hashed whole, and a string avoids the Decimal conversion DynamoDB needs for numbers.
- Fields used to find or filter items are top-level attributes.

## Rules for the collector

- **Hash a normalised config:** remove fields that change without a real change
  (`LaunchTime`, `AttachTime`, `UsageOperationUpdateTime`, extend per service) and sort lists,
  or every day shows false "changed" events.
- **Write only on change.** An unchanged resource is not rewritten (no daily `last_seen`):
  DynamoDB charges an update by the size of the whole item. The run record says when each
  region and type was last seen.
- **Mark "deleted" only when that service and region collected without errors.** A failed
  API call must not look like every resource was deleted. Regions not in the run are left alone.
- **Items over 400 KB** (DynamoDB's limit, e.g. big IAM policies): today the item is stored
  without `config_json` and flagged `config_truncated`; the hash still detects changes.
  Next step when IAM is collected: put the config in S3 and store the key.
- **TTL on change events** (365 days) to cap storage.
- **Safe to re-run:** writes go events, then current items, then the run record, with
  deterministic keys. A run that fails part way can be run again.

## Cost notes

- At one account (about 2,000 resources) this costs well under $1 a month.
- Run the collector outside a VPC: a NAT Gateway (about $30+ a month) would cost more than
  everything else together.

## Consequences

- Cheap: writes only on change, reads are single-key queries.
- Daily diffs come for free; no full diff of two snapshots.
- Normalisation rules need tuning per service before "changed" is trustworthy.
