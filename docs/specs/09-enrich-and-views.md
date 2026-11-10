# 09 Enrich and UI views

## Enrich

```bash
uv run scamallscope enrich snapshots/<file>.snapshot.json --integrations integrations/ \
  [--required-tags owner,env] [--ansible-mode check] [--output <file>.graph.json]
```

Writes graph schema version 2 (architecture.md). Exit codes: `0` all good, `2` snapshot partial
or a raw file could not be parsed (graph still written), `1` snapshot unreadable.
Prints one line per source: loaded or not, findings, matched, unmatched.

## UI

A view switch in the header: **Map**, **Findings**, **Hosts**, **Cost**, **Well-Architected**.
Version 1 graphs show only Map (other views say "Load a graph built with `enrich`").

| View | Shows | Interaction |
|---|---|---|
| Map | As today. New "Colour by": exposure (default), worst finding severity, monthly cost | Node details panel adds sections per source (Wazuh, deployment, Ansible, metrics, cost, findings) |
| Findings | Table: severity, pillar, title, resource, source, BPs | Filter by pillar, severity, source, text; sorted by severity then pillar then title; click a row to open the resource on the map |
| Hosts | One row per instance: name, region, state, exposure, OS, vulns (C/H/M/L), agent, last deploy, Ansible, CPU avg, alarms, cost | Sort by any column |
| Cost | Monthly totals, by service (top 10), by tag, top 10 instances by cost, idle cost | None |
| Well-Architected | Per pillar: counts of issues, clear, not checked; table of BPs with status and link to the AWS page | Filter by status (default: issues and clear) |

All text is set with `textContent`. Links: only `https://` URLs, `rel="noopener noreferrer"`,
`target="_blank"`.

## Tests

| ID | Given | Then |
|---|---|---|
| ENR-1 | Snapshot and no integrations | Graph v2; findings only from inventory rules; integrations all `loaded: false` |
| ENR-2 | All fixture files | Every source `loaded: true`; finding ids unique |
| ENR-3 | Broken `wazuh.json` | Wazuh `loaded: false` with `error`; others loaded; exit code 2 |
| ENR-4 | Node of an instance with Wazuh, deploy, Ansible, metrics, cost | All five keys present |
| ENR-5 | `finding_counts` | Matches findings for that resource |
| ENR-6 | Graph JSON | No IP addresses (no `PrivateIpAddress`, no dotted-quad values except CIDRs in rules) |
| ENR-7 | `idle_monthly_usd` | Sum of cost of instances with HYG-EC2-002 |
| VIEW-1 | `filterFindings` by pillar and severity | Only matching rows |
| VIEW-2 | `sortFindings` | critical before high; then pillar, title |
| VIEW-3 | `hostRows` | One row per instance, with OS and vulns from `wazuh` |
| VIEW-4 | `costSummary` | Last full month total, top services sorted by cost |
| VIEW-5 | `postureRows` with status filter | Only those statuses |
| VIEW-6 | `safeUrl` | `https://...` kept; `javascript:`, `http:`, other values null |
| VIEW-7 | `colourBy` severity | Node class from worst finding severity |
| VIEW-8 | v1 graph | `hasEnrichment` false |
