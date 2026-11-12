# 03 Wazuh

## Input

Two calls, saved in one raw file `integrations/wazuh.json`:

```json
{"fetched_at": "...", "agents": <GET /agents response>, "vulnerabilities": <indexer _search response>}
```

1. **Server API** [R14, R16]. `POST /security/user/authenticate` with basic auth
   (`WAZUH_API_USER`, `WAZUH_API_PASSWORD`) returns `data.token`. Then
   `GET /agents?select=id,name,status,lastKeepAlive,os.name,os.version,os.platform&limit=500&offset=N`
   with `Authorization: Bearer <token>`, paged until `data.total_affected_items` is reached.
   Agent `000` is the manager: skipped.
2. **Indexer** [R15, R17, R24]. Since Wazuh 4.8 vulnerabilities are not in the server API; they
   are in the indexer. `POST <indexer>/wazuh-states-vulnerabilities-*/_search` with basic auth
   (`WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`). One aggregation request, no documents
   (`wazuh.vulnerability_query`):

   ```json
   {"size": 0,
    "query": {"terms": {"vulnerability.severity": ["Critical", "High", "Medium", "Low"]}},
    "aggs": {"by_agent.id": {"terms": {"field": "agent.id", "size": <number of agents>},
               "aggs": {"severity": {"terms": {"field": "vulnerability.severity", "size": 4}},
                        "packages": {"multi_terms": {"terms": [{"field": "package.name"},
                                     {"field": "package.version"}], "size": 5, "shard_size": 100}}}},
             "by_wazuh.agent.id": <the same on wazuh.agent.id>}}
   ```

   Both `agent.*` (4.x) and `wazuh.agent.*` (5.0) are read [R17, R61]. Counts by severity are exact
   however many vulnerabilities there are: they come from bucket counts, not from documents. No
   document fields are returned (`size` 0), so no CVE text or package paths leave the indexer.
   If `sum_other_doc_count` is above 0 (more agents than buckets), the parse records
   `vulns_truncated` (shown as a warning). Top package counts are per (name, version) and may be
   approximate on a many-shard index (`shard_size` 100). The agent bucket count times 10 must stay
   under the indexer's `search.max_buckets` (65,535 by default): about 6,500 agents.

   A raw file without `aggregations` (the old document search) is rejected: re-run `fetch wazuh`.

## Matching

Agent `name` to instance, using `hosts.Index` (see PROJECT.md "Matching"). Unmatched agent names
go to `unmatched`.

## Output per instance (`wazuh` on the node)

`agent_id`, `agent_name`, `status`, `last_keepalive`, `os_name`, `os_version`, `os_platform`,
`vulns` (counts by severity), `top_packages` (up to 5: name, version, count of CVEs, most first).

## Findings

| Check | When | Severity | BP |
|---|---|---|---|
| `wazuh-vulnerable-packages` | Host has at least one vulnerability | Highest severity found | SEC06-BP01 |
| `wazuh-agent-not-active` | `status` is not `active` | medium | SEC04-BP01 |

Detail for vulnerable packages: `"2 critical, 5 high, 0 medium, 1 low (top: openssl 3.0.2)"`.
Coverage: SEC06-BP01 and SEC04-BP01 for each matched agent.

## Tests

| ID | Given | Then |
|---|---|---|
| WAZ-1 | Agents fixture with manager `000` and 3 agents | 3 agents parsed, OS fields kept |
| WAZ-2 | Agent name = instance id | Matched to that instance |
| WAZ-3 | Agent name = `Name` tag that two instances share | Not matched; in `unmatched` |
| WAZ-4 | Vulns for agent 001: 1 Critical, 2 High | `vulns` = {critical 1, high 2, medium 0, low 0}; finding severity critical |
| WAZ-5 | Vulns using `wazuh.agent.id` (5.0 shape) | Counted the same as `agent.id` |
| WAZ-6 | Agent `disconnected` | Finding `wazuh-agent-not-active` |
| WAZ-7 | An agent aggregation with `sum_other_doc_count` > 0 | `vulns_truncated` noted; none on the full fixture |
| WAZ-8 | `top_packages` | At most 5, sorted by count, then name and version |
| WAZ-9 | fetch: auth then paged agents (fake urlopen) | Bearer header sent; 2 pages read; password not in any error text |
| WAZ-10 | fetch: indexer URL not https | `ValueError` before any request |
| WAZ-11 | 6,000 critical and 1,000 low in the bucket counts, no documents | `vulns` exact; title says 7000 |
| WAZ-12 | `vulnerability_query(42)` | `size` 0, no `_source`, both agent aggregations of size 42 |
| WAZ-13 | Raw file in the old document shape | `ValueError` naming `aggregations` |
| HST-1 | Index from snapshot | Keys: instance id, Name tag, `scamallscope:host` tag, short private DNS; all lower-case |
| HST-2 | Match is case-insensitive and trims a domain (`web-1.example.internal` -> `web-1`) | Matched |
