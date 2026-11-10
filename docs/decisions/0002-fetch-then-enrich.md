# 0002: Integrations fetch raw data to files, then a pure "enrich" step builds the graph

- Status: proposed (2026-11-04)
- Date: 2026-11-04

## Context

ScamallScope adds data from Prowler, Wazuh, GitHub, Ansible, CloudWatch, Prometheus and Cost
Explorer to the AWS inventory graph. These sources need different credentials and network
access, some are files (Prowler, Ansible), and some will not be available in every run.
The demo must work with made-up data first, then with real data, with no code change.

## Options

1. **Each integration calls its API inside graph building.** One step, but tests need every API
   mocked, and a demo needs every service running.
2. **Fetch raw responses to files, then enrich from files.** Two steps. Fetch is thin and needs
   network and credentials. Enrich is pure: files in, graph out.
3. **Send everything to AWS Security Hub** [R7] and read it back. Security Hub accepts OCSF and
   ASFF findings, but it has no resource graph, charges per finding and check, and does not hold
   OS inventory, deployments or cost.
4. **Build dashboards in Grafana** from the same sources. Good for time series, poor for a
   resource graph and for joining "this instance" across seven sources.

## Decision

Option 2.

- `scamallscope fetch <source>` writes the API response as it came, plus `fetched_at`, to
  `integrations/<source>.json` (mode `0600`, git-ignored). Prowler and Ansible already write
  files, so they have no fetch step: copy their output into `integrations/`.
- `scamallscope enrich <snapshot> --integrations integrations/` reads whatever files exist and
  writes `graph.json` (schema version 2).
- A source whose file is missing is "not loaded": its checks report **not checked**.
- Fake data is a set of raw files with the same shape as the real responses
  (`collector/tests/fixtures/` and `scripts/make_sample.py`), so tests, the demo and real runs
  all use the same parsing code.

## Consequences

- Most code (parsing, matching, rules, scorecard) is tested without network or mocks.
- Raw files are an audit trail: you can see exactly what a source said on a given day.
- Raw files are sensitive (host names, package versions). They get the same handling as
  snapshots: `0600`, git-ignored, never in `samples/`.
- Two commands instead of one. The scheduled job (roadmap 4) runs them in order.
- If an API changes shape, the parser for that source fails with a clear error and that source
  becomes "not loaded"; the rest of the graph is still built.
