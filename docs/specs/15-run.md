# 15 One command for a whole run

`scamallscope run` does `collect`, then each `fetch` that has its inputs, then `enrich`, and writes
everything for that run into one folder. The separate commands stay for running one step.

```bash
uv run scamallscope run --profile <read-only-profile> --region eu-west-1 \
  [--output-dir runs/<name>] [--skip cost,costhub] \
  [--wazuh-url https://<wazuh>:55000 --wazuh-indexer-url https://<indexer>:9200] [--ca-file ca.pem] \
  [--prometheus-url https://<prometheus>] [--add <prowler-output>/prowler-output-x.ocsf.json] \
  [--tag-key env] [--required-tags owner,env] [--env-tag env] [--app-tag app] [--ansible-mode check]
```

## Folder

Default `runs/<account>-<UTC time>/` (git-ignored: real data). All files mode `0600`.

```
snapshot.json
integrations/<source>.json   one per fetch that ran, plus each --add file
graph.json                   enrich of the two above
```

## Which fetches run

| Fetch | Runs when |
|---|---|
| `cloudwatch`, `cost`, `costhub` | Always (same AWS profile), unless in `--skip`. `cost` costs $0.01 a request, 5 a run |
| `wazuh` | `--wazuh-url`, `--wazuh-indexer-url` and the four `WAZUH_*` variables are set |
| `github` | A resource has a `scamallscope:repo` tag and `GITHUB_TOKEN` is set |
| `prometheus` | `--prometheus-url` is given (`PROMETHEUS_BEARER_TOKEN` optional) |

A fetch that cannot run prints why and is left out. A fetch that fails prints the error (no
credentials, as in `fetch`), writes no file, and the run goes on. Prowler and Ansible have no
fetch: pass their files with `--add`.

## Exit codes

`1`: no region, the account cannot be identified, or `--skip` names an unknown fetch (nothing
written). `2`: the snapshot is partial, a fetch failed, or `enrich` could not parse a raw file.
`0`: everything that ran succeeded.

## Tests

`collector/tests/test_run.py`, moto for AWS, fixtures for the AWS fetches.

| ID | Given | Then |
|---|---|---|
| RUN-1 | No options but the Region | Folder has snapshot, three AWS raw files and graph, all `0600`; graph loads cost and costhub |
| RUN-2 | Wazuh URLs without `WAZUH_*`; no repo tags; no Prometheus URL | Each printed as not fetched with the reason; exit 0 |
| RUN-3 | `cost` fetch raises | Exit 2; no `cost.json`; other raw files and graph written |
| RUN-4 | `--skip cost,costhub --add prowler.ocsf.json` | Only cloudwatch fetched; Prowler file copied and loaded |
| RUN-5 | `--skip nope` | Exit 1; nothing written |
