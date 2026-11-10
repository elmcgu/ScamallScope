# 06 Metrics and logs

## CloudWatch (demo)

Per region, for running instances in the snapshot:

- `GetMetricData` [R25]: one query per instance, `AWS/EC2` `CPUUtilization`, dimension
  `InstanceId` [R27], period 3600 s, stat `Average`, and a second query with stat `Maximum`;
  last 14 days. Up to 500 queries per call; paged with `NextToken`.
- `DescribeAlarms` [R26] (metric alarms), paged. An instance "has an alarm" when an alarm's
  `Dimensions` include its `InstanceId`.

Raw `integrations/cloudwatch.json`:
`{"fetched_at", "days": 14, "regions": {"eu-west-1": {"queries": {"<query id>": "<instance id>|avg"}, "results": [MetricDataResults], "alarms": [MetricAlarms]}}}`.

Output per instance (`metrics`): `cpu_avg`, `cpu_max` (rounded to 0.1), `days`, `alarms`
(count). No data points: `cpu_avg` null (it is not "idle").

The idle and no-alarm rules are hygiene rules (spec 08), because they need inventory state.

## Prometheus (demo)

`GET <url>/api/v1/query?query=up` [R29], optional `PROMETHEUS_BEARER_TOKEN`. Raw
`integrations/prometheus.json`: `{"fetched_at", "response": <API response>}`.

Each series in `data.result` is matched to an instance by label `instance_id` (recommended:
relabel `__meta_ec2_instance_id` to `instance_id` in `ec2_sd_configs` [R30]), else by the host
part of label `instance` (`web-1:9100` -> `web-1`) with `hosts.Index`.

Output per instance: `metrics.prom_up` = lowest `up` value among its series (0 or 1).

## Loki (planned)

`GET <url>/loki/api/v1/query` [R36] with a LogQL metric query such as
`sum by (host) (count_over_time({job="varlogs"} |= "error" [24h]))`. Output per instance:
`logs.errors_24h`. Rule: errors over a threshold, REL06-BP05 "Analyze logs". Not built: the
label that names the host differs per setup, so it needs a real Loki to design against.

## Grafana (planned)

No API call. `--grafana-url-template "https://grafana.example/d/abc/node?var-instance={instance_id}"`
adds a link on each instance [R37]. Only `https://` templates are accepted.

## Tests

| ID | Given | Then |
|---|---|---|
| CWM-1 | Results for 2 instances (avg and max) | `cpu_avg`, `cpu_max` per instance |
| CWM-2 | Instance with empty `Values` | `cpu_avg` null |
| CWM-3 | Alarm with `InstanceId` dimension | `alarms` 1 for that instance, 0 for others |
| CWM-4 | fetch with moto: 2 instances, 1 alarm | Raw file has both query ids and the alarm |
| CWM-5 | Query ids | Valid CloudWatch ids (start lower-case letter, `[a-zA-Z0-9_]`) and unique |
| PRM-1 | `up` vector with `instance_id` label = instance id | `prom_up` 1 |
| PRM-2 | Series with only `instance="prod-app-1:9100"` | Matched by Name tag |
| PRM-3 | Two series for one instance, values 1 and 0 | `prom_up` 0 |
| PRM-4 | `status: error` response | `ValueError` |
