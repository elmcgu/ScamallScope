# References

Official docs and source used for the design. All links checked on 2026-11-04 (HTTP 200).
Where the docs did not say something and the source code did, the source is cited.

## AWS Well-Architected

- **R1** AWS Well-Architected Framework. https://docs.aws.amazon.com/wellarchitected/latest/framework/welcome.html
- **R2** The pillars of the framework. https://docs.aws.amazon.com/wellarchitected/latest/framework/the-pillars-of-the-framework.html
- **R3** Security Pillar. https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html
- **R4** Reliability Pillar. https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/welcome.html
- **R5** Cost Optimization Pillar. https://docs.aws.amazon.com/wellarchitected/latest/cost-optimization-pillar/welcome.html
- **R6** Best-practice pages, one per ID, for example SEC06-BP01:
  https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_vulnerability_management.html.
  All 177 Security, Reliability and Cost IDs, titles and links are in
  `collector/scamallscope/data/well_architected.json` (taken from the question pages
  `sec-01.html` to `sec-11.html`, `rel-01.html` to `rel-13.html` and `cost-01.html` to `cost-11.html`).

## Alternatives considered

- **R7** AWS Security Hub. https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html
- **R8** AWS Compute Optimizer. https://docs.aws.amazon.com/compute-optimizer/latest/ug/what-is-compute-optimizer.html

## Prowler

- **R9** OCSF 1.1.0 Detection Finding class. https://schema.ocsf.io/1.1.0/classes/detection_finding
- **R10** Prowler reporting (output formats, default folder `output`, file name
  `prowler-output-ACCOUNT_NUM-OUTPUT_DATE.format`). https://docs.prowler.com/user-guide/cli/tutorials/reporting
- **R11** Prowler OCSF writer: `status_code`, `severity`, `finding_info.uid`, `resources[].uid`,
  `resources[].region`, `metadata.event_code` (check ID), `unmapped.compliance`, `cloud.account.uid`.
  https://github.com/prowler-cloud/prowler/blob/master/prowler/lib/outputs/ocsf/ocsf.py
- **R12** Prowler mapping of checks to Well-Architected Security best practices.
  https://github.com/prowler-cloud/prowler/blob/master/prowler/compliance/aws/aws_well_architected_framework_security_pillar_aws.json
- **R13** Prowler mapping to Reliability best practices.
  https://github.com/prowler-cloud/prowler/blob/master/prowler/compliance/aws/aws_well_architected_framework_reliability_pillar_aws.json
  Compliance keys are `<Framework>-<Version>` or `<Framework>` when there is no version
  (`prowler/lib/outputs/compliance/compliance_check.py`), so the keys are
  `AWS-Well-Architected-Framework-Security-Pillar` and `AWS-Well-Architected-Framework-Reliability-Pillar`.

## Wazuh

- **R14** Wazuh server API: getting started (`POST /security/user/authenticate`, port 55000,
  `Authorization: Bearer`). https://documentation.wazuh.com/current/user-manual/api/getting-started.html
  and reference https://documentation.wazuh.com/current/user-manual/api/reference.html
- **R15** Wazuh indexer indices: `wazuh-states-vulnerabilities-*` holds vulnerabilities detected
  on monitored endpoints; `wazuh-states-inventory-system-*` OS details.
  https://documentation.wazuh.com/current/user-manual/wazuh-indexer/wazuh-indexer-indices.html
- **R16** Wazuh API spec v4.14.0: `GET /agents` returns `id`, `name`, `status`, `lastKeepAlive`,
  `os.name`, `os.version`, `os.platform`. https://github.com/wazuh/wazuh/blob/v4.14.0/api/api/spec/spec.yaml
- **R17** Wazuh dashboard queries on the vulnerabilities index: `vulnerability.severity` values are
  capitalised (`Critical`, `High`, `Medium`, `Low`), `package.name`. Wazuh 5.0 renames
  `agent.id` and `agent.name` to `wazuh.agent.id` and `wazuh.agent.name`.
  https://github.com/wazuh/wazuh-dashboard-plugins/blob/main/plugins/main/public/components/common/welcome/home-overview/lib/queries.md
- **R24** Wazuh vulnerability detection: the 4.8.0 release removed the server API's
  `/vulnerability` endpoint; results are in the indexer.
  https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html

## GitHub

- **R18** REST API: deployments (`GET /repos/{owner}/{repo}/deployments`, filters `sha`, `ref`,
  `task`, `environment`). https://docs.github.com/en/rest/deployments/deployments
- **R19** REST API: deployment statuses (states `error`, `failure`, `inactive`, `in_progress`,
  `queued`, `pending`, `success`). https://docs.github.com/en/rest/deployments/statuses
- **R20** Permissions for fine-grained personal access tokens ("Deployments" repository
  permission, read). https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens

## Ansible

- **R21** `ansible.posix.json` callback. https://docs.ansible.com/ansible/latest/collections/ansible/posix/json_callback.html
- **R22** Callback source: output `{"plays": [...], "stats": {host: {ok, changed, failures,
  unreachable, skipped, rescued, ignored}}}`.
  https://github.com/ansible-collections/ansible.posix/blob/main/plugins/callback/json.py
- **R23** Check mode ("dry run"): `--check` reports what would change.
  https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_checkmode.html

## CloudWatch

- **R25** `GetMetricData`. https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricData.html
- **R26** `DescribeAlarms`. https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_DescribeAlarms.html
- **R27** EC2 metrics: `AWS/EC2` `CPUUtilization`, dimension `InstanceId`, 5-minute data points by
  default. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html
- **R28** CloudWatch pricing. https://aws.amazon.com/cloudwatch/pricing/

## Prometheus, Loki, Grafana

- **R29** Prometheus HTTP API: `GET /api/v1/query`, response `data.resultType`, `result[].metric`,
  `result[].value` = `[unix_time, "value"]`. https://prometheus.io/docs/prometheus/latest/querying/api/
- **R30** Prometheus configuration, `ec2_sd_config` and the `__meta_ec2_instance_id` label.
  https://prometheus.io/docs/prometheus/latest/configuration/configuration/
- **R36** Loki HTTP API. https://grafana.com/docs/loki/latest/reference/loki-http-api/
- **R37** Grafana dashboard URL variables (`var-<name>=<value>`).
  https://grafana.com/docs/grafana/latest/dashboards/build-dashboards/create-dashboard-url-variables/

## Cost

- **R31** Cost allocation tags. https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/cost-alloc-tags.html
- **R32** `GetCostAndUsage` (`Granularity`, `Metrics`, up to two `GroupBy`, end date exclusive,
  tag group keys returned as `key$value`). https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsage.html
- **R33** `GetCostAndUsageWithResources` (opt-in, last 14 days only, must filter or group by
  resource ID, needs a `SERVICE` filter of `Amazon Elastic Compute Cloud - Compute`).
  https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsageWithResources.html
- **R34** Cost Explorer pricing ($0.01 per API request; resource-level data about $0.01 per 1,000
  usage records a month). https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/
- **R35** Cost Explorer resource-level daily data. https://docs.aws.amazon.com/cost-management/latest/userguide/ce-resource-daily.html
- **R40** Tagging best practices whitepaper. https://docs.aws.amazon.com/whitepapers/latest/tagging-best-practices/tagging-best-practices.html

## Other AWS

- **R38** Lambda runtimes and deprecation dates. https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
- **R39** S3 default encryption FAQ (all new objects encrypted with SSE-S3 by default since
  January 2023). https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-encryption-faq.html
