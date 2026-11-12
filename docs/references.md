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

## Added 2026-11-10 (Phase B research)

Checked on 2026-11-10. API shapes also checked against the botocore 1.43.123 service models.

- **R41** Cost Optimization Hub: consolidates rightsizing, idle deletion, Savings Plans and RI
  recommendations with estimated savings; supported resources include EC2, Auto Scaling groups,
  EBS, Lambda, Fargate, RDS, NAT gateways. Rightsizing and idle come from Compute Optimizer.
  https://docs.aws.amazon.com/cost-management/latest/userguide/cost-optimization-hub.html
- **R42** Cost Optimization Hub `ListRecommendations` (botocore model: `filter`, `orderBy`,
  `includeAllRecommendations`, `maxResults`, `nextToken`; item fields `resourceArn`, `actionType`,
  `estimatedMonthlySavings`, `estimatedMonthlyCost`, `currencyCode`, `implementationEffort`,
  `restartNeeded`, `rollbackPossible`, `recommendationLookbackPeriodInDays`).
  https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_cost-optimization-hub_ListRecommendations.html
  (page did not render on 2026-11-10; shape taken from botocore)
- **R43** Compute Optimizer: opt-in required, analyses 14 days of CloudWatch metrics, finds idle
  resources. https://docs.aws.amazon.com/compute-optimizer/latest/ug/what-is-compute-optimizer.html
- **R44** Trusted Advisor: checks and API need Business Support+, Enterprise or Unified Operations;
  Basic gets service limits and selected security and fault tolerance checks in the console only.
  https://docs.aws.amazon.com/awssupport/latest/user/trusted-advisor.html
- **R45** REL10-BP01 Deploy the workload to multiple locations (at least two AZs; RDS, ElastiCache,
  Redshift need Multi-AZ turned on; load balancers in front of compute).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_fault_isolation_multiaz_region_system.html
- **R46** REL11-BP03 Automate healing on all layers (anti-patterns: no autoscaling, single
  instances, no database failover; EC2 automatic recovery for single instances).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_withstand_component_failures_auto_healing_system.html
- **R47** REL09-BP03 Perform data backup automatically (AWS Backup, RDS PITR, Data Lifecycle Manager).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_backing_up_data_automated_backups_data.html
- **R48** COST04-BP03 Decommission resources.
  https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_decomissioning_resources_decommission.html
- **R49** COST08-BP02 Select components to optimize data transfer cost (VPC endpoints, NAT gateway
  in the same AZ as its heaviest users).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_data_transfer_optimized_components.html
- **R50** SEC08-BP02 Enforce encryption at rest (EBS encryption by default, RDS encryption).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_rest_encrypt.html
- **R51** SEC09-BP02 Enforce encryption in transit (no HTTP to public resources, HTTPS listeners,
  no deprecated TLS, replace certificates before expiry).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_data_transit_encrypt.html
- **R52** SEC04-BP01 Configure service and application logging (CloudTrail trail, VPC Flow Logs,
  Route 53 resolver logs, GuardDuty).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_detect_investigate_events_app_service_logging.html
- **R53** SEC06-BP03 Reduce manual management and interactive access (no 22 or 3389 in security
  groups, SSM Agent and `AmazonSSMManagedInstanceCore`).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_protect_compute_reduce_manual_management.html
- **R54** SEC02-BP05 Audit and rotate credentials periodically (credential report, rotate access
  keys at most every 90 days). https://docs.aws.amazon.com/wellarchitected/latest/framework/sec_identities_audit.html
- **R55** VPC pricing: public IPv4 address, in use or idle, $0.005 per hour. https://aws.amazon.com/vpc/pricing/
- **R56** COST07-BP04 Implement pricing models for all components of this workload (Savings
  Plans and RIs for always-on resources; review coverage).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_pricing_model_implement_models.html
- **R57** COST06-BP03 Select resource type, size, and number automatically based on metrics
  (Compute Optimizer, Auto Scaling, S3 Intelligent-Tiering).
  https://docs.aws.amazon.com/wellarchitected/latest/framework/cost_type_size_number_resources_metrics.html
- **R58** EC2 automatic instance recovery: simplified automatic recovery is on by default on
  supported instances (`MaintenanceOptions.AutoRecovery`); CloudWatch action based recovery needs
  an alarm. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-recover.html
- **R60** Introducing Cost Optimization Hub (What's New, November 2023): no additional cost in
  all Regions except the AWS China and AWS GovCloud (US) Regions.
  https://aws.amazon.com/about-aws/whats-new/2023/11/cost-optimization-hub
- **R59** EBS pricing worked examples: gp3 $0.08, gp2 $0.10, io1 and io2 $0.125, st1 $0.045,
  sc1 $0.015 per GB-month; snapshots $0.05 per GB-month. The examples do not name a Region.
  https://aws.amazon.com/ebs/pricing/
- **R61** OpenSearch multi-terms aggregation: `terms` array, `size`, `shard_size`; buckets with
  `key` (array), `key_as_string` and `doc_count`, ordered by count descending; response has
  `sum_other_doc_count`. Checked 2026-11-12; not yet run against a real Wazuh indexer.
  https://docs.opensearch.org/latest/aggregations/bucket/multi-terms/
- **R62** Cost Optimization Hub `ListEnrollmentStatuses` (botocore model, boto3 in uv.lock):
  input `includeOrganizationInfo`, `accountId`, `nextToken`, `maxResults`; output `items`
  (`accountId`, `status` `Active` | `Inactive`), `includeMemberAccounts`, `nextToken`; errors
  `ValidationException`, `InternalServerException`, `AccessDeniedException`, `ThrottlingException`.
  Cost Explorer `GetCostAndUsageWithResources` errors include `DataUnavailableException`; it is
  opt-in. https://docs.aws.amazon.com/aws-cost-management/latest/APIReference/API_GetCostAndUsageWithResources.html
