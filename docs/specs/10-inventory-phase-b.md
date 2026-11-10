# 10 Inventory for availability, cost and account controls

All calls are read-only, through boto3, in the same `collect` run as today. Each listing is one
unit (`units` in the snapshot): a failed unit means "unknown", never "nothing there".

## New resource types

| Type | Service | Call | Per | Links |
|---|---|---|---|---|
| `volume` | ec2 | `DescribeVolumes` | region | volume `attached` instance |
| `snapshot` | ec2 | `DescribeSnapshots` (`OwnerIds=["self"]`) | region | snapshot `snapshot_of` volume |
| `elastic-ip` | ec2 | `DescribeAddresses` (no paginator) | region | elastic-ip `attached` instance |
| `nat-gateway` | ec2 | `DescribeNatGateways` (skip `deleted`) | region | subnet `contains` nat-gateway; route-table `routes_to` nat-gateway |
| `vpc-endpoint` | ec2 | `DescribeVpcEndpoints` | region | vpc `contains` vpc-endpoint |
| `flow-log` | ec2 | `DescribeFlowLogs` | region | flow-log `logs` vpc, subnet or ENI |
| `db-instance` | rds | `DescribeDBInstances` | region | vpc `contains` db-instance; db-instance `uses` security group |
| `load-balancer` | elbv2 | `DescribeLoadBalancers`, `DescribeListeners`, `DescribeSslPolicies`, `DescribeTags` | region | vpc `contains` lb; lb `uses` security group; lb `routes_to` target group |
| `target-group` | elbv2 | `DescribeTargetGroups`, `DescribeTargetHealth` | region | target-group `targets` instance |
| `autoscaling-group` | autoscaling | `DescribeAutoScalingGroups` | region | asg `manages` instance; asg `registers` target group |
| `certificate` | acm | `ListCertificates`, `DescribeCertificate` | region | |
| `trail` | cloudtrail | `DescribeTrails` (`includeShadowTrails`), `GetTrailStatus` in the trail's home Region | global | |
| `credential-report` | iam | `GenerateCredentialReport`, `GetCredentialReport` | global | |
| `setting` | ec2, guardduty, backup, ssm | see below | region | |

Listeners are kept in the load balancer's `config.Listeners`, each with `SslProtocols` from
`DescribeSslPolicies` for its policy, so the TLS rule uses AWS's own list of protocols per
policy instead of a list of policy names in our code. Target health is kept in the target group's
`config.TargetHealth`.

## Settings (one `setting` resource per Region and setting)

ARN `arn:<partition>:<service>:<region>:<account>:scamallscope-setting/<id>`. This is not a real
AWS ARN; it gives the setting a stable key in the inventory, so a change (for example EBS default
encryption turned off) shows in the change log (decision 0001).

| id | Call | `config` |
|---|---|---|
| `ebs-encryption-by-default` | `ec2:GetEbsEncryptionByDefault` | `{"Enabled": bool}` |
| `guardduty` | `guardduty:ListDetectors`, `GetDetector` | `{"Detectors": [{"Id", "Status"}]}` |
| `backup-protected` | `backup:ListProtectedResources` | `{"Resources": [{"ResourceArn", "ResourceType", "LastBackupTime"}]}` |
| `ssm-managed` | `ssm:DescribeInstanceInformation` | `{"Instances": [{"InstanceId", "PingStatus"}]}` |

## Credential report

`GenerateCredentialReport` is called, then `GetCredentialReport` until the report is ready
(up to 10 tries, 2 s apart). The CSV is parsed into `config.Rows`, one dict per user including
`<root_account>`. Only these columns are kept: `user`, `arn`, `password_enabled`, `mfa_active`,
`access_key_1_active`, `access_key_1_last_rotated`, `access_key_1_last_used_date`, and the
same three for key 2. `GenerateCredentialReport` makes a report; it changes no IAM setting.

## Graph fields (no IP addresses, as before)

| Type | Fields |
|---|---|
| volume | `size_gb`, `volume_type`, `state`, `encrypted`, `availability_zone`, `attached_to` |
| snapshot | `size_gb`, `encrypted`, `start_time`, `volume_id`, `managed_by` (`backup`, `dlm` or null) |
| elastic-ip | `associated` (bool) |
| nat-gateway | `availability_zone`, `state` |
| vpc-endpoint | `service_name`, `endpoint_type` |
| db-instance | `engine`, `instance_class`, `multi_az`, `encrypted`, `publicly_accessible`, `backup_retention_days`, `availability_zone`, `cluster` |
| load-balancer | `scheme`, `lb_type`, `availability_zones`, `listeners` (protocol, port, redirects_to_https, tls_protocols) |
| target-group | `protocol`, `port`, `healthy`, `unhealthy` |
| autoscaling-group | `availability_zones`, `min`, `max`, `desired`, `health_check_type` |
| certificate | `not_after`, `in_use`, `renewal_eligibility`, `cert_type` |
| instance (added) | `availability_zone`, `imds_v2_required`, `auto_recovery` |

The map shows the types it has icons for. Snapshots, settings, trails, the credential report and
certificates are not drawn on the map; they feed rules and views.

## Permissions added

`ec2:DescribeVolumes`, `ec2:DescribeSnapshots`, `ec2:DescribeAddresses`,
`ec2:DescribeNatGateways`, `ec2:DescribeVpcEndpoints`, `ec2:DescribeFlowLogs`,
`ec2:GetEbsEncryptionByDefault`, `rds:DescribeDBInstances`,
`elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeListeners`,
`elasticloadbalancing:DescribeSSLPolicies`, `elasticloadbalancing:DescribeTargetGroups`,
`elasticloadbalancing:DescribeTargetHealth`, `elasticloadbalancing:DescribeTags`,
`autoscaling:DescribeAutoScalingGroups`,
`acm:ListCertificates`, `acm:DescribeCertificate`, `cloudtrail:DescribeTrails`,
`cloudtrail:GetTrailStatus`, `iam:GenerateCredentialReport`, `iam:GetCredentialReport`,
`guardduty:ListDetectors`, `guardduty:GetDetector`, `backup:ListProtectedResources`,
`ssm:DescribeInstanceInformation`.

## Tests

moto for all calls except `backup:ListProtectedResources` and `ssm:DescribeInstanceInformation`
(not implemented in moto 5.2.5): those use botocore `Stubber`.

| ID | Given | Then |
|---|---|---|
| INV-1 | Volume attached to an instance, one unattached | Two `volume` resources; `attached` link for the first |
| INV-2 | Own snapshot of a volume | `snapshot` resource with `snapshot_of` link |
| INV-3 | Elastic IP associated with an instance, one not | `elastic-ip` x2, one `attached` link |
| INV-4 | NAT gateway in a subnet, route table routing to it | `contains` and `routes_to` links |
| INV-5 | VPC endpoint and flow log on a VPC | Both resources, links to the VPC |
| INV-6 | EBS encryption by default off | Setting `ebs-encryption-by-default` with `Enabled` false |
| INV-7 | RDS instance in a VPC | `db-instance` with `MultiAZ`, `StorageEncrypted`, `PubliclyAccessible`; `contains` link |
| INV-8 | ALB with HTTP listener and HTTPS listener, target group with one instance | Listeners in config with `SslProtocols`; `routes_to` and `targets` links |
| INV-9 | ASG with an instance and a target group | `manages` and `registers` links; AZs in config |
| INV-10 | ACM certificate | `certificate` with `NotAfter` |
| INV-11 | Multi-Region trail | `trail` with `IsMultiRegionTrail` and `IsLogging` |
| INV-12 | IAM user with an access key | Credential report row for the user and for `<root_account>`; only listed columns kept |
| INV-13 | GuardDuty detector in one Region | Setting `guardduty` with one detector |
| INV-14 | Stubbed Backup and SSM responses | Settings `backup-protected` and `ssm-managed` |
| INV-15 | A new unit raises AccessDenied | Unit `error`; other units `ok`; snapshot partial |
| INV-16 | Graph | New fields present; no `PublicIp` or `PrivateIpAddress` values |
