# scamallscope collector

Read-only AWS collector. It writes a JSON snapshot of resources and the links between them.

## Run

```bash
cd collector
uv sync
uv run scamallscope collect --profile <read-only-profile> --region eu-west-1
uv run scamallscope graph snapshots/<file>.snapshot.json   # -> <file>.graph.json
uv run scamallscope inventory snapshots/<file>.snapshot.json --table scamallscope-inventory
uv run scamallscope changes --table scamallscope-inventory --date 2026-11-04
uv run scamallscope history --table scamallscope-inventory --arn <arn>
uv run scamallscope fetch cloudwatch --snapshot snapshots/<file>.snapshot.json --profile <read-only-profile>
uv run scamallscope fetch cost --profile <read-only-profile> [--tag-key env]
uv run scamallscope fetch costhub --profile <read-only-profile>     # Cost Optimization Hub + Compute Optimizer status
WAZUH_API_USER=... WAZUH_API_PASSWORD=... WAZUH_INDEXER_USER=... WAZUH_INDEXER_PASSWORD=... \
  uv run scamallscope fetch wazuh --url https://<wazuh>:55000 --indexer-url https://<indexer>:9200 [--ca-file ca.pem]
GITHUB_TOKEN=... uv run scamallscope fetch github --snapshot snapshots/<file>.snapshot.json
uv run scamallscope fetch prometheus --url https://<prometheus>      # PROMETHEUS_BEARER_TOKEN optional
cp <prowler-output>/prowler-output-*.ocsf.json integrations/prowler.ocsf.json
ANSIBLE_STDOUT_CALLBACK=ansible.posix.json ansible-playbook site.yml --check > integrations/ansible.json
uv run scamallscope enrich snapshots/<file>.snapshot.json --integrations integrations/   # -> graph v2
uv run python scripts/make_sample.py   # demo: made-up estate and integration data -> samples/
uv run pytest                          # uv run pytest -k WAZ  runs one spec's tests (IDs in docs/specs/)
uv run pyright                         # type check (TypedDict shapes)
```

Try `enrich` on the made-up sample: `uv run scamallscope enrich ../samples/demo.snapshot.json --integrations ../samples/integrations --output /tmp/demo.graph.json`.

Never put a password or token on the command line; `fetch` reads them from the environment
only. Shell history keeps what you type: set them with `read -rs WAZUH_API_PASSWORD; export WAZUH_API_PASSWORD`.

The snapshot goes to `snapshots/` (git-ignored) with mode `0600`. Exit code `0` = all units
collected, `2` = partial snapshot (see the `units` list for errors).

## Permissions

Only these read-only actions:

- `sts:GetCallerIdentity`
- `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`
- `ec2:DescribeRouteTables`, `ec2:DescribeInternetGateways`, `ec2:DescribeNetworkAcls`
- `ec2:DescribeVolumes`, `ec2:DescribeSnapshots` (own only), `ec2:DescribeAddresses`, `ec2:DescribeNatGateways`,
  `ec2:DescribeVpcEndpoints`, `ec2:DescribeFlowLogs`, `ec2:GetEbsEncryptionByDefault`
- `rds:DescribeDBInstances`
- `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeListeners`,
  `elasticloadbalancing:DescribeSSLPolicies`, `elasticloadbalancing:DescribeTargetGroups`,
  `elasticloadbalancing:DescribeTargetHealth`, `elasticloadbalancing:DescribeTags`
- `autoscaling:DescribeAutoScalingGroups`
- `acm:ListCertificates`, `acm:DescribeCertificate`
- `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`
- `iam:GenerateCredentialReport`, `iam:GetCredentialReport` (the report lists users, MFA and key dates; no secrets.
  Generating it changes no IAM setting)
- `guardduty:ListDetectors`, `guardduty:GetDetector`
- `backup:ListProtectedResources`
- `ssm:DescribeInstanceInformation`
- `lambda:ListFunctions`, `lambda:ListFunctionUrlConfigs`, `lambda:ListTags`
- `iam:GetAccountAuthorizationDetails` (returns policy documents; no passwords or access keys)
- `s3:ListAllMyBuckets`, `s3:GetBucketLocation`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPublicAccessBlock`,
  `s3:GetBucketAcl`, `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketTagging`,
  `s3:GetAccountPublicAccessBlock`

For integrations (each only if you use it):

- CloudWatch: `cloudwatch:GetMetricData`, `cloudwatch:DescribeAlarms`
- Cost Explorer: `ce:GetCostAndUsage`, `ce:GetCostAndUsageWithResources` ($0.01 per request, 3 per run)
- Cost Optimization Hub: `cost-optimization-hub:ListRecommendations`, `compute-optimizer:GetEnrollmentStatus` (no charge)
- Cost Optimization Hub: `cost-optimization-hub:ListRecommendations`, `compute-optimizer:GetEnrollmentStatus` (no charge)
- Wazuh: an API user with read-only access to agents; an indexer user with read on `wazuh-states-vulnerabilities-*`
- GitHub: fine-grained token, repository permission "Deployments: read", only the repos in `scamallscope:repo` tags

IAM and S3 are global: they are collected once per run under the region `global`
(`snapshot.collect(..., include_global=False)` skips them). Lambda environment variable
**values are dropped** when collected; only the names are kept.

For the inventory, the identity that runs it also needs, on the table and its index only:
`dynamodb:Query`, `dynamodb:PutItem`, `dynamodb:DeleteItem`, `dynamodb:BatchWriteItem`.
Create the table from `infra/inventory-table.yaml` (CloudFormation).

## Inventory (DynamoDB)

`scamallscope inventory` compares a snapshot with the current state in the table and writes
only what was created, changed or deleted, plus one change event each and a run record
(see [decision 0001](../docs/decisions/0001-inventory-in-dynamodb.md)). Exit code `2` when the
snapshot is partial: resources in failed units are kept, never marked deleted.

## Snapshot shape

- `units`: one entry per (service, resource type, region), `status` `ok` or `error`. A unit with
  `error` means "unknown", never "nothing there".
- `resources`: `arn`, `account_id`, `region`, `service`, `type`, `id`, `name`, `tags`, `config` (raw API item).
- `links`: `source` ARN, `target` ARN, `type` (`contains`, `uses`, `attached`, `routes`, `routes_to`, `filters`).

## Graph JSON

`scamallscope graph` converts a snapshot into Cytoscape.js `elements` for the frontend.
Nodes keep only the fields the views need (no raw config, no IP addresses). Edges to a
resource that is not in the snapshot are dropped and counted in `meta.dropped_edges`.
`meta.complete` is false, and the exit code is `2`, when the snapshot is partial.

## Internet exposure

Each instance node in the graph has `exposure` (`exposed`, `not_exposed` or `unknown`),
`exposure_reason` and `exposed_ports`. A port is exposed when, on the same network interface:

1. the interface has a public IPv4 or IPv6 address,
2. its subnet's route table (or the VPC main table) has `0.0.0.0/0` or `::/0` to an
   internet gateway attached to the VPC, and
3. one of its security groups allows inbound traffic from `0.0.0.0/0` or `::/0`, and
4. the subnet's network ACL (or the VPC default ACL) lets that traffic in. Inbound rules are
   checked lowest rule number first and the first match wins. Only rules with source
   `0.0.0.0/0` or `::/0` count, the same as for security groups. Only the part of a port
   range that the ACL allows is reported.

S3 buckets are exposed when AWS's policy status says the bucket policy is public, or the ACL
grants access to everyone or any AWS account, unless Block Public Access (bucket or account)
stops it. Lambda functions are exposed when they have a function URL with `AuthType NONE`.
IAM users, groups and roles get `admin` (see `iam_analysis.py` for what is and is not checked).

`unknown` means a collection unit the check needs failed. Not checked yet: prefix lists,
split default routes, load balancers, ICMP type and code in network ACL rules.
Outbound ACL rules are not used: blocking return traffic does not stop a packet reaching
the instance.
