# ScamallScope: what it is, how it works, why

*Scamall* is Irish for "cloud". ScamallScope draws a map of an AWS account and lays security,
hygiene, reliability and cost data over it. Every issue it shows links to the AWS
Well-Architected best practice that it breaks.

Status (2026-11-04): working demo with made-up data. Not yet run against a real account.
Numbers in square brackets, like [R1], point to [references.md](references.md).

## The problem

A small team running AWS has its answers in several places:

| Question | Where the answer is today |
|---|---|
| What runs in the account, and what can the internet reach? | AWS console, one service and region at a time |
| Which checks fail against good practice? | Prowler report (CSV, HTML or JSON) |
| Which servers have old OS versions or vulnerable packages? | Wazuh dashboard |
| What code is deployed where, and did the last deploy work? | GitHub |
| Is server configuration what we think it is? | Ansible run output |
| Is it up, and is anyone alerted when it is not? | Prometheus, CloudWatch |
| What does it cost, and what is wasted? | Cost Explorer |

Each tool is good on its own. The gap is joining them: "this public instance has 3 critical
vulnerabilities, no alarm, failed its last Ansible run and costs $40 a month at 2% CPU" is one
sentence, but today it takes five tools to write it.

## What ScamallScope does

1. **Collects** an inventory of the AWS account with read-only API calls (EC2 networking,
   instances, Lambda, IAM, S3), and links the resources into a graph.
2. **Reads** data from the tools you already run (the integrations), and attaches it to the
   resource it is about.
3. **Checks** hygiene rules that need data from more than one source, for example "running
   instance with no Wazuh agent" or "idle instance" (CloudWatch CPU plus inventory).
4. **Maps** every finding to AWS Well-Architected best-practice IDs, such as `SEC06-BP01`,
   and builds a scorecard per pillar: issues, clear, or not checked.
5. **Shows** it in a browser:
   - **Map:** VPCs, subnets, instances and how they connect, coloured by exposure, findings or cost.
   - **Findings:** one table of all issues from all sources, filtered by pillar, severity and source.
   - **Hosts:** per instance: OS version, vulnerable packages, last deployment, last Ansible run,
     monitoring.
   - **Cost:** spend by service, by tag, by resource, and the cost of idle resources.
   - **Well-Architected:** the scorecard, with a link to the AWS page for every best practice.

## Integrations

| Source | What ScamallScope reads | How | Status |
|---|---|---|---|
| Prowler | Failed and passed checks, with their Well-Architected mapping | Prowler JSON-OCSF output file [R10, R11] | Demo |
| Wazuh | Agent OS name and version, status, last keep-alive; vulnerable packages | Server API `GET /agents` [R14]; indexer index `wazuh-states-vulnerabilities-*` [R15] | Demo |
| GitHub | Deployments and their latest status, per repo and environment | REST API `GET /repos/{owner}/{repo}/deployments` [R18, R19] | Demo |
| Ansible | Per host: ok, changed, failed, unreachable; drift in check mode | `ansible.posix.json` callback output [R21, R22, R23] | Demo |
| CloudWatch | EC2 `CPUUtilization` over 14 days; which instances have alarms | `GetMetricData`, `DescribeAlarms` [R25, R26, R27] | Demo |
| Prometheus | Which instances are scraped and whether they are `up` | HTTP API `/api/v1/query` [R29, R30] | Demo |
| Cost Explorer | Cost by service, by tag, and by EC2 instance | `GetCostAndUsage`, `GetCostAndUsageWithResources` [R32, R33] | Demo |
| Loki | Error log lines per host over 24 hours | HTTP API `query` with a LogQL metric query [R36] | Planned |
| Grafana | Link from a resource to its Grafana dashboard | Dashboard URL variables [R37] | Planned |

Each integration is optional. When a source is not loaded, the checks that need it say
**not checked**. They never say "clear". This follows the rule the inventory already uses: a
failed collection means "unknown", never "nothing there" ([decision 0001](decisions/0001-inventory-in-dynamodb.md)).

## How it works

```
                       read-only, outside ScamallScope's control
  AWS APIs   Prowler   Wazuh   GitHub   Ansible   CloudWatch   Prometheus   Cost Explorer
     |          |        |        |        |          |            |             |
  collect     (file)   fetch    fetch    (file)     fetch        fetch         fetch
     |          |        |        |        |          |            |             |
  snapshot.json         integrations/  (raw API responses, mode 0600, git-ignored)
     \__________________________|______________________________________________/
                                |
                             enrich        pure functions: parse, match to resources,
                                |          hygiene rules, Well-Architected scorecard
                                v
                          graph.json  ---->  browser UI (static files, reads the file locally)
```

- **Fetch** talks to other systems. It needs network access and credentials (from environment
  variables only), and writes the raw responses unchanged.
- **Enrich** has no network and no credentials. It reads the snapshot and the raw files and
  writes one graph JSON file. All the logic is here, so it is all tested with fake raw files
  that have the same shape as the real API responses.
- The UI is static files. It reads the graph JSON in the browser and never uploads it.

Why this split is described in [decision 0002](decisions/0002-fetch-then-enrich.md). The full
design is in [architecture.md](architecture.md) and the behaviour, with tests, in [specs/](specs/).

### Matching data to resources

Other tools do not know AWS ARNs, so ScamallScope matches them:

| Source | Matched by |
|---|---|
| Prowler | `resources[].uid` is the ARN |
| Wazuh, Ansible | Host name equals the instance ID, the `Name` tag, the `scamallscope:host` tag, or the short private DNS name (`ip-10-0-1-5`) |
| Prometheus | Label `instance_id` (set by relabelling `__meta_ec2_instance_id` from EC2 service discovery [R30]), else the host part of `instance` |
| GitHub | Resource tag `scamallscope:repo` = `owner/repo`, optional `scamallscope:environment` |
| CloudWatch, Cost Explorer | `InstanceId` dimension, or resource ID |

A name that matches more than one instance is **not** matched, and is listed as unmatched. A
wrong match would be worse than no match.

## How it helps with AWS Well-Architected

The AWS Well-Architected Framework has six pillars [R1, R2]. ScamallScope covers three of them:
security [R3], reliability [R4] and cost optimisation [R5]. Each best practice below is one that
ScamallScope checks, or gives the evidence for. The scorecard view shows the full list for each
pillar, so you can also see what is **not** checked.

### Security

| Best practice | What ScamallScope shows | Source |
|---|---|---|
| SEC01-BP02 Secure account root user and properties [R6] | Root MFA, root access keys | Prowler |
| SEC02-BP02 Use temporary credentials | IAM users (long-term credentials) listed for review | Inventory |
| SEC03-BP02 Grant least privilege access | Users, groups and roles with admin rights (★ on the map) | Inventory |
| SEC04-BP01 Configure service and application logging | Wazuh agents that are not active | Wazuh |
| SEC04-BP03 Correlate and enrich security alerts | Findings from all sources on one resource | All |
| SEC05-BP01 / BP02 Network layers and traffic flow | Instances, buckets and functions reachable from the internet, with the rule that allows it | Inventory |
| SEC06-BP01 Perform vulnerability management | Vulnerable packages per host; instances with no agent; deprecated Lambda runtimes | Wazuh, inventory |
| SEC08-BP02 Enforce encryption at rest | Buckets without default encryption | Inventory, Prowler |
| SEC11-BP06 Deploy software programmatically | Which code is deployed where, from GitHub deployments | GitHub |
| Every BP in Prowler's Well-Architected mapping | Prowler findings, with their BP IDs | Prowler [R12] |

**Why it helps:** SEC04-BP03 asks you to correlate and enrich alerts so you can see what matters
first. A vulnerability on a private, idle test box and the same vulnerability on a public web
server are not the same risk. ScamallScope puts exposure, vulnerabilities and admin rights on the
same resource.

### Reliability

| Best practice | What ScamallScope shows | Source |
|---|---|---|
| REL06-BP01 Monitor all components for the workload | Running instances not scraped by Prometheus, or `up` = 0 | Prometheus |
| REL06-BP03 Send notifications | Running instances with no CloudWatch alarm | CloudWatch |
| REL08-BP02 Integrate functional testing as part of your deployment | Latest deployment failed | GitHub |
| REL08-BP05 Deploy changes with automation | Hosts not in the Ansible run, hosts that failed, and drift found in check mode | Ansible |
| REL09-BP01 Identify and back up all data | Buckets without versioning | Inventory |
| Every BP in Prowler's reliability mapping | Prowler findings | Prowler [R13] |

**Why it helps:** most outages in a small estate come from changes and from things nobody was
watching. The Hosts view answers "is this box monitored, alerted on, managed by Ansible and
deployed by a pipeline?" in one row.

### Cost optimisation

| Best practice | What ScamallScope shows | Source |
|---|---|---|
| COST03-BP02 Add organization information to cost and usage | Resources missing the required tags (default `owner`, `env`) | Inventory |
| COST03-BP05 Configure billing and cost management tools | Cost by service and by tag, from Cost Explorer | Cost Explorer |
| COST04-BP01 Track resources over their lifetime | Daily inventory and change log (roadmap 3) | Inventory |
| COST04-BP03 Decommission resources | Stopped instances (EBS still charged) | Inventory |
| COST06-BP02 Select resource type, size, and number based on data | Idle instances: average CPU under 5% and peak under 20% over 14 days, with their cost | CloudWatch, Cost Explorer |

**Why it helps:** COST03 says cost data is useful only when you can tie it to an owner.
ScamallScope shows the cost next to the resource, its tags and its owner, so "who can switch
this off?" has an answer.

## What ScamallScope is not

- **Not a replacement for Prowler, Wazuh or Security Hub.** It reads their results. Detection
  stays in the tools built for it.
- **Not a Well-Architected review.** A review is a conversation about a workload [R1]. The
  scorecard gives evidence for some best practices and says clearly which ones it does not check.
- **Not real time.** It runs once a day (roadmap 4). Use CloudWatch and Prometheus alerting for
  real time.
- **Not a write tool.** Every call is read-only. It never changes AWS, Wazuh, GitHub or Ansible.

## Cost of running it

| Item | Cost |
|---|---|
| Collector calls (EC2, IAM, S3, Lambda describe and list) | No charge for these API calls |
| Cost Explorer API | $0.01 per request [R34]. A daily run uses 3 requests: about $0.90 a month |
| Cost Explorer resource-level data (opt-in) | About $0.01 per 1,000 usage records a month [R34] |
| CloudWatch `GetMetricData` | Charged per metric requested; see [R28]. One metric per instance per day |
| DynamoDB inventory | Well under $1 a month at 2,000 resources ([decision 0001](decisions/0001-inventory-in-dynamodb.md)) |

## Security of ScamallScope itself

ScamallScope's output is a map of the estate and its weak points, so:

- All AWS access is read-only (see `collector/README.md` for the exact actions).
- Wazuh and GitHub use read-only accounts or tokens (specs list the exact permissions).
- Credentials come from environment variables only. They are never written to a file, a log or
  the graph.
- Raw integration files and graphs are written with mode `0600` and are git-ignored.
- The graph keeps no IP addresses, no Lambda environment values and no package file paths.
- TLS is verified on every connection. A private CA file can be given; verification cannot be
  turned off.
- The UI treats every value as untrusted text (`textContent` only, strict Content Security Policy).

## Plan

See [plan.md](plan.md) for what is built, what is next, and the order of work.
