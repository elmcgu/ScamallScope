# 14 Overview and Availability views

## Overview (default view for graph v2)

Header totals from `g["summary"]`: open issues by severity, savings a month ("estimate" when any
saving comes from the price table), single points of failure.

Three columns: **Security**, **Cost**, **Availability (Reliability)**. Each shows the top 10
primary findings of its pillar by `priority`, as cards:

- title and severity
- resource name (click: opens it on the Map) and Region
- why: the best-practice title, linked to its AWS page
- fix: `remediation`
- cost cards: `savings_usd` a month
- "also reported by" sources, if any

Under each column: "N more in Findings" (opens Findings filtered to that pillar). When a source
is not loaded, the column says which checks did not run, for example "Cost Optimization Hub not
loaded: savings are estimates from our own rules".

## Availability view

`g["workloads"]` (built in `availability.py`): one row per workload.

| Field | Meaning |
|---|---|
| `name`, `kind` | `app` tag group, ASG, target group, DB instance, or standalone instance |
| `region`, `vpc` | |
| `azs` | AZs it runs in |
| `prod` | spec 12 prod rule |
| `healing` | `asg`, `auto-recovery`, `recover-alarm`, `multi-az` (RDS) or `none` |
| `backup` | `ok` (within 7 days), `missing`, `n/a` (stateless: no attached volume with data), or `unknown` (unit failed) |
| `monitoring` | `alarm`, `prometheus`, both, `none`, or `unknown` (sources not loaded) |
| `findings` | Count of primary reliability findings on its resources |

Sorted by findings, then prod first. Filter: prod only.

## Map

"Colour by" adds **pillar**: worst severity among primary findings of the chosen pillar.

## Tests

| ID | Given | Then |
|---|---|---|
| VIEW-9 | `overviewColumns` | Three columns, top 10 by priority, no duplicates |
| VIEW-10 | Cost card | Shows `savings_usd` with 2 decimals |
| VIEW-11 | Source not loaded | Column note lists it |
| VIEW-12 | `workloadRows` prod filter | Only prod rows |
| VIEW-13 | `colourBy` pillar | Worst severity of that pillar only |
| AVL-1 | Two instances with `app=web` in two AZs | One workload, `azs` 2, no REL-AZ-001 |
| AVL-2 | Standalone instance | Workload `kind` instance, `healing` auto-recovery when not disabled |
| AVL-3 | RDS Multi-AZ | `healing` multi-az |
