# Specs

One file per part. Each has the behaviour, then a test table. Test IDs (for example `PRW-3`)
appear in the test names, so `uv run pytest -k PRW` runs one spec's tests.

| Spec | Tests in |
|---|---|
| [01 Findings and Well-Architected scorecard](01-findings-and-posture.md) | `collector/tests/test_findings.py`, `test_posture.py` |
| [02 Prowler](02-prowler.md) | `collector/tests/test_prowler.py` |
| [03 Wazuh](03-wazuh.md) | `collector/tests/test_wazuh.py`, `test_hosts.py` |
| [04 GitHub](04-github.md) | `collector/tests/test_github.py` |
| [05 Ansible](05-ansible.md) | `collector/tests/test_ansible.py` |
| [06 Metrics and logs](06-metrics.md) | `collector/tests/test_cloudwatch.py`, `test_prometheus.py` |
| [07 Cost](07-cost.md) | `collector/tests/test_cost.py` |
| [08 Hygiene rules](08-hygiene.md) | `collector/tests/test_hygiene.py` |
| [09 Enrich and UI views](09-enrich-and-views.md) | `collector/tests/test_enrich.py`, `frontend/tests/views.test.js` |
| [10 Inventory for availability, cost and account controls](10-inventory-phase-b.md) | `collector/tests/test_inventory_b.py` |
| [11 Cost Optimization Hub and commitment coverage](11-cost-recommendations.md) | `collector/tests/test_costhub.py`, `test_cost.py` |
| [12 Security, cost and availability rules](12-rules-phase-b.md) | `collector/tests/test_rules_b.py` |
| [13 Ranking and duplicates](13-ranking.md) | `collector/tests/test_rank.py` |
| [14 Overview and Availability views](14-overview-and-availability.md) | `collector/tests/test_availability.py`, `frontend/tests/views.test.js` |

Fixtures in `collector/tests/fixtures/` are made up, in the shape of the real responses
(cited in each spec). Account `123456789012` and names like `prod-web-1` are not real.
