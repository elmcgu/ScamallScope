"""Wazuh agents (server API) and vulnerabilities (indexer) (spec 03)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .. import hosts, httpjson
from ..findings import SEVERITIES, Parsed, cover, empty_parsed, make, severity, worst

SOURCE = "wazuh"
AGENT_FIELDS = "id,name,status,lastKeepAlive,os.name,os.version,os.platform"
PAGE = 500
VULN_INDEX = "wazuh-states-vulnerabilities-*"
VULN_SEVERITIES = ["Critical", "High", "Medium", "Low"]
AGENT_ID_FIELDS = ("agent.id", "wazuh.agent.id")  # 4.x and 5.0 field names [R17]
TOP_PACKAGES = 5
VULN_BP, AGENT_BP = "SEC06-BP01", "SEC04-BP01"


def vulnerability_query(agent_count: int) -> dict[str, Any]:
    """One aggregation request: per agent, counts by severity and the top packages. size 0: no documents.

    Counts are exact for every agent bucket returned; the agent bucket size is the number of agents."""
    per_agent = {
        "severity": {"terms": {"field": "vulnerability.severity", "size": len(VULN_SEVERITIES)}},
        "packages": {"multi_terms": {"terms": [{"field": "package.name"}, {"field": "package.version"}],
                                     "size": TOP_PACKAGES, "shard_size": 100}},
    }
    size = max(agent_count, 1)
    return {"size": 0,
            "query": {"terms": {"vulnerability.severity": VULN_SEVERITIES}},
            "aggs": {f"by_{field}": {"terms": {"field": field, "size": size}, "aggs": per_agent}
                     for field in AGENT_ID_FIELDS}}


def vulnerabilities_by_agent(response: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], bool]:
    """{agent id: {"vulns": counts by severity, "total": n, "top_packages": [...]}}, and whether agents were left out."""
    aggs = response.get("aggregations")
    if not isinstance(aggs, dict):
        raise ValueError("wazuh.json: vulnerabilities has no aggregations (re-run fetch wazuh)")
    out: dict[str, dict[str, Any]] = {}
    truncated = False
    for field in AGENT_ID_FIELDS:
        agg = aggs.get(f"by_{field}") or {}
        truncated |= bool(agg.get("sum_other_doc_count"))
        for b in agg.get("buckets") or []:
            row = out.setdefault(str(b.get("key")), {"vulns": {s: 0 for s in SEVERITIES if s != "info"},
                                                     "total": 0, "top_packages": []})
            for sb in (b.get("severity") or {}).get("buckets") or []:
                sev = severity(sb.get("key"))
                if sev in row["vulns"]:
                    row["vulns"][sev] += int(sb.get("doc_count") or 0)
            row["total"] = sum(row["vulns"].values())
            row["top_packages"] = _top_packages(row["top_packages"] + [
                {"name": str((pb.get("key") or ["?", "?"])[0]), "version": str((pb.get("key") or ["?", "?"])[-1]),
                 "count": int(pb.get("doc_count") or 0)}
                for pb in (b.get("packages") or {}).get("buckets") or []])
    return out, truncated


def _top_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most CVEs first, then by name and version; at most TOP_PACKAGES."""
    return sorted(packages, key=lambda p: (-p["count"], p["name"], p["version"]))[:TOP_PACKAGES]


def parse(raw: dict[str, Any], index: hosts.Index) -> Parsed:
    try:
        agents = raw["agents"]["data"]["affected_items"]
    except (KeyError, TypeError):
        raise ValueError("wazuh.json: no agents.data.affected_items (GET /agents response)") from None
    vulns, truncated = vulnerabilities_by_agent(raw.get("vulnerabilities") or {})
    out = empty_parsed()
    if truncated:
        out["notes"].append("vulns_truncated: the indexer had vulnerabilities for more agents than were read")
    for a in agents:
        if str(a.get("id")) == "000":  # the manager itself
            continue
        arn = hosts.match(index, a.get("name"))
        if not arn:
            out["unmatched"].append(str(a.get("name")))
            continue
        os_ = a.get("os") or {}
        mine = vulns.get(str(a.get("id"))) or {"vulns": {s: 0 for s in SEVERITIES if s != "info"},
                                               "total": 0, "top_packages": []}
        by_sev = mine["vulns"]
        out["resources"][arn] = {
            "agent_id": a.get("id"), "agent_name": a.get("name"), "status": a.get("status"),
            "last_keepalive": a.get("lastKeepAlive"), "os_name": os_.get("name"),
            "os_version": os_.get("version"), "os_platform": os_.get("platform"),
            "vulns": by_sev, "top_packages": mine["top_packages"],
        }
        region = arn.split(":")[3]
        top = out["resources"][arn]["top_packages"]
        if mine["total"]:
            sev = worst([s for s, n in by_sev.items() if n]) or "info"
            detail = ", ".join(f"{n} {s}" for s, n in by_sev.items())
            if top:
                detail += f" (top: {top[0]['name']} {top[0]['version']})"
            out["findings"].append(make(
                SOURCE, "wazuh-vulnerable-packages", f"{mine['total']} vulnerable package findings on {a.get('name')}",
                sev, [VULN_BP], arn, str(a.get("name")), region, detail,
                "Update the packages (see the Wazuh vulnerability dashboard for each CVE)."))
        cover(out["coverage"], [VULN_BP], failed=bool(mine["total"]))
        if a.get("status") != "active":
            out["findings"].append(make(
                SOURCE, "wazuh-agent-not-active", f"Wazuh agent {a.get('name')} is {a.get('status')}",
                "medium", [AGENT_BP], arn, str(a.get("name")), region,
                f"last keep-alive {a.get('lastKeepAlive') or 'never'}",
                "Check the agent service and its connection to the manager."))
        cover(out["coverage"], [AGENT_BP], failed=a.get("status") != "active")
    return out


def fetch(api_url: str, indexer_url: str, api_user: str, api_password: str,  # pragma: allowlist secret
          indexer_user: str, indexer_password: str, ca_file: str | None = None) -> dict[str, Any]:  # pragma: allowlist secret
    api_url, indexer_url = httpjson.require_https(api_url), httpjson.require_https(indexer_url)
    auth = httpjson.request("POST", f"{api_url}/security/user/authenticate",
                            headers={"Authorization": httpjson.basic_auth(api_user, api_password)}, ca_file=ca_file)
    token = (auth.get("data") or {}).get("token")  # pragma: allowlist secret
    if not token:
        raise httpjson.HttpError("Wazuh API did not return a token")
    bearer = {"Authorization": f"Bearer {token}"}
    items: list[dict[str, Any]] = []
    total = None
    while total is None or len(items) < total:
        page = httpjson.request("GET", f"{api_url}/agents", headers=bearer, ca_file=ca_file,
                                params={"select": AGENT_FIELDS, "limit": PAGE, "offset": len(items)})
        data = page.get("data") or {}
        batch = data.get("affected_items") or []
        total = data.get("total_affected_items", len(batch))
        items.extend(batch)
        if not batch:
            break
    vulns = httpjson.request("POST", f"{indexer_url}/{VULN_INDEX}/_search", body=vulnerability_query(len(items)),
                             ca_file=ca_file,
                             headers={"Authorization": httpjson.basic_auth(indexer_user, indexer_password)})
    return {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agents": {"data": {"affected_items": items, "total_affected_items": len(items)}},
            "vulnerabilities": vulns}
