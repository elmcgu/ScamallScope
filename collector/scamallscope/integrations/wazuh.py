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
VULN_SOURCE = ["agent.id", "agent.name", "wazuh.agent.id", "wazuh.agent.name",
               "package.name", "package.version", "vulnerability.id", "vulnerability.severity"]
VULN_LIMIT = 5000
VULN_BP, AGENT_BP = "SEC06-BP01", "SEC04-BP01"


def _get(doc: dict[str, Any], dotted: str) -> Any:
    """Read 'a.b.c' from nested dicts, or from a flat key 'a.b.c'."""
    if dotted in doc:
        return doc[dotted]
    cur: Any = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def vulnerabilities_by_agent(response: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], bool]:
    hits = (response.get("hits") or {})
    rows = hits.get("hits") or []
    t = hits.get("total")  # {"value": n, "relation": "eq"} in OpenSearch; a plain int in old versions
    total = t.get("value", len(rows)) if isinstance(t, dict) else t if isinstance(t, int) else len(rows)
    out: dict[str, list[dict[str, Any]]] = {}
    for h in rows:
        src = h.get("_source") or {}
        agent = _get(src, "agent.id") or _get(src, "wazuh.agent.id")
        if agent is None:
            continue
        out.setdefault(str(agent), []).append({
            "severity": severity(_get(src, "vulnerability.severity")),
            "cve": _get(src, "vulnerability.id"),
            "package": _get(src, "package.name"),
            "version": _get(src, "package.version"),
        })
    return out, total > len(rows)


def _top_packages(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], int] = {}
    for v in vulns:
        key = (str(v["package"] or "?"), str(v["version"] or "?"))
        counts[key] = counts.get(key, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{"name": n, "version": ver, "count": c} for (n, ver), c in ranked[:5]]


def parse(raw: dict[str, Any], index: hosts.Index) -> Parsed:
    try:
        agents = raw["agents"]["data"]["affected_items"]
    except (KeyError, TypeError):
        raise ValueError("wazuh.json: no agents.data.affected_items (GET /agents response)") from None
    vulns, truncated = vulnerabilities_by_agent(raw.get("vulnerabilities") or {})
    out = empty_parsed()
    if truncated:
        out["notes"].append("vulns_truncated: the indexer had more vulnerabilities than were read")
    for a in agents:
        if str(a.get("id")) == "000":  # the manager itself
            continue
        arn = hosts.match(index, a.get("name"))
        if not arn:
            out["unmatched"].append(str(a.get("name")))
            continue
        os_ = a.get("os") or {}
        mine = vulns.get(str(a.get("id")), [])
        by_sev = {s: sum(1 for v in mine if v["severity"] == s) for s in SEVERITIES if s != "info"}
        out["resources"][arn] = {
            "agent_id": a.get("id"), "agent_name": a.get("name"), "status": a.get("status"),
            "last_keepalive": a.get("lastKeepAlive"), "os_name": os_.get("name"),
            "os_version": os_.get("version"), "os_platform": os_.get("platform"),
            "vulns": by_sev, "top_packages": _top_packages(mine),
        }
        region = arn.split(":")[3]
        top = out["resources"][arn]["top_packages"]
        if mine:
            sev = worst([v["severity"] for v in mine]) or "info"
            detail = ", ".join(f"{n} {s}" for s, n in by_sev.items())
            if top:
                detail += f" (top: {top[0]['name']} {top[0]['version']})"
            out["findings"].append(make(
                SOURCE, "wazuh-vulnerable-packages", f"{len(mine)} vulnerable package findings on {a.get('name')}",
                sev, [VULN_BP], arn, str(a.get("name")), region, detail,
                "Update the packages (see the Wazuh vulnerability dashboard for each CVE)."))
        cover(out["coverage"], [VULN_BP], failed=bool(mine))
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
    query = {"size": VULN_LIMIT, "_source": VULN_SOURCE,
             "query": {"terms": {"vulnerability.severity": ["Critical", "High", "Medium", "Low"]}}}
    vulns = httpjson.request("POST", f"{indexer_url}/{VULN_INDEX}/_search", body=query, ca_file=ca_file,
                             headers={"Authorization": httpjson.basic_auth(indexer_user, indexer_password)})
    return {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "agents": {"data": {"affected_items": items, "total_affected_items": len(items)}},
            "vulnerabilities": vulns}
