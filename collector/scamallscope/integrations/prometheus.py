"""Prometheus `up` per instance (spec 06)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .. import hosts, httpjson
from ..findings import Parsed, empty_parsed

SOURCE = "prometheus"
ID_LABEL = "instance_id"
IPV4 = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")


def _safe(name: str) -> str:
    """Unmatched names go into the graph: never an IP address."""
    return IPV4.sub("<ip>", name)


def parse(raw: dict[str, Any], index: hosts.Index) -> Parsed:
    resp = raw.get("response") or {}
    if resp.get("status") != "success" or (resp.get("data") or {}).get("resultType") != "vector":
        raise ValueError(f"prometheus.json: query failed or not a vector ({resp.get('error') or resp.get('status')})")
    out = empty_parsed()
    for series in resp["data"].get("result") or []:
        labels = series.get("metric") or {}
        arn = hosts.by_instance_id(index, labels.get(ID_LABEL)) or hosts.match(index, labels.get("instance"))
        if not arn:
            out["unmatched"].append(_safe(str(labels.get(ID_LABEL) or labels.get("instance"))))
            continue
        value = int(float((series.get("value") or [0, "0"])[1]))
        prev = out["resources"].get(arn, {}).get("prom_up")
        out["resources"][arn] = {"prom_up": value if prev is None else min(prev, value)}
    return out


def fetch(url: str, token: str | None = None, ca_file: str | None = None) -> dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = httpjson.request("GET", f"{httpjson.require_https(url)}/api/v1/query", headers=headers,
                            params={"query": "up"}, ca_file=ca_file)
    return {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "query": "up", "response": resp}
