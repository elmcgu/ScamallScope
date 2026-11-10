"""Ansible playbook results from the ansible.posix.json callback (spec 05). No fetch step."""

from __future__ import annotations

from typing import Any, Literal

from .. import hosts
from ..findings import Parsed, cover, empty_parsed, make

SOURCE = "ansible"
BP = "REL08-BP05"
Mode = Literal["check", "apply"]


def parse(raw: dict[str, Any], index: hosts.Index, mode: Mode = "check") -> Parsed:
    stats = raw.get("stats")
    if not isinstance(stats, dict):
        raise ValueError("ansible.json: no stats object (use ANSIBLE_STDOUT_CALLBACK=ansible.posix.json)")
    plays = raw.get("plays") or [{}]
    ran_at = (((plays[0] or {}).get("play") or {}).get("duration") or {}).get("start")
    out = empty_parsed()
    for host, s in sorted(stats.items()):
        arn = hosts.match(index, host)
        if not arn:
            out["unmatched"].append(host)
            continue
        run = {k: int(s.get(k, 0)) for k in ("ok", "changed", "failures", "unreachable")}
        out["resources"][arn] = {**run, "mode": mode, "ran_at": ran_at}
        region = arn.split(":")[3]
        bad = False
        if run["failures"] or run["unreachable"]:
            bad = True
            out["findings"].append(make(SOURCE, "ansible-host-failed", f"Ansible run failed on {host}", "medium",
                                        [BP], arn, host, region,
                                        f"{run['failures']} failed, {run['unreachable']} unreachable",
                                        "Read the play output for this host and fix the failing task."))
        if mode == "check" and run["changed"]:
            bad = True
            out["findings"].append(make(SOURCE, "ansible-drift", f"Configuration drift on {host}", "medium",
                                        [BP], arn, host, region,
                                        f"{run['changed']} task(s) would change in check mode",
                                        "Find who changed the host by hand; apply the playbook or update it."))
        cover(out["coverage"], [BP], failed=bad)
    return out
