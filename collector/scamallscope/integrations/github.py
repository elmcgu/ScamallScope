"""GitHub deployments for repos named in resource tags (spec 04)."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .. import httpjson
from ..findings import Parsed, cover, empty_parsed, make
from ..model import Snapshot

SOURCE = "github"
REPO_TAG, ENV_TAG, DEFAULT_ENV = "scamallscope:repo", "scamallscope:environment", "production"
REPO_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
FAILED_STATES = {"failure", "error"}


def repos_from_snapshot(snapshot: Snapshot) -> list[str]:
    return sorted({r["tags"][REPO_TAG] for r in snapshot["resources"]
                   if REPO_NAME.match(r["tags"].get(REPO_TAG, ""))})


def _newest_by_env(deployments: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    newest: dict[str, dict[str, Any]] = {}
    for d in deployments:
        env = d.get("environment") or DEFAULT_ENV
        if env not in newest or str(d.get("created_at")) > str(newest[env].get("created_at")):
            newest[env] = d
    return newest


def parse(raw: dict[str, Any], snapshot: Snapshot) -> Parsed:
    repos = raw.get("repos")
    if not isinstance(repos, dict):
        raise ValueError("github.json: no repos object")
    out = empty_parsed()
    for r in snapshot["resources"]:
        repo = r["tags"].get(REPO_TAG, "")
        if not REPO_NAME.match(repo):
            continue
        env = r["tags"].get(ENV_TAG) or DEFAULT_ENV
        name = r.get("name") or r["id"]
        data = repos.get(repo) or {}
        dep = _newest_by_env(data.get("deployments") or []).get(env)
        bps = ["REL08-BP02", "SEC11-BP06"]
        if not dep:
            out["findings"].append(make(SOURCE, "github-no-deployment", f"No {env} deployment of {repo} recorded",
                                        "low", ["SEC11-BP06"], r["arn"], name, r["region"],
                                        f"{repo} has no GitHub deployment for environment {env}",
                                        "Deploy from a pipeline that records GitHub deployments."))
            cover(out["coverage"], bps, failed=True)
            continue
        statuses = (data.get("statuses") or {}).get(str(dep.get("id"))) or []
        state = statuses[0].get("state") if statuses else "unknown"
        out["resources"][r["arn"]] = {
            "repo": repo, "environment": env, "sha": str(dep.get("sha") or "")[:7], "ref": dep.get("ref"),
            "created_at": dep.get("created_at"), "state": state, "url": f"https://github.com/{repo}/deployments",
        }
        failed = state in FAILED_STATES
        if failed:
            out["findings"].append(make(SOURCE, "github-deploy-failed", f"Latest {env} deployment of {repo} {state}",
                                        "high", ["REL08-BP02"], r["arn"], name, r["region"],
                                        f"{str(dep.get('sha') or '')[:7]} at {dep.get('created_at')}",
                                        "Check the workflow run; roll back or fix forward."))
        cover(out["coverage"], ["REL08-BP02"], failed=failed)
        cover(out["coverage"], ["SEC11-BP06"])
    return out


def fetch(repos: list[str], token: str) -> dict[str, Any]:  # pragma: allowlist secret
    auth = {**HEADERS, "Authorization": f"Bearer {token}"}
    out: dict[str, Any] = {}
    for repo in repos:
        if not REPO_NAME.match(repo):
            raise ValueError(f"Not a repo name: {repo!r}")
        deployments = httpjson.request("GET", f"{API}/repos/{repo}/deployments", headers=auth, params={"per_page": 30})
        statuses = {}
        for dep in _newest_by_env(deployments).values():
            statuses[str(dep["id"])] = httpjson.request(
                "GET", f"{API}/repos/{repo}/deployments/{dep['id']}/statuses", headers=auth, params={"per_page": 1})
        out[repo] = {"deployments": deployments, "statuses": statuses}
    return {"fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "repos": out}
