"""Which IAM principals have full admin.

A principal is "admin" when it can do any action on any resource without conditions:
- AWS managed AdministratorAccess is attached, or
- an attached customer managed policy (default version) or an inline policy has an Allow
  statement with Action "*" and Resource "*" and no Condition, or
- (users) it is in a group that is admin.

Not checked yet: permission boundaries, SCPs, NotAction statements, service-level wildcards
such as "iam:*".
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import unquote

from .model import Resource, Snapshot

ADMIN_POLICY_SUFFIX = ":iam::aws:policy/AdministratorAccess"
CHECKS = ("AdministratorAccess, or an attached or inline policy that allows * on * with no condition, "
          "or membership of an admin group. Not checked: permission boundaries, SCPs, NotAction, "
          "service wildcards such as iam:*.")


def document(doc: Any) -> dict[str, Any]:
    """Policy documents come as dicts, or as URL-encoded JSON strings from some APIs."""
    if isinstance(doc, str):
        return json.loads(unquote(doc))
    return doc or {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def grants_admin(doc: Any) -> bool:
    for st in _as_list(document(doc).get("Statement", [])):
        if (st.get("Effect") == "Allow" and "Condition" not in st
                and "*" in _as_list(st.get("Action", [])) and "*" in _as_list(st.get("Resource", []))):
            return True
    return False


def policy_is_admin(policy: Resource) -> bool:
    """AWS managed AdministratorAccess, or a customer managed policy whose default version allows * on *."""
    if policy["arn"].endswith(ADMIN_POLICY_SUFFIX):
        return True
    versions = policy["config"].get("PolicyVersionList", [])
    default = next((v for v in versions if v.get("IsDefaultVersion")), None)
    return bool(default) and grants_admin(default.get("Document"))


def admin_principals(snapshot: Snapshot) -> dict[str, str]:
    """{principal ARN: reason} for users, groups and roles with full admin."""
    by_type: dict[str, list[Resource]] = {"user": [], "group": [], "role": [], "policy": []}
    for r in snapshot["resources"]:
        if r["service"] == "iam" and r["type"] in by_type:
            by_type[r["type"]].append(r)

    admin_policies = {p["arn"]: (
        "AdministratorAccess attached" if p["arn"].endswith(ADMIN_POLICY_SUFFIX)
        else f"policy {p['name']} allows * on *") for p in by_type["policy"] if policy_is_admin(p)}

    out: dict[str, str] = {}
    inline_key = {"user": "UserPolicyList", "group": "GroupPolicyList", "role": "RolePolicyList"}
    for kind in ("group", "role", "user"):
        for r in by_type[kind]:
            c = r["config"]
            for p in c.get("AttachedManagedPolicies", []):
                if p["PolicyArn"] in admin_policies:
                    out[r["arn"]] = admin_policies[p["PolicyArn"]]
                elif p["PolicyArn"].endswith(ADMIN_POLICY_SUFFIX):  # AWS managed, not in snapshot
                    out[r["arn"]] = "AdministratorAccess attached"
            for p in c.get(inline_key[kind], []):
                if grants_admin(p.get("PolicyDocument")):
                    out[r["arn"]] = f"inline policy {p.get('PolicyName')} allows * on *"
    groups = {g["name"]: g["arn"] for g in by_type["group"]}
    for u in by_type["user"]:
        for g in u["config"].get("GroupList", []):
            if u["arn"] not in out and groups.get(g) in out:
                out[u["arn"]] = f"member of admin group {g}"
    return out


def trusted_principals(role_config: dict[str, Any]) -> list[str]:
    """Who can assume a role, from its trust policy (Service, AWS, Federated principals)."""
    out: list[str] = []
    for st in _as_list(document(role_config.get("AssumeRolePolicyDocument")).get("Statement", [])):
        if st.get("Effect") != "Allow":
            continue
        principal = st.get("Principal", {})
        if principal == "*":
            out.append("*")
            continue
        for kind in ("Service", "AWS", "Federated"):
            out += [str(v) for v in _as_list(principal.get(kind, []))]
    return sorted(set(out))
