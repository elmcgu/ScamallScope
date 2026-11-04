"""IAM users, groups, roles and policies, from one paginated call.

Read-only call: iam:GetAccountAuthorizationDetails. It returns policy documents (permissions,
trust policies) but no secrets: no passwords and no access keys.
"""

from __future__ import annotations

from typing import Any

from ..model import GLOBAL, Link, Resource, link, make_resource, tags_to_dict

TYPES = ("user", "group", "role", "policy")
Result = tuple[list[Resource], list[Link]]


def fetch(client: Any) -> dict[str, list[dict[str, Any]]]:
    details: dict[str, list[dict[str, Any]]] = {"UserDetailList": [], "GroupDetailList": [],
                                                 "RoleDetailList": [], "Policies": []}
    paginator = client.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User", "Group", "Role", "LocalManagedPolicy"]):
        for key in details:
            details[key] += page.get(key, [])
    return details


def collect(client: Any, account_id: str) -> dict[str, Result]:
    """{resource type: (resources, links)} for users, groups, roles and policies."""
    d = fetch(client)
    out: dict[str, Result] = {t: ([], []) for t in TYPES}
    aws_managed: dict[str, str] = {}  # ARN -> name of AWS managed policies that are attached

    def principal(kind: str, item: dict[str, Any], id_key: str, name_key: str) -> None:
        r = make_resource(item["Arn"], account_id, GLOBAL, "iam", kind, item[id_key],
                          tags_to_dict(item.get("Tags")), item, name=item[name_key])
        out[kind][0].append(r)
        for p in item.get("AttachedManagedPolicies", []):
            out[kind][1].append(link(r["arn"], p["PolicyArn"], "attached"))
            if ":iam::aws:policy/" in p["PolicyArn"]:
                aws_managed[p["PolicyArn"]] = p["PolicyName"]

    for u in d["UserDetailList"]:
        principal("user", u, "UserId", "UserName")
        for g in u.get("GroupList", []):
            group_arn = next((x["Arn"] for x in d["GroupDetailList"] if x["GroupName"] == g), None)
            if group_arn:
                out["user"][1].append(link(u["Arn"], group_arn, "member_of"))
    for g in d["GroupDetailList"]:
        principal("group", g, "GroupId", "GroupName")
    for r in d["RoleDetailList"]:
        principal("role", r, "RoleId", "RoleName")

    for p in d["Policies"]:
        # AWS returns PolicyName and PolicyId; fall back to the ARN so a missing field never breaks a run.
        name = p.get("PolicyName") or p["Arn"].rsplit("/", 1)[-1]
        out["policy"][0].append(make_resource(p["Arn"], account_id, GLOBAL, "iam", "policy", p.get("PolicyId") or name,
                                              tags_to_dict(p.get("Tags")), p, name=name))
    # AWS managed policies: only those attached here, by name (their documents are public and large).
    for policy_arn, name in sorted(aws_managed.items()):
        out["policy"][0].append(make_resource(policy_arn, account_id, GLOBAL, "iam", "policy", name, {},
                                              {"Arn": policy_arn, "PolicyName": name, "AwsManaged": True}, name=name))
    return out


def instance_profile_roles(resources: list[Resource]) -> dict[str, str]:
    """{instance profile ARN: role ARN}, from the roles' InstanceProfileList."""
    out: dict[str, str] = {}
    for r in resources:
        if r["type"] == "role":
            for profile in r["config"].get("InstanceProfileList", []):
                out[profile["Arn"]] = r["arn"]
    return out
