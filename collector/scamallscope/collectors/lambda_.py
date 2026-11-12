"""Lambda functions (regional).

Read-only calls: lambda:ListFunctions, lambda:ListFunctionUrlConfigs, lambda:ListTags.

Environment variable values often hold secrets. Only the variable names are kept;
the values are dropped here, before anything is stored.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..model import Link, Resource, link, make_resource
from .base import Context, Result
from .ec2 import arn as ec2_arn


def _redact(fn: dict[str, Any]) -> dict[str, Any]:
    fn = dict(fn)
    env = fn.pop("Environment", None) or {}
    fn["EnvironmentVariableNames"] = sorted((env.get("Variables") or {}).keys())
    if env.get("Error"):
        fn["EnvironmentError"] = env["Error"]
    return fn


def _detail(errors: dict[str, str], name: str, call: Any) -> Any:
    try:
        return call()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        errors[name] = f"{err.get('Code', 'ClientError')}: {err.get('Message', '')}".strip()
    except BotoCoreError as exc:
        errors[name] = f"{type(exc).__name__}: {exc}"
    return None


def collect_functions(client: Any, ctx: Context) -> Result:
    resources: list[Resource] = []
    links: list[Link] = []
    for page in client.get_paginator("list_functions").paginate():
        for fn in page.get("Functions", []):
            errors: dict[str, str] = {}
            fn_arn = fn["FunctionArn"]
            config = _redact(fn)
            config["FunctionUrlConfigs"] = _detail(
                errors, "FunctionUrlConfigs",
                lambda: client.list_function_url_configs(FunctionName=fn["FunctionName"]).get("FunctionUrlConfigs", []))
            tags = _detail(errors, "Tags", lambda: client.list_tags(Resource=fn_arn).get("Tags", {})) or {}
            config["DetailErrors"] = errors
            r = make_resource(fn_arn, ctx["account_id"], ctx["region"], "lambda", "function", fn["FunctionName"], tags, config,
                              name=fn["FunctionName"])
            resources.append(r)
            if fn.get("Role"):
                links.append(link(r["arn"], fn["Role"], "assumes"))
            vpc = fn.get("VpcConfig") or {}
            for subnet in vpc.get("SubnetIds", []):
                links.append(link(r["arn"], ec2_arn(ctx, "subnet", subnet), "attached"))
            for sg in vpc.get("SecurityGroupIds", []):
                links.append(link(r["arn"], ec2_arn(ctx, "security-group", sg), "uses"))
    return resources, links
