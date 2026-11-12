"""What every collector shares: where it runs, what it returns, and how it lists."""

from __future__ import annotations

from typing import Any, TypedDict

from ..model import Link, Resource

Result = tuple[list[Resource], list[Link]]


class Context(TypedDict):
    """Where a collector runs: partition, account and region."""

    partition: str
    account_id: str
    region: str


def context(partition: str, account_id: str, region: str) -> Context:
    return {"partition": partition, "account_id": account_id, "region": region}


def items(client: Any, operation: str, key: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Every item of a list call, following pages when the operation has them."""
    if client.can_paginate(operation):
        return [x for page in client.get_paginator(operation).paginate(**kwargs) for x in page.get(key, [])]
    return list(getattr(client, operation)(**kwargs).get(key, []))
