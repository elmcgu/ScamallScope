"""Data model for a snapshot: resources, links and per-unit collection results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Resource:
    arn: str
    account_id: str
    region: str
    service: str
    type: str
    id: str
    name: str | None
    tags: dict[str, str]
    config: dict[str, Any]


@dataclass(frozen=True)
class Link:
    source: str  # ARN
    target: str  # ARN
    type: str  # e.g. "contains", "uses"


@dataclass(frozen=True)
class UnitResult:
    """Outcome of collecting one resource type in one region.

    Later runs must only mark resources "deleted" when the unit that owns them
    has status "ok" (decision 0001). A failed unit is never an empty list.
    """

    service: str
    resource_type: str
    region: str
    status: str  # "ok" or "error"
    count: int = 0
    error: str | None = None


@dataclass
class Snapshot:
    account_id: str
    partition: str
    collected_at: str
    regions: list[str]
    units: list[UnitResult] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(u.status == "ok" for u in self.units)

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": SCHEMA_VERSION, **asdict(self)}


def tags_to_dict(tags: list[dict[str, str]] | None) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in tags or []}
