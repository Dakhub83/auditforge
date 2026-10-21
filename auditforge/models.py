"""Core data model shared by connectors, checks, reports and the store."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL_REVIEW = "MANUAL_REVIEW"  # automation can't see enough to decide; a human must


@dataclass(frozen=True)
class Evidence:
    """Metadata for one raw API response saved unmodified to disk."""

    evidence_id: str
    source_uri: str  # e.g. "GET https://api.github.com/repos/o/r/rules/branches/main"
    http_status: int
    collected_at: str  # UTC ISO-8601
    sha256: str  # hash of the exact bytes on disk
    file_path: str  # relative to the run directory, e.g. "raw/rulesets.json"


@dataclass(frozen=True)
class RawResponse:
    """What a connector hands to a check: the parsed body plus the evidence it came from."""

    evidence: Evidence
    body: Any  # parsed JSON, or None if the body was not JSON

    @property
    def status(self) -> int:
        return self.evidence.http_status


@dataclass
class Finding:
    check_id: str
    title: str
    resource: str  # what was tested, e.g. "myorg/payments-api@main"
    status: Status
    detail: str
    observed: dict[str, Any]
    evidence_ids: list[str]
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex)
