"""Shared pieces for full-population tests: the audit period, per-item outcomes, and the
roll-up of item outcomes into one population-level finding status.

A population test looks at every item in scope (every merged PR, every landed commit) rather
than a sample. Each item is OK, an EXCEPTION, or needs REVIEW by a human; the finding is FAIL if
any item is an exception, MANUAL_REVIEW if any needs review, and PASS only if every item is OK.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from auditforge.models import Status

OK, EXCEPTION, REVIEW = "ok", "exception", "review"
MAX_LISTED = 10  # items named in a finding's detail; the full list is in observed
SHA = re.compile(r"[0-9a-f]{40}")


def parse_ts(timestamp: str) -> datetime:
    return datetime.fromisoformat(timestamp)


@dataclass(frozen=True)
class AuditPeriod:
    """[start, end) in UTC, built from inclusive calendar dates."""

    start: datetime
    end: datetime

    @classmethod
    def from_dates(cls, first_day: date, last_day: date) -> AuditPeriod:
        if last_day < first_day:
            raise ValueError("The period end is before its start")
        start = datetime.combine(first_day, time(), UTC)
        return cls(start, datetime.combine(last_day + timedelta(days=1), time(), UTC))

    @property
    def start_iso(self) -> str:
        return self.start.strftime("%Y-%m-%dT%H:%M:%SZ")

    @property
    def first_day(self) -> str:
        return self.start.date().isoformat()

    @property
    def last_day(self) -> str:
        return (self.end - timedelta(days=1)).date().isoformat()

    @property
    def label(self) -> str:
        return f"{self.first_day} to {self.last_day}"

    def contains(self, timestamp: str | None) -> bool:
        return bool(timestamp) and self.start <= parse_ts(timestamp) < self.end


@dataclass(frozen=True)
class ItemResult:
    item: str  # "#123" or a commit SHA
    outcome: str  # OK | EXCEPTION | REVIEW
    note: str
    facts: dict[str, Any]


def _label(item: str) -> str:
    """Commit SHAs are shortened like git does; other item names are kept whole."""
    return item[:12] if SHA.fullmatch(item) else item


def named(results: list[ItemResult]) -> str:
    listed = "; ".join(f"{_label(r.item)} ({r.note})" for r in results[:MAX_LISTED])
    more = len(results) - MAX_LISTED
    return listed + (f"; and {more} more (see observed in report.json)" if more > 0 else "")


def population_status(results: list[ItemResult], noun: str, passed: str, failed: str) -> tuple[Status, str]:
    exceptions = [r for r in results if r.outcome == EXCEPTION]
    reviews = [r for r in results if r.outcome == REVIEW]
    n = len(results)
    if exceptions:
        detail = f"{len(exceptions)} of {n} {noun} {failed}: {named(exceptions)}."
        if reviews:
            detail += f" A further {len(reviews)} need manual review."
        return Status.FAIL, detail
    if reviews:
        return Status.MANUAL_REVIEW, f"{len(reviews)} of {n} {noun} need manual review: {named(reviews)}."
    return Status.PASS, f"All {n} {noun} {passed}."


def summary(results: list[ItemResult]) -> dict[str, Any]:
    return {
        "population": len(results),
        "ok": sum(r.outcome == OK for r in results),
        "exceptions": sum(r.outcome == EXCEPTION for r in results),
        "manual_review": sum(r.outcome == REVIEW for r in results),
        "items": [{**r.facts, "outcome": r.outcome, "note": r.note} for r in results],
    }
