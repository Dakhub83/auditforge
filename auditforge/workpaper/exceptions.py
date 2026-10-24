"""Finding exceptions: a documented, approved, time-limited acceptance of a failing result.

An exception applies to a check on a resource (e.g. GIT-CM-03 on payments-api@origin/main),
not to one finding, because every run creates new findings: the acceptance carries over to
later runs until it expires or is revoked. Rules:
- the approver must not be the person recording it (no self-approval);
- it must expire, at most MAX_DAYS ahead, so accepted risk is re-decided at least yearly;
- it must point at a check/resource that actually has a FAIL or MANUAL_REVIEW finding;
- it can reference the risk in the register that documents the accepted risk.

Signed reports are never changed: exceptions are applied when the gap report and the
dashboard are built, and shown as "accepted" with who approved them and until when.
Exceptions and revocations are append-only.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta

MAX_DAYS = 365

SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_exceptions (
    exception_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    check_id      TEXT NOT NULL,
    resource      TEXT NOT NULL,
    finding_id    TEXT NOT NULL REFERENCES findings(finding_id),  -- the finding that prompted it
    reason        TEXT NOT NULL CHECK (length(trim(reason)) > 0),
    approved_by   TEXT NOT NULL CHECK (length(trim(approved_by)) > 0),
    approved_on   TEXT NOT NULL,
    expires_on    TEXT NOT NULL CHECK (expires_on > approved_on),
    risk_id       TEXT,
    recorded_at   TEXT NOT NULL,
    recorded_by   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exception_revocations (
    exception_id INTEGER PRIMARY KEY REFERENCES finding_exceptions(exception_id),
    revoked_at   TEXT NOT NULL,
    revoked_by   TEXT NOT NULL,
    reason       TEXT NOT NULL CHECK (length(trim(reason)) > 0)
);
CREATE TRIGGER IF NOT EXISTS finding_exceptions_append_only_u BEFORE UPDATE ON finding_exceptions
    BEGIN SELECT RAISE(ABORT, 'exceptions are append-only; revoke and record a new one'); END;
CREATE TRIGGER IF NOT EXISTS finding_exceptions_append_only_d BEFORE DELETE ON finding_exceptions
    BEGIN SELECT RAISE(ABORT, 'exceptions are append-only; revoke instead'); END;
CREATE TRIGGER IF NOT EXISTS exception_revocations_append_only_u BEFORE UPDATE ON exception_revocations
    BEGIN SELECT RAISE(ABORT, 'revocations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS exception_revocations_append_only_d BEFORE DELETE ON exception_revocations
    BEGIN SELECT RAISE(ABORT, 'revocations are append-only'); END;
"""


class ExceptionError(ValueError):
    pass


@dataclass(frozen=True)
class FindingException:
    exception_id: int
    check_id: str
    resource: str
    finding_id: str
    reason: str
    approved_by: str
    approved_on: str
    expires_on: str
    risk_id: str | None
    recorded_at: str
    recorded_by: str
    revoked_on: str | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None

    def is_active_on(self, day: str) -> bool:
        return self.revoked_on is None and self.approved_on <= day <= self.expires_on

    def describe(self) -> str:
        risk = f", risk {self.risk_id}" if self.risk_id else ""
        return (
            f"EXC-{self.exception_id} approved by {self.approved_by} until {self.expires_on}{risk}: "
            f"{self.reason}"
        )


def _drop_unused_legacy_table(conn: sqlite3.Connection) -> None:
    """The first schema had an `exceptions` table nothing ever wrote to; remove it if still empty."""
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'exceptions'"
    ).fetchone()
    if exists and conn.execute("SELECT COUNT(*) FROM exceptions").fetchone()[0] == 0:
        conn.execute("DROP TABLE exceptions")


class Exceptions:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.conn.execute("PRAGMA foreign_keys = ON")
        with self.conn:
            _drop_unused_legacy_table(self.conn)
        self.conn.executescript(SCHEMA)

    def add(
        self,
        check_id: str,
        resource: str,
        reason: str,
        approved_by: str,
        expires_on: date,
        recorded_by: str,
        approved_on: date | None = None,
        risk_id: str | None = None,
    ) -> FindingException:
        today = datetime.now(UTC).date()
        approved_on = approved_on or today
        if approved_by.strip().lower() == recorded_by.strip().lower():
            raise ExceptionError(
                "The approver cannot be the person recording the exception (no self-approval)"
            )
        if approved_on > today:
            raise ExceptionError(f"Approval date {approved_on} is in the future")
        if expires_on <= today:
            raise ExceptionError("The expiry date must be in the future")
        if expires_on > approved_on + timedelta(days=MAX_DAYS):
            raise ExceptionError(
                f"Exceptions can last at most {MAX_DAYS} days; re-approve it when it expires"
            )
        row = self.conn.execute(
            "SELECT f.finding_id FROM findings f JOIN runs r USING (run_id) "
            "WHERE f.check_id = ? AND f.resource = ? AND f.status IN ('FAIL', 'MANUAL_REVIEW') "
            "ORDER BY r.started_at DESC LIMIT 1",
            (check_id, resource),
        ).fetchone()
        if row is None:
            raise ExceptionError(
                f"No FAIL or MANUAL_REVIEW finding for {check_id} on {resource}; nothing to accept "
                "(check the exact resource name in the report)"
            )
        if risk_id and not self.conn.execute("SELECT 1 FROM risks WHERE risk_id = ?", (risk_id,)).fetchone():
            raise ExceptionError(f"No risk {risk_id} in the register")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO finding_exceptions (check_id, resource, finding_id, reason, approved_by, "
                "approved_on, "
                "expires_on, risk_id, recorded_at, recorded_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    check_id, resource, row[0], reason.strip(), approved_by.strip(),
                    approved_on.isoformat(), expires_on.isoformat(), risk_id,
                    datetime.now(UTC).isoformat(timespec="seconds"), recorded_by,
                ),
            )  # fmt: skip
        return self.get(int(cur.lastrowid))

    def revoke(self, exception_id: int, reason: str, revoked_by: str) -> FindingException:
        exc = self.get(exception_id)
        if exc.revoked_on:
            raise ExceptionError(f"EXC-{exception_id} was already revoked on {exc.revoked_on}")
        with self.conn:
            self.conn.execute(
                "INSERT INTO exception_revocations (exception_id, revoked_at, revoked_by, reason) "
                "VALUES (?, ?, ?, ?)",
                (exception_id, datetime.now(UTC).isoformat(timespec="seconds"), revoked_by, reason.strip()),
            )
        return self.get(exception_id)

    _SELECT = (
        "SELECT e.*, substr(v.revoked_at, 1, 10), v.revoked_by, v.reason FROM finding_exceptions e "
        "LEFT JOIN exception_revocations v USING (exception_id)"
    )

    def get(self, exception_id: int) -> FindingException:
        row = self.conn.execute(self._SELECT + " WHERE e.exception_id = ?", (exception_id,)).fetchone()
        if row is None:
            raise ExceptionError(f"No exception EXC-{exception_id}")
        return FindingException(*row)

    def all(self) -> list[FindingException]:
        return [
            FindingException(*row) for row in self.conn.execute(self._SELECT + " ORDER BY e.exception_id")
        ]

    def active(self, check_id: str, resource: str, day: str) -> FindingException | None:
        """The newest exception covering this check on this resource on the given day."""
        matching = [
            e for e in self.all() if e.check_id == check_id and e.resource == resource and e.is_active_on(day)
        ]
        return matching[-1] if matching else None
