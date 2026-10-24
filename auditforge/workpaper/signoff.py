"""Workpaper sign-off: a dated preparer and reviewer on each signed report.

A sign-off binds to the exact report content: it stores the report's signed payload hash,
and the report is verified (signature and every evidence hash) before anyone may sign it.
Rules, as in any audit file:
- a reviewer sign-off needs an existing preparer sign-off on the same content;
- the reviewer must be a different person from the preparer (segregation of duties).
Sign-offs are append-only.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from auditforge.signing import verify_report

ROLES = ("preparer", "reviewer")

SCHEMA = """
CREATE TABLE IF NOT EXISTS signoffs (
    signoff_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id         TEXT NOT NULL,
    report_sha256  TEXT NOT NULL,  -- the signed payload hash: sign-off covers exactly this content
    role           TEXT NOT NULL CHECK (role IN ('preparer', 'reviewer')),
    signed_by      TEXT NOT NULL,
    signed_at      TEXT NOT NULL,
    note           TEXT NOT NULL DEFAULT ''
);
CREATE TRIGGER IF NOT EXISTS signoffs_append_only_u BEFORE UPDATE ON signoffs
    BEGIN SELECT RAISE(ABORT, 'sign-offs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS signoffs_append_only_d BEFORE DELETE ON signoffs
    BEGIN SELECT RAISE(ABORT, 'sign-offs are append-only'); END;
"""


class SignoffError(ValueError):
    pass


@dataclass(frozen=True)
class Signoff:
    signoff_id: int
    run_id: str
    report_sha256: str
    role: str
    signed_by: str
    signed_at: str
    note: str


class Signoffs:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.conn.executescript(SCHEMA)

    def sign(
        self, report_path: Path, role: str, signer: str, trusted_key: Ed25519PublicKey, note: str = ""
    ) -> Signoff:
        if role not in ROLES:
            raise SignoffError(f"Role must be one of {', '.join(ROLES)}")
        result = verify_report(report_path, trusted_key)
        if not result.ok:
            raise SignoffError(f"Refusing to sign an unverified report. {result.message}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        run_id, digest = report["run_id"], report["signature"]["payload_sha256"]
        existing = self.for_report(run_id, digest)
        if any(s.role == role and s.signed_by.lower() == signer.lower() for s in existing):
            raise SignoffError(f"{signer} has already signed this report as {role}")
        if role == "reviewer":
            preparers = [s for s in existing if s.role == "preparer"]
            if not preparers:
                raise SignoffError("A reviewer can only sign after a preparer has signed")
            if any(s.signed_by.lower() == signer.lower() for s in preparers):
                raise SignoffError("The reviewer must be a different person from the preparer")
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO signoffs (run_id, report_sha256, role, signed_by, signed_at, note) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (run_id, digest, role, signer, datetime.now(UTC).isoformat(timespec="seconds"), note.strip()),
            )
        return self._get(int(cur.lastrowid))

    def _get(self, signoff_id: int) -> Signoff:
        return Signoff(
            *self.conn.execute("SELECT * FROM signoffs WHERE signoff_id = ?", (signoff_id,)).fetchone()
        )

    def for_report(self, run_id: str, report_sha256: str) -> list[Signoff]:
        return [
            Signoff(*row)
            for row in self.conn.execute(
                "SELECT * FROM signoffs WHERE run_id = ? AND report_sha256 = ? ORDER BY signoff_id",
                (run_id, report_sha256),
            )
        ]
