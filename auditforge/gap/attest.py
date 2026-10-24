"""Manual attestations: a person's documented test of a control, with optional evidence file.

Most controls (policies, training, vendor reviews, physical security) cannot be tested by a
script. An attestation records who tested the control, how, when, the result, and until when
the result can be relied on. The evidence file is copied into the evidence folder and hashed,
so the gap report can carry it and `auditforge verify` can re-check it.

Attestations are append-only: a re-test adds a new row, and the latest valid one counts.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

ATTESTATION_DIR = "attestations"
DEFAULT_VALIDITY_DAYS = 365

SCHEMA = """
CREATE TABLE IF NOT EXISTS attestations (
    attestation_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    framework       TEXT NOT NULL,
    control_id      TEXT NOT NULL,
    result          TEXT NOT NULL CHECK (result IN ('PASS', 'FAIL')),
    procedure       TEXT NOT NULL CHECK (length(trim(procedure)) > 0),
    tested_by       TEXT NOT NULL CHECK (length(trim(tested_by)) > 0),
    tested_on       TEXT NOT NULL,
    valid_until     TEXT NOT NULL CHECK (valid_until > tested_on),
    recorded_at     TEXT NOT NULL,
    recorded_by     TEXT NOT NULL,
    evidence_path   TEXT,
    evidence_sha256 TEXT,
    FOREIGN KEY (framework, control_id) REFERENCES controls(framework, control_id)
);
CREATE TRIGGER IF NOT EXISTS attestations_append_only_u BEFORE UPDATE ON attestations
    BEGIN SELECT RAISE(ABORT, 'attestations are append-only; record a new one'); END;
CREATE TRIGGER IF NOT EXISTS attestations_append_only_d BEFORE DELETE ON attestations
    BEGIN SELECT RAISE(ABORT, 'attestations are append-only; record a new one'); END;
"""


class AttestationError(ValueError):
    pass


@dataclass(frozen=True)
class Attestation:
    attestation_id: int
    framework: str
    control_id: str
    result: str
    procedure: str
    tested_by: str
    tested_on: str
    valid_until: str
    recorded_at: str
    recorded_by: str
    evidence_path: str | None
    evidence_sha256: str | None

    def is_valid_on(self, day: str) -> bool:
        return self.valid_until >= day


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


class Attestations:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def add(
        self,
        framework: str,
        control_id: str,
        result: str,
        procedure: str,
        tested_by: str,
        recorded_by: str,
        evidence_root: Path,
        tested_on: date | None = None,
        valid_until: date | None = None,
        evidence: Path | None = None,
    ) -> Attestation:
        result = result.upper()
        if result not in ("PASS", "FAIL"):
            raise AttestationError(
                "Result must be PASS or FAIL; a person decides, so there is no MANUAL_REVIEW"
            )
        today = datetime.now(UTC).date()
        tested_on = tested_on or today
        if tested_on > today:
            raise AttestationError(f"Test date {tested_on} is in the future")
        valid_until = valid_until or tested_on + timedelta(days=DEFAULT_VALIDITY_DAYS)
        if valid_until <= tested_on:
            raise AttestationError("valid-until must be after the test date")
        if not self.conn.execute(
            "SELECT 1 FROM controls WHERE framework = ? AND control_id = ?", (framework, control_id)
        ).fetchone():
            raise AttestationError(f"Unknown control {framework} {control_id}; check mappings/crosswalk.yaml")

        stored, digest = None, None
        if evidence is not None:
            if not evidence.is_file():
                raise AttestationError(f"No evidence file at {evidence}")
            digest = _sha256(evidence)
            # Content-addressed copy: the same file attached twice is stored once.
            target = evidence_root / ATTESTATION_DIR / f"{digest[:12]}-{evidence.name}"
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copy2(evidence, target)
            if _sha256(target) != digest:
                raise AttestationError(
                    f"{target} exists with different content; refusing to overwrite evidence"
                )
            stored = str(target.resolve())

        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO attestations (framework, control_id, result, procedure, tested_by, tested_on, "
                "valid_until, recorded_at, recorded_by, evidence_path, evidence_sha256) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    framework, control_id, result, procedure.strip(), tested_by.strip(),
                    tested_on.isoformat(),
                    valid_until.isoformat(), datetime.now(UTC).isoformat(timespec="seconds"), recorded_by,
                    stored, digest,
                ),
            )  # fmt: skip
        return self.get(int(cur.lastrowid))

    def get(self, attestation_id: int) -> Attestation:
        row = self.conn.execute(
            "SELECT * FROM attestations WHERE attestation_id = ?", (attestation_id,)
        ).fetchone()
        if row is None:
            raise AttestationError(f"No attestation A-{attestation_id}")
        return Attestation(*row)

    def latest(self, framework: str, control_id: str) -> Attestation | None:
        """The most recent test of a control (valid or not; callers check validity)."""
        row = self.conn.execute(
            "SELECT * FROM attestations WHERE framework = ? AND control_id = ? "
            "ORDER BY tested_on DESC, attestation_id DESC LIMIT 1",
            (framework, control_id),
        ).fetchone()
        return Attestation(*row) if row else None

    def all(self) -> list[Attestation]:
        return [
            Attestation(*row)
            for row in self.conn.execute(
                "SELECT * FROM attestations ORDER BY framework, control_id, tested_on, attestation_id"
            )
        ]
