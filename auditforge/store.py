"""SQLite store (auditforge.db): an index of runs, evidence and findings.

The signed report.json is the record of truth; this database makes runs
queryable across time. The exceptions table is for human-entered risk
acceptance and is never written by the tool.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from auditforge.mappings import Mappings

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id       TEXT PRIMARY KEY,
    started_at   TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    operator     TEXT NOT NULL,
    signature    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id  TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL REFERENCES runs(run_id),
    source_uri   TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    file_path    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    run_id     TEXT NOT NULL REFERENCES runs(run_id),
    check_id   TEXT NOT NULL,
    resource   TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('PASS', 'FAIL', 'MANUAL_REVIEW')),
    detail     TEXT NOT NULL
);
-- A finding can rest on several evidence items (e.g. classic protection + rulesets).
CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id  TEXT NOT NULL REFERENCES findings(finding_id),
    evidence_id TEXT NOT NULL REFERENCES evidence(evidence_id),
    PRIMARY KEY (finding_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS controls (
    control_id TEXT NOT NULL,
    framework  TEXT NOT NULL,
    title      TEXT NOT NULL,
    PRIMARY KEY (framework, control_id)
);
-- Reflects the current mappings. Each report.json keeps the mapping used at run time.
CREATE TABLE IF NOT EXISTS check_control_map (
    check_id   TEXT NOT NULL,
    framework  TEXT NOT NULL,
    control_id TEXT NOT NULL,
    PRIMARY KEY (check_id, framework, control_id),
    FOREIGN KEY (framework, control_id) REFERENCES controls(framework, control_id)
);
CREATE TABLE IF NOT EXISTS exceptions (
    finding_id  TEXT NOT NULL REFERENCES findings(finding_id),
    approved_by TEXT NOT NULL,
    reason      TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path) -> None:
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def sync_mappings(self, mappings: Mappings) -> None:
        with self.conn:
            self.conn.executemany(
                "INSERT INTO controls (framework, control_id, title) VALUES (?, ?, ?) "
                "ON CONFLICT (framework, control_id) DO UPDATE SET title = excluded.title",
                mappings.control_catalog(),
            )
            self.conn.execute("DELETE FROM check_control_map")
            self.conn.executemany(
                "INSERT INTO check_control_map (check_id, framework, control_id) VALUES (?, ?, ?)",
                [
                    (check_id, framework, control_id)
                    for check_id in mappings.checks
                    for framework, ids in mappings.controls_for(check_id).items()
                    for control_id in ids
                ],
            )

    def record_run(self, report: dict[str, Any], run_dir: Path) -> None:
        """Insert a signed report's run, evidence and findings in one transaction."""
        with self.conn:
            self.conn.execute(
                "INSERT INTO runs (run_id, started_at, tool_version, operator, signature) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    report["run_id"],
                    report["started_at"],
                    report["tool_version"],
                    report["operator"],
                    report["signature"]["signature"],
                ),
            )
            self.conn.executemany(
                "INSERT INTO evidence (evidence_id, run_id, source_uri, collected_at, sha256, file_path) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        e["evidence_id"],
                        report["run_id"],
                        e["source_uri"],
                        e["collected_at"],
                        e["sha256"],
                        str((run_dir / e["file_path"]).resolve()),
                    )
                    for e in report["evidence"]
                ],
            )
            self.conn.executemany(
                "INSERT INTO findings (finding_id, run_id, check_id, resource, status, detail) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        f["finding_id"],
                        report["run_id"],
                        f["check_id"],
                        f["resource"],
                        f["status"],
                        f["detail"],
                    )
                    for f in report["findings"]
                ],
            )
            self.conn.executemany(
                "INSERT INTO finding_evidence (finding_id, evidence_id) VALUES (?, ?)",
                [(f["finding_id"], ev) for f in report["findings"] for ev in f["evidence_ids"]],
            )
