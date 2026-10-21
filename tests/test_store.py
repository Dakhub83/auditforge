from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from auditforge.mappings import Mappings
from auditforge.paths import default_mappings_dir
from auditforge.store import Store


def report(run_id: str = "run-1") -> dict[str, Any]:
    return {
        "run_id": run_id,
        "started_at": "2026-10-21T10:00:00+00:00",
        "tool_version": "0.2.0",
        "operator": "auditor",
        "signature": {"signature": "c2ln"},
        "evidence": [
            {
                "evidence_id": f"{run_id}-ev1",
                "source_uri": "GET https://api.github.com/a",
                "collected_at": "2026-10-21T10:00:01+00:00",
                "sha256": "a" * 64,
                "file_path": "raw/classic_protection.json",
            },
            {
                "evidence_id": f"{run_id}-ev2",
                "source_uri": "GET https://api.github.com/b",
                "collected_at": "2026-10-21T10:00:02+00:00",
                "sha256": "b" * 64,
                "file_path": "raw/rulesets.json",
            },
        ],
        "findings": [
            {
                "finding_id": f"{run_id}-f1",
                "check_id": "GH-BP-01",
                "resource": "acme/payments-api@main",
                "status": "FAIL",
                "detail": "No PR requirement found.",
                "evidence_ids": [f"{run_id}-ev1", f"{run_id}-ev2"],
            }
        ],
    }


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "auditforge.db")
    yield s
    s.close()


def count(store: Store, table: str) -> int:
    return store.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_record_run(store: Store, tmp_path: Path) -> None:
    store.record_run(report(), tmp_path / "run-1")
    assert (count(store, "runs"), count(store, "evidence"), count(store, "findings")) == (1, 2, 1)
    assert count(store, "finding_evidence") == 2
    path = store.conn.execute("SELECT file_path FROM evidence WHERE evidence_id = 'run-1-ev1'").fetchone()[0]
    assert Path(path).is_absolute()


def test_runs_accumulate(store: Store, tmp_path: Path) -> None:
    store.record_run(report("run-1"), tmp_path)
    store.record_run(report("run-2"), tmp_path)
    assert count(store, "runs") == 2


def test_duplicate_run_rolls_back_whole_transaction(store: Store, tmp_path: Path) -> None:
    store.record_run(report(), tmp_path)
    with pytest.raises(sqlite3.IntegrityError):
        store.record_run(report(), tmp_path)
    assert (count(store, "runs"), count(store, "evidence"), count(store, "findings")) == (1, 2, 1)


def test_invalid_status_rejected(store: Store, tmp_path: Path) -> None:
    bad = report()
    bad["findings"][0]["status"] = "PROBABLY_FINE"
    with pytest.raises(sqlite3.IntegrityError):
        store.record_run(bad, tmp_path)
    assert count(store, "runs") == 0


def test_finding_evidence_must_reference_real_evidence(store: Store, tmp_path: Path) -> None:
    bad = report()
    bad["findings"][0]["evidence_ids"] = ["does-not-exist"]
    with pytest.raises(sqlite3.IntegrityError):
        store.record_run(bad, tmp_path)


def test_sync_mappings_idempotent(store: Store) -> None:
    mappings = Mappings.load(default_mappings_dir())
    store.sync_mappings(mappings)
    store.sync_mappings(mappings)
    assert count(store, "controls") == len(mappings.control_catalog())
    rows = store.conn.execute(
        "SELECT framework, control_id FROM check_control_map WHERE check_id = 'GH-BP-05' ORDER BY 1, 2"
    ).fetchall()
    assert ("NIST-800-53r5", "CM-5") in rows and ("SOC2", "CC6.1") in rows


def test_exceptions_table_exists_and_is_empty(store: Store) -> None:
    assert count(store, "exceptions") == 0
