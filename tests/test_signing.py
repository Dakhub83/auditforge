from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auditforge.signing import (
    PUBLIC_KEY_FILE,
    load_or_create_key,
    load_public_key,
    sign_report,
    verify_report,
)


def make_run(run_dir: Path, key: Ed25519PrivateKey, mutate: Any = None) -> Path:
    raw = run_dir / "raw" / "rulesets.json"
    raw.parent.mkdir(parents=True)
    raw.write_bytes(b'[{"type": "pull_request"}]')
    report: dict[str, Any] = {
        "run_id": "r1",
        "findings": [{"check_id": "GH-BP-01", "status": "PASS", "detail": "Ünïcode survives"}],
        "evidence": [
            {"file_path": "raw/rulesets.json", "sha256": hashlib.sha256(raw.read_bytes()).hexdigest()}
        ],
    }
    if mutate:
        mutate(report)
    report["signature"] = sign_report(report, key)
    path = run_dir / "report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def test_roundtrip_valid(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    result = verify_report(make_run(tmp_path, key), key.public_key())
    assert result.ok, result.message
    assert "1 evidence hashes" in result.message


def test_edited_report_is_invalid(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    path = make_run(tmp_path, key)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["findings"][0]["status"] = "FAIL"
    path.write_text(json.dumps(doc), encoding="utf-8")
    result = verify_report(path, key.public_key())
    assert not result.ok and "modified after signing" in result.message


def test_resigned_with_attacker_key_is_invalid(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    # The prototype trusted the key embedded in the report, so this passed.
    attacker = Ed25519PrivateKey.generate()
    path = make_run(tmp_path, attacker)
    result = verify_report(path, key.public_key())
    assert not result.ok and "not the trusted key" in result.message


def test_edited_evidence_is_invalid(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    path = make_run(tmp_path, key)
    (tmp_path / "raw" / "rulesets.json").write_bytes(b"[]")
    result = verify_report(path, key.public_key())
    assert not result.ok and "raw/rulesets.json" in result.message


def test_missing_evidence_is_invalid(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    path = make_run(tmp_path, key)
    (tmp_path / "raw" / "rulesets.json").unlink()
    result = verify_report(path, key.public_key())
    assert not result.ok and "missing" in result.message


def test_evidence_path_outside_run_dir_is_invalid(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (tmp_path / "outside.json").write_bytes(b"x")

    def point_outside(report: dict[str, Any]) -> None:
        report["evidence"] = [{"file_path": "../outside.json", "sha256": hashlib.sha256(b"x").hexdigest()}]

    result = verify_report(make_run(run_dir, key, point_outside), key.public_key())
    assert not result.ok and "missing" in result.message


def test_malformed_report_is_invalid(tmp_path: Path, key: Ed25519PrivateKey) -> None:
    path = tmp_path / "report.json"
    path.write_text('{"no": "signature"}', encoding="utf-8")
    assert not verify_report(path, key.public_key()).ok


def test_key_created_once_then_reused(tmp_path: Path) -> None:
    key1, created1 = load_or_create_key(tmp_path)
    key2, created2 = load_or_create_key(tmp_path)
    assert created1 and not created2
    pub = load_public_key(tmp_path / PUBLIC_KEY_FILE)
    assert (
        pub.public_bytes_raw() == key1.public_key().public_bytes_raw() == key2.public_key().public_bytes_raw()
    )
