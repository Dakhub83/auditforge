"""IaC scan import: Checkov JSON + SARIF parsing, rule classification, findings, CLI, gap link."""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditforge.checks import iac
from auditforge.checks.population import EXCEPTION, OK, REVIEW
from auditforge.cli import app
from auditforge.mappings import MappingError, Mappings, load_iac_rules
from auditforge.models import Evidence, RawResponse, Status
from auditforge.paths import default_mappings_dir
from auditforge.store import latest_control_results
from tests.conftest import FIXTURES

runner = CliRunner()
MAPPINGS = Mappings.load(default_mappings_dir())
RULES = load_iac_rules(default_mappings_dir(), MAPPINGS)
TITLES = {k: v["title"] for k, v in MAPPINGS.checks.items()}
CHECKOV = FIXTURES / "iac" / "checkov_terraform.json"
SARIF = FIXTURES / "iac" / "kube_linter.sarif"


def raw(path: Path) -> RawResponse:
    ev = Evidence(uuid.uuid4().hex, f"file {path}", None, "2026-10-22T00:00:00+00:00", "0" * 64, "raw/x.json")
    return RawResponse(ev, json.loads(path.read_text(encoding="utf-8")))


def result(rule_id: str = "X", name: str = "") -> iac.ScanResult:
    return iac.ScanResult("t", rule_id, name, EXCEPTION, "r", "f", None, None, "", "e")


# --- Parsing --------------------------------------------------------------------------


def test_detect_format() -> None:
    assert iac.detect_format(raw(CHECKOV).body) == "checkov"
    assert iac.detect_format([raw(CHECKOV).body]) == "checkov"  # multi-framework runs are a list
    assert iac.detect_format(raw(SARIF).body) == "sarif"
    assert iac.detect_format({"version": "2.0.0", "runs": []}) is None
    assert iac.detect_format({"foo": 1}) is None


def test_parse_checkov_keeps_failures_passes_and_suppressions() -> None:
    results = iac.parse(raw(CHECKOV))
    by = {r.rule_id: r for r in results}
    assert len(results) == 8
    assert by["CKV_AWS_19"].outcome == EXCEPTION and by["CKV_AWS_19"].file == "/infra/storage.tf"
    assert by["CKV_AWS_20"].outcome == OK
    assert by["CKV_AWS_145"].outcome == REVIEW
    assert "SSE-S3 accepted by security policy SP-12" in by["CKV_AWS_145"].note


def test_parse_sarif_kinds_levels_and_suppressions() -> None:
    by = {r.rule_id: r for r in iac.parse(raw(SARIF))}
    assert set(by) == {"privileged-container", "run-as-non-root", "latest-tag"}  # notApplicable dropped
    assert by["privileged-container"].outcome == EXCEPTION
    assert by["privileged-container"].resource == "payments/Deployment/api"
    assert by["privileged-container"].line == 22
    assert by["run-as-non-root"].outcome == REVIEW and "SEC-418" in by["run-as-non-root"].note
    assert by["latest-tag"].outcome == OK


# --- Classification -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule_id", "name", "family"),
    [
        ("CKV_AWS_19", "anything", "IAC-ENC"),  # explicit ID wins
        ("X", "Ensure S3 bucket has public access block", "IAC-NET"),  # NET is checked before ENC
        ("X", "Ensure root block device is encrypted", "IAC-ENC"),  # 'encrypt' before 'root' (PRIV)
        ("X", "Ensure the S3 bucket has access logging enabled", "IAC-LOG"),
        ("X", "Ensure Instance Metadata Service Version 1 is not enabled", "IAC-CFG"),  # fallback
    ],
)
def test_classify_precedence(rule_id: str, name: str, family: str) -> None:
    assert iac.classify(result(rule_id, name), RULES)[0] == family


def test_rules_must_reference_known_families(tmp_path: Path) -> None:
    (tmp_path / "iac_rules.yaml").write_text("fallback: IAC-NOPE\nfamilies: {}\n", encoding="utf-8")
    with pytest.raises(MappingError, match="IAC-NOPE"):
        load_iac_rules(tmp_path, MAPPINGS)


# --- Findings -------------------------------------------------------------------------


def test_evaluate_groups_by_family_with_statuses() -> None:
    findings = {
        f.check_id: f for f in iac.evaluate([raw(CHECKOV), raw(SARIF)], RULES, TITLES, "iac:payments")
    }
    assert findings["IAC-ENC"].status is Status.FAIL  # CKV_AWS_19 failed
    assert findings["IAC-ENC"].observed["manual_review"] == 1  # the suppressed KMS rule
    assert findings["IAC-NET"].status is Status.FAIL
    assert findings["IAC-LOG"].status is Status.FAIL
    assert findings["IAC-BAK"].status is Status.PASS  # only S3 versioning, which passed
    assert findings["IAC-PRIV"].status is Status.FAIL  # privileged container
    assert findings["IAC-CFG"].status is Status.FAIL  # IMDSv1 fell back to the baseline family
    assert findings["IAC-ENC"].detail.startswith("1 of 3 scanner results failed: CKV_AWS_19 aws_s3_bucket")
    items = findings["IAC-NET"].observed["items"]
    assert items[0]["classified_by"].startswith("rule CKV_AWS_24")
    assert len(findings["IAC-PRIV"].evidence_ids) == 1


def test_only_suppressions_is_manual_review() -> None:
    skipped = {"check_id": "CKV_AWS_19", "check_name": "x", "check_result": {"suppress_comment": "accepted"}}
    body = {"check_type": "terraform", "results": {"skipped_checks": [skipped]}}
    ev = Evidence("e", "file x", None, "t", "0" * 64, "raw/x.json")
    (finding,) = iac.evaluate([RawResponse(ev, body)], RULES, TITLES, "iac:x")
    assert finding.status is Status.MANUAL_REVIEW


# --- CLI ------------------------------------------------------------------------------


def cli(tmp_path: Path, *args: str):
    return runner.invoke(
        app,
        ["check", "iac", *args, "--out", str(tmp_path / "evidence"), "--db", str(tmp_path / "auditforge.db")],
    )


def test_cli_imports_maps_signs_and_feeds_controls(tmp_path: Path) -> None:
    result = cli(tmp_path, "--results", str(CHECKOV), "--results", str(SARIF), "--target", "payments-infra")
    assert result.exit_code == 1, result.output  # failures present
    assert "1 pass, 5 fail, 0 manual review" in result.output

    (report_path,) = (tmp_path / "evidence").glob("*/report.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    raws = sorted((report_path.parent / "raw").iterdir())
    assert [p.read_bytes() for p in raws] == [CHECKOV.read_bytes(), SARIF.read_bytes()]  # copied unmodified
    enc = next(f for f in report["findings"] if f["check_id"] == "IAC-ENC")
    assert enc["controls"]["ISO27001:2022"] == ["A.8.24"]
    assert enc["controls"]["NIST-800-53r5"] == ["SC-8", "SC-28"]
    assert runner.invoke(app, ["verify", str(report_path)]).exit_code == 0

    conn = sqlite3.connect(tmp_path / "auditforge.db")
    health = latest_control_results(conn, "SOC2", "CC6.7")
    conn.close()
    assert [(h["check_id"], h["status"], h["resource"]) for h in health] == [
        ("IAC-ENC", "FAIL", "iac:payments-infra")
    ]


def test_cli_rejects_unknown_format(tmp_path: Path) -> None:
    bogus = tmp_path / "trivy-table.json"
    bogus.write_text('{"Results": []}', encoding="utf-8")
    result = cli(tmp_path, "--results", str(bogus))
    assert result.exit_code == 2
    assert "neither Checkov JSON nor SARIF" in result.output


def test_cli_rejects_empty_scan(tmp_path: Path) -> None:
    empty = tmp_path / "empty.sarif"
    empty.write_text(
        '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}}, "results": []}]}', "utf-8"
    )
    result = cli(tmp_path, "--results", str(empty))
    assert result.exit_code == 2
    assert "no results" in result.output


def test_cli_missing_file_exits_2(tmp_path: Path) -> None:
    assert cli(tmp_path, "--results", str(tmp_path / "nope.json")).exit_code == 2
