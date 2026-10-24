# ruff: noqa: F811  -- pytest fixtures (repo) are imported by name and re-bound as parameters
"""Finding exceptions and preparer/reviewer sign-off, plus their effect on gap and view."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditforge.cli import app
from auditforge.gap.engine import ControlInput, GapMethod, assess
from auditforge.paths import default_mappings_dir
from tests.test_local_git import needs_git, repo, run_cli  # noqa: F401  (repo is a fixture)

runner = CliRunner()
TODAY = datetime.now(UTC).date()
RESOURCE = "payments-api@main"  # what run_cli's fixture repo is reported as


def as_user(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setattr("auditforge.workpaper.cli.operator", lambda: name)


def wp(tmp_path: Path, *args: str):
    return runner.invoke(app, [*args, "--db", str(tmp_path / "auditforge.db")])


def add_exception(tmp_path: Path, **overrides: str):
    opts = {
        "--check": "GIT-CM-03", "--resource": RESOURCE,
        "--reason": "Hotfix process with post-review; see SEC-12",
        "--approved-by": "Dana CISO", "--expires": (TODAY + timedelta(days=90)).isoformat(),
    } | overrides  # fmt: skip
    return wp(tmp_path, "exception", "add", *[x for kv in opts.items() for x in kv])


# --- Exceptions -----------------------------------------------------------------------


@needs_git
def test_exception_lifecycle(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_cli(repo, tmp_path)
    as_user(monkeypatch, "alice")
    added = add_exception(tmp_path)
    assert added.exit_code == 0, added.output
    assert "Recorded EXC-1 approved by Dana CISO" in added.output
    assert "active" in wp(tmp_path, "exception", "list").output

    revoked = wp(tmp_path, "exception", "revoke", "EXC-1", "--reason", "Branch protection now enforced")
    assert revoked.exit_code == 0, revoked.output
    assert "revoked" in wp(tmp_path, "exception", "list").output
    assert wp(tmp_path, "exception", "revoke", "EXC-1", "--reason", "again").exit_code == 2

    conn = sqlite3.connect(tmp_path / "auditforge.db")
    for sql in ("UPDATE finding_exceptions SET reason = 'x'", "DELETE FROM finding_exceptions",
                "DELETE FROM exception_revocations"):  # fmt: skip
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(sql)
    conn.close()


@needs_git
@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"--approved-by": "ALICE"}, "no self-approval"),
        ({"--expires": (TODAY + timedelta(days=400)).isoformat()}, "at most 365 days"),
        ({"--expires": (TODAY - timedelta(days=1)).isoformat()}, "in the future"),
        ({"--resource": "other@main"}, "nothing to accept"),
        ({"--check": "GIT-CM-99"}, "nothing to accept"),
        ({"--risk": "R-404"}, "No risk R-404"),
    ],
)
def test_exception_rules(
    repo: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict,
    message: str,
) -> None:
    run_cli(repo, tmp_path)
    as_user(monkeypatch, "alice")
    result = add_exception(tmp_path, **overrides)
    assert result.exit_code == 2
    assert message in result.output


# --- Gap engine with exceptions -------------------------------------------------------

METHOD = GapMethod.load(default_mappings_dir())


def fail(check: str = "GIT-CM-03", resource: str = RESOURCE, status: str = "FAIL") -> dict[str, str]:
    return {
        "check_id": check,
        "resource": resource,
        "status": status,
        "run_id": "r",
        "at": "2026-10-01T00:00:00",
    }


def decide(automated: list[dict[str, str]], exceptions: dict) -> tuple[str, list[str]]:
    c = ControlInput("SOC2", "CC6.1", "t", automated, None, [], exceptions=exceptions)
    r = assess([c], METHOD, TODAY.isoformat())[0]
    return r.status, r.reasons


def test_fully_excepted_failure_is_accepted_not_a_gap() -> None:
    status, reasons = decide([fail()], {("GIT-CM-03", RESOURCE): "EXC-1 approved by Dana until 2027-01-31"})
    assert status == "accepted"
    assert "accepted: EXC-1" in reasons[0]


def test_unexcepted_failure_keeps_the_control_failing() -> None:
    status, reasons = decide(
        [fail(), fail(resource="other@main")], {("GIT-CM-03", RESOURCE): "EXC-1 approved by Dana"}
    )
    assert status == "failing"
    assert any("accepted: EXC-1" in r for r in reasons)  # still shown


def test_open_review_keeps_needs_review() -> None:
    status, _ = decide(
        [fail(), fail("GIT-CM-01", status="MANUAL_REVIEW")], {("GIT-CM-03", RESOURCE): "EXC-1"}
    )
    assert status == "needs_review"


@needs_git
def test_gap_report_lists_accepted_exception(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_cli(repo, tmp_path)
    as_user(monkeypatch, "alice")
    assert add_exception(tmp_path).exit_code == 0
    scope = tmp_path / "scope.yaml"
    runner.invoke(app, ["scope", "init", "--framework", "SOC2", "--out", str(scope)])
    result = wp(tmp_path, "gap", "--scope", str(scope), "--out", str(tmp_path / "gap"))
    (path,) = (tmp_path / "gap").glob("*/gap-report.json")
    report = json.loads(path.read_text(encoding="utf-8"))
    cc61 = next(c for c in report["controls"] if c["key"] == "SOC2 CC6.1")
    assert cc61["status"] == "accepted"
    assert report["summary"]["frameworks"]["SOC2"]["accepted"] == 1
    assert "## Accepted exceptions (1)" in (path.parent / "gap-report.md").read_text(encoding="utf-8")
    assert result.exit_code == 0  # nothing left failing once the FAIL is accepted


# --- Sign-off -------------------------------------------------------------------------


@needs_git
def test_preparer_then_independent_reviewer(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run_cli(repo, tmp_path)
    (report,) = (tmp_path / "evidence").glob("*/report.json")

    as_user(monkeypatch, "bob")
    early = wp(tmp_path, "signoff", "add", str(report), "--role", "reviewer")
    assert early.exit_code == 2 and "after a preparer" in early.output

    as_user(monkeypatch, "alice")
    prepared = wp(
        tmp_path, "signoff", "add", str(report), "--role", "preparer", "--note", "Tested full population"
    )
    assert prepared.exit_code == 0, prepared.output
    same = wp(tmp_path, "signoff", "add", str(report), "--role", "reviewer")
    assert same.exit_code == 2 and "different person" in same.output

    as_user(monkeypatch, "bob")
    reviewed = wp(tmp_path, "signoff", "add", str(report), "--role", "reviewer")
    assert reviewed.exit_code == 0, reviewed.output
    shown = wp(tmp_path, "signoff", "show", str(report)).output
    assert re.search(r"preparer\s+alice", shown) and re.search(r"reviewer\s+bob", shown)

    view = tmp_path / "view.html"
    assert (
        runner.invoke(app, ["view", "--db", str(tmp_path / "auditforge.db"), "--out", str(view)]).exit_code
        == 0
    )
    html = view.read_text(encoding="utf-8")
    assert '"signed_by": "alice"' in html and '"role": "reviewer"' in html


@needs_git
def test_cannot_sign_a_tampered_report(repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run_cli(repo, tmp_path)
    (report,) = (tmp_path / "evidence").glob("*/report.json")
    (log,) = report.parent.glob("raw/first_parent_log.txt")
    log.write_text("edited", encoding="utf-8")
    as_user(monkeypatch, "alice")
    result = wp(tmp_path, "signoff", "add", str(report), "--role", "preparer")
    assert result.exit_code == 2
    assert "Refusing to sign an unverified report" in result.output


def test_dates_are_validated(tmp_path: Path) -> None:
    args = ["exception", "add", "--check", "X", "--resource", "y", "--reason", "z", "--approved-by", "a"]
    result = runner.invoke(app, [*args, "--expires", "31/01/2027", "--db", str(tmp_path / "a.db")])
    assert result.exit_code == 2
    assert "date like" in result.output
