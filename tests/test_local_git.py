"""GIT-CM-01..03: pure checks on synthetic git output, plus the connector and CLI on a real
throwaway repo built in tmp_path (local only; no network)."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import uuid
from datetime import date
from pathlib import Path

import pytest
import responses
from typer.testing import CliRunner

from auditforge.checks import local_git as lg
from auditforge.checks.population import EXCEPTION, OK, REVIEW, AuditPeriod
from auditforge.cli import app
from auditforge.connectors.git import LOG_FIELDS, GitConnector
from auditforge.models import CommandOutput, Evidence, Status

PERIOD = AuditPeriod.from_dates(date(2026, 1, 1), date(2026, 3, 31))
WEB_FLOW_FPR = "968479A1AFF927E37D1A566BB5690EEEBB952194"  # ends with the current web-flow key ID
runner = CliRunner()


# --- Pure checks on synthetic output --------------------------------------------------


def log_record(**overrides: str) -> str:
    fields = {
        "sha": uuid.uuid4().hex + "00000000",
        "parents": "a" * 40,
        "committed_at": "2026-02-01T12:00:00+00:00",
        "author_name": "Alice",
        "author_email": "alice@example.com",
        "committer_name": "GitHub",
        "committer_email": "noreply@github.com",
        "signature": "G",
        "signing_key": "B5690EEEBB952194",
        "signing_fingerprint": WEB_FLOW_FPR,
        "subject": "Add retry to payment client (#42)",
        **overrides,
    }
    return "\x1f".join(fields[name] for name, _ in LOG_FIELDS) + "\x1e\n"


def output(text: str, exit_code: int = 0, error: str = "") -> CommandOutput:
    ev = Evidence(
        uuid.uuid4().hex, "git x", None, "2026-04-01T00:00:00+00:00", "0" * 64, "raw/x.txt", exit_code
    )
    return CommandOutput(ev, text, error)


def evidence(log_text: str, shallow: str = "false\n") -> lg.GitEvidence:
    return lg.GitEvidence(
        shallow=output(shallow),
        ref=output("f" * 40 + "\n"),
        remote=output("https://github.com/acme/payments-api.git\n"),
        log=output(log_text),
    )


def landing(**overrides: str):
    return lg.landing_result(lg.parse_log(log_record(**overrides))[0])


def test_parse_log_survives_awkward_subjects() -> None:
    commits = lg.parse_log(log_record(subject="fix: a | b ; c 'quoted' \"double\"") + log_record())
    assert len(commits) == 2
    assert commits[0]["subject"] == "fix: a | b ; c 'quoted' \"double\""
    assert commits[0]["parents"] == ["a" * 40]


def test_parse_log_rejects_malformed_records() -> None:
    with pytest.raises(ValueError):
        lg.parse_log("only\x1ftwo\x1e")


@pytest.mark.parametrize(
    ("subject", "number"),
    [
        ("Merge pull request #12 from acme/feature", 12),
        ("Add retry to payment client (#42)", 42),
        ("Rebased commit with no marker", None),
    ],
)
def test_pr_number(subject: str, number: int | None) -> None:
    assert lg.pr_number(subject) == number


def test_github_merge_signed_by_web_flow_is_ok() -> None:
    result = landing()
    assert result.outcome == OK
    assert result.note == "merged through GitHub from #42"


def test_expired_pre_2024_web_flow_key_still_ok() -> None:
    assert landing(signature="Y", signing_fingerprint="", signing_key="4AEE18F83AFDEB23").outcome == OK


def test_direct_push_is_exception() -> None:
    result = landing(committer_name="Alice", committer_email="alice@example.com", signature="N")
    assert result.outcome == EXCEPTION
    assert result.note.startswith("direct push")


def test_forged_github_committer_is_exception() -> None:
    # Claims GitHub as committer, but signed by someone else's key, or with a bad signature.
    assert landing(signing_fingerprint="0" * 40, signing_key="0" * 16).outcome == EXCEPTION
    assert landing(signature="B").outcome == EXCEPTION


@pytest.mark.parametrize("signature", ["E", "N", "R"])
def test_unverifiable_github_commit_needs_review(signature: str) -> None:
    assert landing(signature=signature).outcome == REVIEW


def test_evaluate_rolls_up_population() -> None:
    log = (
        log_record()
        + log_record(
            committer_name="Alice", committer_email="alice@example.com", signature="N", subject="hotfix"
        )
        + log_record(committed_at="2025-12-31T23:59:59+00:00")  # before the period
    )
    findings = {f.check_id: f for f in lg.evaluate(evidence(log), "payments-api@origin/main", PERIOD)}

    assert findings["GIT-CM-03"].status is Status.FAIL
    assert findings["GIT-CM-03"].detail.startswith("1 of 2 commits landed on the branch")
    for check_id in ("GIT-CM-01", "GIT-CM-02"):
        f = findings[check_id]
        assert f.status is Status.MANUAL_REVIEW
        assert "#42" in f.detail and "2 changes" in f.detail
        assert f.observed["manual_review"] == 2
    assert findings["GIT-CM-01"].observed["remote"] == "https://github.com/acme/payments-api.git"


def test_all_github_merges_pass_gitcm03_only() -> None:
    findings = lg.evaluate(
        evidence(log_record() + log_record(subject="Merge pull request #43 from x")), "r", PERIOD
    )
    assert [f.status for f in findings] == [Status.MANUAL_REVIEW, Status.MANUAL_REVIEW, Status.PASS]


def test_shallow_clone_is_manual_review() -> None:
    findings = lg.evaluate(evidence(log_record(), shallow="true\n"), "r", PERIOD)
    assert all(f.status is Status.MANUAL_REVIEW for f in findings)
    assert "unshallow" in findings[2].detail


def test_failed_log_is_manual_review() -> None:
    ev = lg.GitEvidence(
        output("false"), output("f" * 40), output("", 2), output("", 128, "fatal: bad object")
    )
    findings = lg.evaluate(ev, "r", PERIOD)
    assert all(f.status is Status.MANUAL_REVIEW for f in findings)
    assert "bad object" in findings[0].detail


def test_empty_period_is_manual_review() -> None:
    assert all(f.status is Status.MANUAL_REVIEW for f in lg.evaluate(evidence(""), "r", PERIOD))


# --- Connector and CLI on a real repo -------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

ALICE = {"GIT_COMMITTER_NAME": "Alice", "GIT_COMMITTER_EMAIL": "alice@example.com"}
GITHUB = {"GIT_COMMITTER_NAME": "GitHub", "GIT_COMMITTER_EMAIL": "noreply@github.com"}


def git(repo: Path, *args: str, at: str = "2026-02-01T12:00:00Z", committer: dict | None = None) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,  # ignore the developer's own config (e.g. commit.gpgsign)
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "Alice",
        "GIT_AUTHOR_EMAIL": "alice@example.com",
        "GIT_AUTHOR_DATE": at,
        "GIT_COMMITTER_DATE": at,
        **(committer or ALICE),
    }
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env, check=True)
    return proc.stdout.decode().strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """main: base (2025, direct) -> #7 squash (GitHub) -> hotfix (direct) -> merge of #8 (GitHub).

    The feature commit inside #8 is not on the first-parent chain, so it is not a landing.
    """
    r = tmp_path / "payments-api"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "commit", "-q", "--allow-empty", "-m", "base", at="2025-12-01T12:00:00Z")
    git(r, "commit", "-q", "--allow-empty", "-m", "Add retry (#7)", committer=GITHUB)
    git(r, "commit", "-q", "--allow-empty", "-m", "hotfix straight to main", at="2026-02-10T12:00:00Z")
    git(r, "checkout", "-q", "-b", "feature")
    git(r, "commit", "-q", "--allow-empty", "-m", "feature work", at="2026-02-12T12:00:00Z")
    git(r, "checkout", "-q", "main")
    git(
        r,
        "merge",
        "-q",
        "--no-ff",
        "feature",
        "-m",
        "Merge pull request #8 from acme/feature",
        at="2026-02-15T12:00:00Z",
        committer=GITHUB,
    )
    return r


def collect(repo: Path, run_dir: Path) -> lg.GitEvidence:
    gc = GitConnector(repo, run_dir)
    ref = gc.resolve("main")
    return lg.GitEvidence(
        gc.is_shallow(), ref, gc.remote_url(), gc.first_parent_log(ref.text.strip(), PERIOD.start_iso)
    )


@needs_git
def test_connector_saves_command_output_as_evidence(repo: Path, tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    ev = collect(repo, run_dir)
    assert ev.ref.ok and ev.log is not None and ev.log.ok
    assert not ev.remote.ok  # no origin; recorded, not fatal
    saved = run_dir / ev.log.evidence.file_path
    assert saved.read_text(encoding="utf-8") == ev.log.text
    assert ev.log.evidence.source_uri.startswith(f"git -C {repo.resolve()} log --first-parent")
    assert ev.log.evidence.http_status is None and ev.log.evidence.exit_code == 0

    landed = lg.parse_log(ev.log.text)
    assert [c["subject"] for c in landed] == [
        "Merge pull request #8 from acme/feature",
        "hotfix straight to main",
        "Add retry (#7)",
    ]  # 'base' is before --since; 'feature work' is not a first parent


@needs_git
def test_repo_config_cannot_make_git_run_a_program(repo: Path, tmp_path: Path) -> None:
    # A signed-looking commit makes `log --format=%G?` invoke gpg.program. Point the repo's own
    # config at a script that leaves a marker, then show the connector never runs it.
    marker = tmp_path / "pwned"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\necho x > '{marker.as_posix()}'\nexit 1\n", encoding="utf-8")
    script.chmod(0o755)
    tree = git(repo, "rev-parse", "HEAD^{tree}")
    head = git(repo, "rev-parse", "HEAD")
    body = (
        f"tree {tree}\nparent {head}\nauthor A <a@x> 1771000000 +0000\n"
        "committer GitHub <noreply@github.com> 1771000000 +0000\n"
        "gpgsig -----BEGIN PGP SIGNATURE-----\n \n iQEz\n -----END PGP SIGNATURE-----\n\nsigned\n"
    )
    proc = subprocess.run(
        ["git", "-C", str(repo), "hash-object", "-t", "commit", "-w", "--stdin"],
        input=body.encode(),
        capture_output=True,
        check=True,
    )
    git(repo, "update-ref", "refs/heads/main", proc.stdout.decode().strip())
    git(repo, "config", "gpg.program", script.as_posix())

    subprocess.run(["git", "-C", str(repo), "log", "-1", "--format=%G?"], capture_output=True, check=False)
    if not marker.exists():
        pytest.skip("this git build did not run the repo's gpg.program, so there is nothing to prove")
    marker.unlink()

    collect(repo, tmp_path / "run")
    assert not marker.exists()


@needs_git
def test_replace_refs_cannot_disguise_a_direct_push(repo: Path, tmp_path: Path) -> None:
    hotfix = git(repo, "rev-parse", "HEAD^1")
    disguised = git(
        repo,
        "commit-tree",
        f"{hotfix}^{{tree}}",
        "-p",
        f"{hotfix}^",
        "-m",
        "Looks merged (#9)",
        committer=GITHUB,
    )
    git(repo, "replace", hotfix, disguised)

    ev = collect(repo, tmp_path / "run")
    hotfix_result = next(r for r in map(lg.landing_result, lg.parse_log(ev.log.text)) if r.item == hotfix)
    assert hotfix_result.outcome == EXCEPTION


def run_cli(repo: Path, tmp_path: Path, *extra: str):
    args = [
        "check",
        "git-change-management",
        "--path",
        str(repo),
        "--ref",
        "main",
        "--period-start",
        "2026-01-01",
        "--period-end",
        "2026-03-31",
        "--out",
        str(tmp_path / "evidence"),
        "--db",
        str(tmp_path / "auditforge.db"),
        *extra,
    ]
    return runner.invoke(app, args)


@needs_git
def test_cli_end_to_end_without_network(
    repo: Path, tmp_path: Path, mock_http: responses.RequestsMock
) -> None:
    result = run_cli(repo, tmp_path)
    assert result.exit_code == 1, result.output
    assert "0 pass, 1 fail, 2 manual review" in result.output
    assert len(mock_http.calls) == 0  # no HTTP at all

    (report_path,) = (tmp_path / "evidence").glob("*/report.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["target"]["platform"] == "git"
    assert [f["check_id"] for f in report["findings"]] == ["GIT-CM-01", "GIT-CM-02", "GIT-CM-03"]
    cm03 = report["findings"][2]
    assert cm03["observed"]["exceptions"] == 1 and cm03["observed"]["manual_review"] == 2
    assert {e["file_path"] for e in report["evidence"]} == {
        "raw/ref.txt",
        "raw/shallow.txt",
        "raw/remote.txt",
        "raw/first_parent_log.txt",
    }
    assert "| exit 0 |" in (report_path.parent / "report.md").read_text(encoding="utf-8")
    assert runner.invoke(app, ["verify", str(report_path)]).exit_code == 0


@needs_git
def test_cli_unknown_ref_exits_2(repo: Path, tmp_path: Path) -> None:
    result = run_cli(repo, tmp_path, "--ref", "origin/nope")
    assert result.exit_code == 2
    assert "Could not resolve" in result.output


@needs_git
def test_cli_not_a_repo_exits_2(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run_cli(empty, tmp_path).exit_code == 2


def test_cli_rejects_option_like_ref(tmp_path: Path) -> None:
    assert run_cli(tmp_path, tmp_path, "--ref", "--output=x").exit_code == 2


def test_custom_merge_key_and_committer_for_enterprise_server() -> None:
    record = log_record(
        committer_name="GitHub Enterprise",
        committer_email="noreply@git.acme.internal",
        signing_fingerprint="0" * 24 + "ABCDEF0123456789",
        signing_key="ABCDEF0123456789",
    )
    findings = lg.evaluate(evidence(record), "r", PERIOD, ("ABCDEF0123456789",), "noreply@git.acme.internal")
    assert findings[2].status is Status.PASS
    # The same commit under github.com defaults is a direct push.
    assert lg.evaluate(evidence(record), "r", PERIOD)[2].status is Status.FAIL


@needs_git
def test_cli_records_trusted_merge_keys(repo: Path, tmp_path: Path) -> None:
    result = run_cli(repo, tmp_path, "--merge-key", "abcd ef01 2345 6789", "--merge-committer-email", "x@y")
    assert result.exit_code == 1, result.output
    (report_path,) = (tmp_path / "evidence").glob("*/report.json")
    params = json.loads(report_path.read_text(encoding="utf-8"))["parameters"]
    assert params["trusted_merge_keys"] == ["ABCDEF0123456789"]
    assert params["merge_committer_email"] == "x@y"


def test_cli_rejects_short_merge_key(tmp_path: Path) -> None:
    assert run_cli(tmp_path, tmp_path, "--merge-key", "DEADBEEF").exit_code == 2
