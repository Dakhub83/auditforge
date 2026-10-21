"""End-to-end: `auditforge check github-change-management` against mocked GitHub responses."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import responses
from typer.testing import CliRunner

from auditforge.cli import app
from auditforge.connectors.github import API
from tests import change_mgmt_scenario as sc

TOKEN = "github_pat_TESTTOKEN_do_not_leak"
REPO_API = f"{API}/repos/{sc.REPO}"

runner = CliRunner()


def mock_scenario(mock: responses.RequestsMock) -> None:
    mock.get(f"{REPO_API}/branches/main", json=sc.BRANCH)
    mock.get(f"{REPO_API}/pulls", json=sc.PULLS_PAGE)
    mock.get(f"{REPO_API}/commits", json=sc.COMMITS_PAGE)
    for number, head in ((101, sc.H101), (102, sc.H102), (103, sc.H103)):
        mock.get(f"{REPO_API}/pulls/{number}/reviews", json=sc.REVIEWS[number])
        mock.get(f"{REPO_API}/commits/{head}/check-runs", json=sc.CHECK_RUNS[number])
        mock.get(f"{REPO_API}/commits/{head}/status", json=sc.STATUSES[number])
    for sha, body in sc.COMMIT_PULLS.items():
        mock.get(f"{REPO_API}/commits/{sha}/pulls", json=body)


def run(tmp_path: Path, *extra: str, token: str | None = TOKEN):
    args = ["check", "github-change-management", "--repo", sc.REPO]
    args += ["--period-start", "2026-01-01", "--period-end", "2026-03-31"]
    args += ["--out", str(tmp_path / "evidence"), "--db", str(tmp_path / "auditforge.db"), *extra]
    return runner.invoke(app, args, env={"GITHUB_TOKEN": token} if token else {})


def only_report(tmp_path: Path) -> Path:
    (report,) = (tmp_path / "evidence").glob("*/report.json")
    return report


def test_full_population_run_writes_signed_verifiable_report(
    tmp_path: Path, mock_http: responses.RequestsMock
) -> None:
    mock_scenario(mock_http)
    result = run(tmp_path)
    assert result.exit_code == 1, result.output
    assert "0 pass, 3 fail, 0 manual review" in result.output

    report_path = only_report(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert (
        report["title"]
        == "Change Management Integrity Report — `acme/payments-api@main`, 2026-01-01 to 2026-03-31"
    )
    assert report["parameters"] == {"period_start": "2026-01-01", "period_end_inclusive": "2026-03-31"}
    cm01 = report["findings"][0]
    assert cm01["check_id"] == "GH-CM-01"
    assert cm01["controls"]["SOC2"] == ["CC8.1"]
    assert "AC-5" in cm01["controls"]["NIST-800-53r5"]
    assert report["findings"][1]["controls"]["NIST-800-53r5"] == ["CM-3", "SA-11"]

    # Only in-scope PRs and untraced commits were fetched: 3 list/branch + 3x3 per PR + 2 lookups.
    assert len(report["evidence"]) == 14
    raw = report_path.parent / "raw"
    assert (raw / "pulls_p1.json").is_file()
    assert (raw / "pr_102_reviews_p1.json").is_file()
    assert (raw / f"commit_{sc.D1[:12]}_pulls.json").is_file()
    assert not (raw / "pr_104_reviews_p1.json").exists()  # closed unmerged, out of scope

    md = (report_path.parent / "report.md").read_text(encoding="utf-8")
    assert md.startswith("# Change Management Integrity Report")

    verified = runner.invoke(app, ["verify", str(report_path)])
    assert verified.exit_code == 0, verified.output


def test_run_is_stored_with_multi_evidence_links(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_scenario(mock_http)
    run(tmp_path)
    conn = sqlite3.connect(tmp_path / "auditforge.db")
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status = 'FAIL'").fetchone()[0] == 3
    links = dict(
        conn.execute(
            "SELECT f.check_id, COUNT(*) FROM finding_evidence fe JOIN findings f USING (finding_id) "
            "GROUP BY f.check_id"
        ).fetchall()
    )
    conn.close()
    assert links == {"GH-CM-01": 4, "GH-CM-02": 7, "GH-CM-03": 5}


def test_only_get_requests_and_token_not_written(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_scenario(mock_http)
    result = run(tmp_path)
    assert {c.request.method for c in mock_http.calls} == {"GET"}
    assert TOKEN not in result.output
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert TOKEN.encode() not in f.read_bytes(), f


def test_missing_branch_exits_2(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(f"{REPO_API}/branches/main", json={"message": "Branch not found"}, status=404)
    result = run(tmp_path)
    assert result.exit_code == 2
    assert "not found" in result.output
    assert not (tmp_path / "auditforge.db").exists()


def test_bad_period_exits_2(tmp_path: Path) -> None:
    args = [
        "check",
        "github-change-management",
        "--repo",
        sc.REPO,
        "--period-start",
        "2026-03-31",
        "--period-end",
        "2026-01-01",
    ]
    result = runner.invoke(app, args, env={"GITHUB_TOKEN": TOKEN})
    assert result.exit_code == 2
    assert "Bad audit period" in result.output


def test_missing_token_names_the_permissions(tmp_path: Path) -> None:
    result = run(tmp_path, token=None)
    assert result.exit_code == 2
    assert "Checks" in result.output
