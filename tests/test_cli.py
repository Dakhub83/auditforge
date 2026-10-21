"""End-to-end CLI tests against recorded GitHub responses (no live calls)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
import responses
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from typer.testing import CliRunner

from auditforge.cli import app
from auditforge.connectors.github import API
from auditforge.paths import key_dir
from tests.conftest import FIXTURES

TOKEN = "github_pat_TESTTOKEN_do_not_leak"
CLASSIC_URL = f"{API}/repos/acme/payments-api/branches/main/protection"
RULES_URL = f"{API}/repos/acme/payments-api/rules/branches/main"

runner = CliRunner()


def fx(name: str) -> bytes:
    return (FIXTURES / "github" / name).read_bytes()


def mock_github(
    mock: responses.RequestsMock, classic: tuple[int, str], rules: tuple[int, str] | None
) -> None:
    mock.get(CLASSIC_URL, body=fx(classic[1]), status=classic[0])
    if rules is None:
        mock.get(RULES_URL, json=[], status=200)
    else:
        mock.get(RULES_URL, body=fx(rules[1]), status=rules[0])


def check(tmp_path: Path, *extra: str, token: str | None = TOKEN):
    env = {"GITHUB_TOKEN": token} if token else {}
    args = ["check", "github-branch-protection", "--repo", "acme/payments-api"]
    args += ["--out", str(tmp_path / "evidence"), "--db", str(tmp_path / "auditforge.db"), *extra]
    return runner.invoke(app, args, env=env)


def only_report(tmp_path: Path) -> Path:
    reports = list((tmp_path / "evidence").glob("*/report.json"))
    assert len(reports) == 1
    return reports[0]


def test_strong_protection_exits_0_and_writes_signed_report(
    tmp_path: Path, mock_http: responses.RequestsMock
) -> None:
    mock_github(mock_http, (200, "classic_strong.json"), None)
    result = check(tmp_path)
    assert result.exit_code == 0, result.output
    assert "5 pass, 0 fail, 0 manual review" in result.output

    report_path = only_report(tmp_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["schema"] == "auditforge.report/v2"
    assert set(report["mappings"]) == {"checks.yaml", "crosswalk.yaml"}
    assert report["findings"][0]["controls"]["SOC2"] == ["CC8.1"]
    assert (report_path.parent / "report.md").read_text(encoding="utf-8").count("✅ PASS") == 5
    assert (report_path.parent / "raw" / "classic_protection.json").read_bytes() == fx("classic_strong.json")


def test_weak_protection_exits_1(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (200, "classic_weak.json"), None)
    result = check(tmp_path)
    assert result.exit_code == 1
    assert "0 pass, 5 fail" in result.output


def test_run_is_stored_in_sqlite(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (200, "classic_weak.json"), None)
    check(tmp_path)
    conn = sqlite3.connect(tmp_path / "auditforge.db")
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM findings WHERE status = 'FAIL'").fetchone()[0] == 5
    assert conn.execute("SELECT COUNT(*) FROM finding_evidence").fetchone()[0] == 10
    conn.close()


def test_token_never_written_or_printed(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (200, "classic_weak.json"), None)
    result = check(tmp_path)
    assert TOKEN not in result.output
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert TOKEN.encode() not in f.read_bytes(), f


def test_verify_valid_then_tampered(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (200, "classic_weak.json"), None)
    check(tmp_path)
    report_path = only_report(tmp_path)

    ok = runner.invoke(app, ["verify", str(report_path)])
    assert ok.exit_code == 0, ok.output
    assert "VALID" in ok.output

    doc = json.loads(report_path.read_text(encoding="utf-8"))
    doc["summary"]["fail"] = 0
    report_path.write_text(json.dumps(doc), encoding="utf-8")
    bad = runner.invoke(app, ["verify", str(report_path)])
    assert bad.exit_code == 1
    assert "INVALID" in bad.output


def test_verify_with_wrong_pubkey_fails(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (200, "classic_strong.json"), None)
    check(tmp_path)
    other = tmp_path / "other.pub.pem"
    other.write_bytes(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    )
    result = runner.invoke(app, ["verify", str(only_report(tmp_path)), "--pubkey", str(other)])
    assert result.exit_code == 1
    assert "not the trusted key" in result.output


def test_verify_with_explicit_operator_pubkey(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (200, "classic_strong.json"), None)
    check(tmp_path)
    pub = key_dir() / "signing_key.pub.pem"
    result = runner.invoke(app, ["verify", str(only_report(tmp_path)), "--pubkey", str(pub)])
    assert result.exit_code == 0, result.output


def test_first_run_announces_new_key(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (200, "classic_strong.json"), None)
    assert "Created signing key" in check(tmp_path).output


def test_missing_token_exits_2(tmp_path: Path) -> None:
    result = check(tmp_path, token=None)
    assert result.exit_code == 2
    assert "GITHUB_TOKEN" in result.output


def test_bad_token_exits_2(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_http.get(CLASSIC_URL, body=fx("bad_credentials_401.json"), status=401)
    result = check(tmp_path)
    assert result.exit_code == 2
    assert "401" in result.output


def test_repo_not_found_exits_2(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (404, "not_protected_404.json"), (404, "not_protected_404.json"))
    assert check(tmp_path).exit_code == 2


def test_branch_typo_is_an_error_not_five_fails(tmp_path: Path, mock_http: responses.RequestsMock) -> None:
    mock_github(mock_http, (404, "branch_not_found_404.json"), None)
    result = check(tmp_path)
    assert result.exit_code == 2
    assert "Branch not found" in result.output
    assert not (tmp_path / "auditforge.db").exists()


def test_network_error_exits_2(tmp_path: Path) -> None:
    # Nothing is mocked, so the RequestsMock raises ConnectionError.
    result = check(tmp_path)
    assert result.exit_code == 2
    assert "Could not reach GitHub" in result.output


@pytest.mark.parametrize("repo", ["acme", "../etc"])
def test_bad_repo_exits_2(tmp_path: Path, repo: str) -> None:
    result = runner.invoke(
        app, ["check", "github-branch-protection", "--repo", repo], env={"GITHUB_TOKEN": TOKEN}
    )
    assert result.exit_code == 2


def test_verify_without_any_key_exits_2(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text("{}", encoding="utf-8")
    result = runner.invoke(app, ["verify", str(report)])
    assert result.exit_code == 2
    assert "--pubkey" in result.output
