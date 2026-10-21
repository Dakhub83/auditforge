"""`auditforge view`: self-contained HTML built from auditforge.db and signed reports."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditforge.cli import app
from auditforge.store import Store
from tests.test_local_git import needs_git, repo, run_cli  # noqa: F401  (repo is a fixture)

runner = CliRunner()
INJECTION = "Leak </script><script>alert(1)</script>"

SMOKE_JS = Path(__file__).parent / "view_smoke.js"


def page_data(html: str) -> dict:
    payload = re.search(r"const DATA = (.*?);\nconst REG", html, re.S).group(1)
    return json.loads(payload.replace("<\\/", "</"))


def smoke(page: Path, tmp_path: Path) -> dict:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not installed")
    proc = subprocess.run([node, str(SMOKE_JS), str(page)], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_empty_database_renders_with_empty_states(tmp_path: Path) -> None:
    Store(tmp_path / "auditforge.db").close()
    out = tmp_path / "view.html"
    result = runner.invoke(app, ["view", "--db", str(tmp_path / "auditforge.db"), "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "0 risk(s), 0 run(s)" in result.output
    html = out.read_text(encoding="utf-8")
    assert "__AUDITFORGE_DATA__" not in html
    assert page_data(html)["register"]["risks"] == []
    assert smoke(out, tmp_path) == {"risks": 0, "runs": 0}


def test_missing_database_exits_2(tmp_path: Path) -> None:
    assert runner.invoke(app, ["view", "--db", str(tmp_path / "nope.db")]).exit_code == 2


@needs_git
def test_full_view_is_offline_escaped_and_verified(repo: Path, tmp_path: Path) -> None:  # noqa: F811
    assert run_cli(repo, tmp_path).exit_code == 1  # one direct push in the fixture repo -> FAIL
    db = str(tmp_path / "auditforge.db")
    created = runner.invoke(app, [
        "risk", "add", "--title", INJECTION, "--category", "Change management", "--owner", "Tom",
        "--likelihood", "4", "--impact", "4", "--residual-likelihood", "2", "--residual-impact", "4",
        "--control", "SOC2:CC8.1", "--db", db,
    ])  # fmt: skip
    assert created.exit_code == 0, created.output

    out = tmp_path / "view.html"
    result = runner.invoke(app, ["view", "--db", db, "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "1 risk(s), 1 run(s), 1 verified" in result.output

    html = out.read_text(encoding="utf-8")
    assert not re.search(r"https?://", html), "the page must not reference the network"
    assert "</script><script>alert(1)" not in html  # cannot break out of the data script
    data = page_data(html)
    risk = data["register"]["risks"][0]
    assert risk["title"] == INJECTION
    health = {h["check_id"]: h["status"] for h in risk["control_health"]["SOC2|CC8.1"]}
    assert health["GIT-CM-03"] == "FAIL"
    assert any("FAILED" in w for w in risk["warnings"])
    assert data["reports"][0]["_verify"]["ok"] is True
    assert smoke(out, tmp_path) == {"risks": 1, "runs": 1}


@needs_git
def test_tampered_run_shows_as_failed_verification(repo: Path, tmp_path: Path) -> None:  # noqa: F811
    run_cli(repo, tmp_path)
    (log,) = (tmp_path / "evidence").glob("*/raw/first_parent_log.txt")
    log.write_text("edited", encoding="utf-8")
    out = tmp_path / "view.html"
    result = runner.invoke(app, ["view", "--db", str(tmp_path / "auditforge.db"), "--out", str(out)])
    assert result.exit_code == 1
    assert "FAILED verification" in result.output
    verify = page_data(out.read_text(encoding="utf-8"))["reports"][0]["_verify"]
    assert verify["ok"] is False and "first_parent_log.txt" in verify["message"]
