"""Risk register: 5x5 scoring, validation, links to controls/assets, history, CLI."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditforge.cli import app
from auditforge.mappings import Mappings
from auditforge.paths import default_mappings_dir
from auditforge.risk.cli import parse_asset, parse_control
from auditforge.risk.matrix import MatrixError, RiskMatrix
from auditforge.risk.register import AssetImpact, ControlLink, RiskError, RiskRegister
from auditforge.store import Store

runner = CliRunner()
MATRIX = RiskMatrix.load(default_mappings_dir())
DATA_LEAK = {
    "title": "Customer data leaked from production database",
    "category": "Information security",
    "owner": "Priya Shah",
    "inherent_likelihood": 4,
    "inherent_impact": 5,
    "residual_likelihood": 2,
    "residual_impact": 5,
}


@pytest.fixture
def reg(tmp_path: Path):
    store = Store(tmp_path / "auditforge.db")
    store.sync_mappings(Mappings.load(default_mappings_dir()))
    register = RiskRegister(store.conn, MATRIX)
    register.add_asset("AST-001", "Customer payments database", "data", "Priya Shah", "restricted")
    yield register
    store.close()


# --- Matrix ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("likelihood", "impact", "score", "band"),
    [(1, 1, 1, "Low"), (2, 2, 4, "Low"), (1, 5, 5, "Medium"), (3, 3, 9, "Medium"),
     (2, 5, 10, "High"), (4, 4, 16, "High"), (4, 5, 20, "Critical"), (5, 5, 25, "Critical")],
)  # fmt: skip
def test_score_and_band(likelihood: int, impact: int, score: int, band: str) -> None:
    assert MATRIX.score(likelihood, impact) == score
    assert MATRIX.band(score) == band


@pytest.mark.parametrize(("likelihood", "impact"), [(0, 3), (6, 1), (3, 0)])
def test_levels_outside_1_to_5_rejected(likelihood: int, impact: int) -> None:
    with pytest.raises(MatrixError):
        MATRIX.score(likelihood, impact)


def test_describe_uses_level_labels() -> None:
    assert MATRIX.describe(4, 5) == "4 Likely x 5 Severe = 20 Critical"


def test_matrix_must_have_five_levels(tmp_path: Path) -> None:
    (tmp_path / "risk_matrix.yaml").write_text(
        "likelihood: {1: {label: a}}\nimpact: {1: {label: a}}\nbands: [{name: Low, min: 1}]\n"
        "appetite: 9\ncategories: [X]\n",
        encoding="utf-8",
    )
    with pytest.raises(MatrixError, match="exactly levels 1-5"):
        RiskMatrix.load(tmp_path)


# --- Register -------------------------------------------------------------------------


def test_create_calculates_scores_and_assigns_id(reg: RiskRegister) -> None:
    risk = reg.create(
        DATA_LEAK, "auditor",
        assets=[AssetImpact("AST-001", ("confidentiality",))],
        controls=[ControlLink("SOC2", "CC6.1"), ControlLink("ISO27001:2022", "A.8.24")],
    )  # fmt: skip
    assert risk.risk_id == "R-001"
    assert (risk.inherent_score, risk.residual_score) == (20, 10)
    assert {(c.framework, c.control_id) for c in risk.controls} == {
        ("SOC2", "CC6.1"),
        ("ISO27001:2022", "A.8.24"),
    }
    assert risk.assets == [AssetImpact("AST-001", ("confidentiality",))]
    assert risk.updated_by == "auditor"
    assert reg.create({**DATA_LEAK, "title": "Second"}, "auditor").risk_id == "R-002"


def test_database_computes_scores_itself(reg: RiskRegister) -> None:
    reg.create(DATA_LEAK, "auditor")
    reg.conn.execute("UPDATE risks SET inherent_likelihood = 3 WHERE risk_id = 'R-001'")
    assert reg.get("R-001").inherent_score == 15
    with pytest.raises(sqlite3.OperationalError):
        reg.conn.execute("UPDATE risks SET inherent_score = 1")


def test_residual_cannot_exceed_inherent(reg: RiskRegister) -> None:
    with pytest.raises(RiskError, match="controls can only lower risk"):
        reg.create({**DATA_LEAK, "residual_likelihood": 5}, "auditor")
    # The database enforces it too, for anything that bypasses the register.
    reg.create(DATA_LEAK, "auditor")
    with pytest.raises(sqlite3.IntegrityError):
        reg.conn.execute("UPDATE risks SET residual_likelihood = 5 WHERE risk_id = 'R-001'")


def test_residual_is_assessed_as_a_pair(reg: RiskRegister) -> None:
    with pytest.raises(RiskError, match="both"):
        reg.create({**DATA_LEAK, "residual_impact": None}, "auditor")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [("category", "Weather", "Category"), ("treatment", "ignore", "Treatment"), ("status", "done", "Status"),
     ("owner", " ", "owner"), ("review_date", "31/12/2026", "review date")],
)  # fmt: skip
def test_invalid_fields_rejected(reg: RiskRegister, field: str, value: str, message: str) -> None:
    with pytest.raises(RiskError, match=message):
        reg.create({**DATA_LEAK, field: value}, "auditor")


def test_unknown_control_and_asset_rejected_without_partial_writes(reg: RiskRegister) -> None:
    with pytest.raises(RiskError, match="Unknown control SOC2 CC9.9"):
        reg.create(DATA_LEAK, "auditor", controls=[ControlLink("SOC2", "CC9.9")])
    with pytest.raises(RiskError, match="Unknown asset AST-404"):
        reg.create(DATA_LEAK, "auditor", assets=[AssetImpact("AST-404", ("integrity",))])
    assert reg.all() == []  # both creates rolled back


def test_update_changes_only_given_fields_and_rescores(reg: RiskRegister) -> None:
    reg.create(DATA_LEAK, "alice", controls=[ControlLink("SOC2", "CC6.1")])
    risk = reg.update("R-001", {"residual_likelihood": 1, "status": "monitoring"}, "bob")
    assert risk.residual_score == 5
    assert risk.status == "monitoring"
    assert risk.title == DATA_LEAK["title"]
    assert risk.controls == [ControlLink("SOC2", "CC6.1")]  # untouched when not passed
    assert risk.updated_by == "bob"
    risk = reg.update("R-001", {}, "bob", controls=[ControlLink("ISO27001:2022", "A.8.24")])
    assert risk.controls == [ControlLink("ISO27001:2022", "A.8.24")]  # replaced when passed


def test_update_validates_against_merged_values(reg: RiskRegister) -> None:
    reg.create(DATA_LEAK, "alice")
    with pytest.raises(RiskError, match="controls can only lower risk"):
        reg.update("R-001", {"inherent_likelihood": 1}, "bob")  # inherent 5 < residual 10
    assert reg.get("R-001").inherent_score == 20


def test_history_is_append_only_and_risks_cannot_be_deleted(reg: RiskRegister) -> None:
    reg.create(DATA_LEAK, "alice")
    reg.update("R-001", {"status": "assessed"}, "bob")
    reg.add_mitigation("R-001", "Encrypt backups", "Tom", "bob", due_date="2026-11-30")
    history = reg.history("R-001")
    assert [h["action"] for h in history] == ["create", "update", "mitigation_added"]
    assert history[1]["snapshot"]["status"] == "assessed"
    assert history[2]["snapshot"]["mitigations"][0]["description"] == "Encrypt backups"
    for sql in ("UPDATE risk_history SET changed_by = 'x'", "DELETE FROM risk_history", "DELETE FROM risks"):
        with pytest.raises(sqlite3.IntegrityError):
            reg.conn.execute(sql)


def test_mitigation_status(reg: RiskRegister) -> None:
    reg.create(DATA_LEAK, "alice")
    mid = reg.add_mitigation("R-001", "Encrypt backups", "Tom", "alice")
    assert reg.set_mitigation_status(mid, "implemented", "tom") == "R-001"
    assert reg.get("R-001").mitigations[0].status == "implemented"
    with pytest.raises(RiskError):
        reg.set_mitigation_status(mid, "finished", "tom")
    with pytest.raises(RiskError, match="No mitigation"):
        reg.set_mitigation_status(999, "verified", "tom")


def _record_run(conn: sqlite3.Connection, run_id: str, at: str, resource: str, status: str) -> None:
    conn.execute("INSERT INTO runs VALUES (?, ?, '0.2.0', 'ci', 'sig')", (run_id, at))
    conn.execute(
        "INSERT INTO findings VALUES (?, ?, 'GIT-CM-03', ?, ?, 'detail')",
        (run_id + "-f", run_id, resource, status),
    )
    conn.commit()


def test_control_health_is_latest_per_resource_and_flags_residual(reg: RiskRegister) -> None:
    reg.create(
        {**DATA_LEAK, "category": "Change management"}, "alice", controls=[ControlLink("SOC2", "CC8.1")]
    )
    _record_run(reg.conn, "r1", "2026-04-01T00:00:00+00:00", "payments-api@origin/main", "FAIL")
    _record_run(reg.conn, "r2", "2026-04-02T00:00:00+00:00", "other@origin/main", "PASS")
    health = reg.control_health(ControlLink("SOC2", "CC8.1"))
    assert {(h["resource"], h["status"]) for h in health} == {
        ("payments-api@origin/main", "FAIL"),  # not hidden by the newer run on another repo
        ("other@origin/main", "PASS"),
    }
    warnings = reg.residual_warnings(reg.get("R-001"))
    assert any("FAILED" in w and "SOC2 CC8.1" in w for w in warnings)

    _record_run(reg.conn, "r3", "2026-04-03T00:00:00+00:00", "payments-api@origin/main", "PASS")
    assert not any("FAILED" in w for w in reg.residual_warnings(reg.get("R-001")))


def test_accepting_above_appetite_is_flagged(reg: RiskRegister) -> None:
    risk = reg.create({**DATA_LEAK, "treatment": "accept"}, "alice")  # residual 10 > appetite 9
    assert any("above the risk appetite" in w for w in reg.residual_warnings(risk))


# --- CLI ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [("SOC2:CC6.1", ("SOC2", "CC6.1")), ("ISO27001:2022:A.8.24", ("ISO27001:2022", "A.8.24")),
     ("ISO27001:A.8.24", ("ISO27001:2022", "A.8.24")), ("NIST:CM-5", ("NIST-800-53r5", "CM-5"))],
)  # fmt: skip
def test_parse_control(value: str, expected: tuple[str, str]) -> None:
    assert parse_control(value) == ControlLink(*expected)


def test_parse_asset() -> None:
    assert parse_asset("AST-001:C,i") == AssetImpact("AST-001", ("confidentiality", "integrity"))
    with pytest.raises(RiskError):
        parse_asset("AST-001")
    with pytest.raises(RiskError):
        parse_asset("AST-001:X")


MINIMAL_ADD = ["risk", "add", "--title", "x", "--category", "Privacy", "--owner", "y"] + [
    "--likelihood", "1", "--impact", "1",
]  # fmt: skip


def cli(tmp_path: Path, *args: str):
    return runner.invoke(app, [*args, "--db", str(tmp_path / "auditforge.db")])


def test_cli_create_update_show_list(tmp_path: Path) -> None:
    assert cli(tmp_path, "asset", "add", "--id", "AST-001", "--name", "Customer DB", "--type", "data",
               "--owner", "Priya", "--classification", "restricted").exit_code == 0  # fmt: skip
    created = cli(
        tmp_path, "risk", "add", "--title", "Customer data leaked", "--category", "Information security",
        "--owner", "Priya", "--likelihood", "4", "--impact", "5", "--residual-likelihood", "2",
        "--residual-impact", "5", "--asset", "AST-001:C", "--control", "SOC2:CC6.1",
        "--control", "ISO27001:A.8.24",
    )  # fmt: skip
    assert created.exit_code == 0, created.output
    assert "Created R-001" in created.output
    assert "4 Likely x 5 Severe = 20 Critical" in created.output
    assert "2 Unlikely x 5 Severe = 10 High   (above appetite 9)" in created.output

    updated = cli(tmp_path, "risk", "update", "R-001", "--residual-likelihood", "1")
    assert updated.exit_code == 0, updated.output
    assert "Updated R-001 (residual 10 -> 5)" in updated.output

    assert cli(tmp_path, "risk", "mitigate", "R-001", "--description", "Encrypt backups",
               "--owner", "Tom", "--due", "2026-11-30").exit_code == 0  # fmt: skip
    assert "M-1 on R-001 is now verified" in cli(tmp_path, "risk", "mitigation-status", "M-1",
                                                  "--status", "verified").output  # fmt: skip

    shown = cli(tmp_path, "risk", "show", "R-001", "--history")
    assert "M-1 [verified] Encrypt backups" in shown.output
    assert "ISO27001:2022 A.8.24" in shown.output and "no automated check" in shown.output
    assert shown.output.count("inherent 20") == 4  # create, update, mitigation_added, mitigation_status

    listed = cli(tmp_path, "risk", "list")
    assert "R-001" in listed.output and "Residual risk heat map" in listed.output

    doc = json.loads(cli(tmp_path, "risk", "list", "--json").output)
    risk = doc["risks"][0]
    assert (risk["inherent_score"], risk["inherent_band"], risk["residual_score"], risk["residual_band"]) == (
        20, "Critical", 5, "Medium")  # fmt: skip
    assert doc["appetite"] == 9 and len(doc["matrix_sha256"]) == 64


@pytest.mark.parametrize(
    "args",
    [
        [*MINIMAL_ADD[:5], "Weather", *MINIMAL_ADD[6:]],  # --category Weather
        [*MINIMAL_ADD, "--control", "SOC2:CC9.9"],
        ["risk", "update", "R-404", "--status", "closed"],
        ["risk", "mitigation-status", "X-1", "--status", "verified"],
    ],
)  # fmt: skip
def test_cli_invalid_input_exits_2(tmp_path: Path, args: list[str]) -> None:
    result = cli(tmp_path, *args)
    assert result.exit_code == 2, result.output
