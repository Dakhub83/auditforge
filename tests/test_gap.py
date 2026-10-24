"""Gap assessment: scope, attestations, decision rules, ranking/sizing, signed report, CLI."""

from __future__ import annotations

import json
import sqlite3
from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from auditforge.cli import app
from auditforge.gap.attest import Attestation, AttestationError, Attestations
from auditforge.gap.engine import ControlInput, GapMethod, MethodError, assess
from auditforge.gap.scope import Scope, ScopeError, starter_scope
from auditforge.mappings import Mappings
from auditforge.paths import default_mappings_dir
from auditforge.signing import load_public_key, verify_report
from auditforge.store import Store

runner = CliRunner()
MAPPINGS = Mappings.load(default_mappings_dir())
METHOD = GapMethod.load(default_mappings_dir())
TODAY = "2026-10-22"


def auto(status: str, at: str = "2026-10-01T00:00:00+00:00", check: str = "GIT-CM-03") -> dict[str, str]:
    return {
        "check_id": check,
        "resource": "payments-api@origin/main",
        "status": status,
        "run_id": "r1",
        "at": at,
    }


def attestation(
    result: str = "PASS", tested_on: str = "2026-10-05", valid_until: str = "2027-10-05"
) -> Attestation:
    return Attestation(
        7, "SOC2", "CC8.1", result, "Inspected change tickets", "Priya", tested_on, valid_until,
        "2026-10-05T00:00:00+00:00", "priya", None, None,
    )  # fmt: skip


def control(
    automated=(), att=None, risks=(), key=("SOC2", "CC8.1"), objectives=("CHG-REVIEW",)
) -> ControlInput:
    return ControlInput(key[0], key[1], "title", list(automated), att, list(risks), tuple(objectives))


def one(c: ControlInput):
    return assess([c], METHOD, TODAY)[0]


# --- Decision rules -------------------------------------------------------------------


def test_automated_fail_is_failing_even_with_manual_pass() -> None:
    r = one(control([auto("FAIL")], attestation("PASS")))
    assert r.status == "failing"
    assert any("does not override an automated FAIL" in x for x in r.reasons)


def test_failed_attestation_is_failing() -> None:
    assert one(control([], attestation("FAIL"))).status == "failing"


def test_valid_pass_attestation_covers() -> None:
    r = one(control([], attestation("PASS")))
    assert r.status == "covered" and r.attestation_id == 7 and r.priority is None


def test_expired_attestation_is_no_evidence_and_says_so() -> None:
    r = one(control([], attestation("PASS", "2025-01-01", "2025-12-31")))
    assert r.status == "no_evidence"
    assert any("expired 2025-12-31" in x for x in r.reasons)


def test_all_automated_pass_covers() -> None:
    assert one(control([auto("PASS"), auto("PASS", check="GIT-CM-01")])).status == "covered"


def test_manual_review_needs_a_later_attestation() -> None:
    assert one(control([auto("MANUAL_REVIEW")])).status == "needs_review"
    later = one(
        control([auto("MANUAL_REVIEW", at="2026-10-01T00:00:00+00:00")], attestation(tested_on="2026-10-05"))
    )
    assert later.status == "covered"
    earlier = one(
        control([auto("MANUAL_REVIEW", at="2026-10-09T00:00:00+00:00")], attestation(tested_on="2026-10-05"))
    )
    assert earlier.status == "needs_review"
    assert any("predates the latest run" in x for x in earlier.reasons)


def test_nothing_at_all_is_no_evidence() -> None:
    assert one(control()).status == "no_evidence"


# --- Ranking and sizing ---------------------------------------------------------------


def test_points_priority_and_effort() -> None:
    risk = {"risk_id": "R-001", "title": "Leak", "score": 15, "band": "High"}
    r = one(control([auto("FAIL")], risks=[risk], key=("SOC2", "CC6.1")))
    assert (r.points, r.priority, r.effort) == (55, "P1", "L")  # 40 failing + 15 risk
    assert one(control(key=("SOC2", "CC2.2"))).priority == "P3"  # 25 no evidence
    assert one(control([auto("MANUAL_REVIEW")], key=("SOC2", "CC6.1"))).effort == "S"  # review is always S


@pytest.mark.parametrize(
    ("key", "size"),
    [("SOC2 CC6.4", "M"), ("SOC2 CC6.1", "L"), ("ISO27001:2022 A.7.2", "M"), ("ISO27001:2022 A.6.3", "S"),
     ("SOX-ITGC ITGC-PC", "L")],
)  # fmt: skip
def test_effort_rules_first_match_wins(key: str, size: str) -> None:
    assert METHOD.effort(key, "no_evidence") == size


def test_gaps_first_by_priority_and_related_by_objective() -> None:
    results = assess(
        [
            control([], attestation("PASS"), key=("SOC2", "CC5.3"), objectives=()),
            control([auto("FAIL")], key=("SOC2", "CC8.1"), objectives=("CHG-REVIEW",)),
            control(key=("ISO27001:2022", "A.8.32"), objectives=("CHG-REVIEW",)),
        ],
        METHOD,
        TODAY,
    )
    assert [r.key for r in results] == ["SOC2 CC8.1", "ISO27001:2022 A.8.32", "SOC2 CC5.3"]
    assert results[0].related == ["ISO27001:2022 A.8.32"]


def test_method_must_define_every_gap_type(tmp_path: Path) -> None:
    (tmp_path / "gap_method.yaml").write_text(
        "gap_weights: {failing: 40}\ntiers: [{name: P1, min: 0}]\n"
        "effort: {sizes: {S: x}, review: S, default: S}\n",
        encoding="utf-8",
    )
    with pytest.raises(MethodError, match="gap_weights"):
        GapMethod.load(tmp_path)


# --- Scope ----------------------------------------------------------------------------


def write_scope(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "scope.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_scope_excludes_with_justification(tmp_path: Path) -> None:
    path = write_scope(
        tmp_path, 'frameworks: [ISO27001:2022]\nexclude:\n  "ISO27001:2022 A.7.12": Fully remote\n'
    )
    scope = Scope.load(path, MAPPINGS)
    keys = {f"{fw} {cid}" for fw, cid, _ in scope.in_scope(MAPPINGS)}
    assert len(keys) == 92 and "ISO27001:2022 A.7.12" not in keys


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ("frameworks: []\n", "at least one framework"),
        ("frameworks: [PCI]\n", "unknown framework"),
        ('frameworks: [SOC2]\nexclude:\n  "SOC2 CC6.4": ""\n', "needs a justification"),
        ('frameworks: [SOC2]\nexclude:\n  "SOC2 CC99.1": x\n', "not an in-scope catalog control"),
        ('frameworks: [SOC2]\nowners:\n  "ISO27001:2022 A.5.1": x\n', "not an in-scope catalog control"),
    ],
)
def test_invalid_scope_rejected(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(ScopeError, match=message):
        Scope.load(write_scope(tmp_path, body), MAPPINGS)


def test_starter_scope_round_trips(tmp_path: Path) -> None:
    path = write_scope(tmp_path, starter_scope(["SOC2"], MAPPINGS))
    assert len(Scope.load(path, MAPPINGS).in_scope(MAPPINGS)) == 33


# --- Attestations ---------------------------------------------------------------------


@pytest.fixture
def attest(tmp_path: Path):
    store = Store(tmp_path / "auditforge.db")
    store.sync_mappings(MAPPINGS)
    yield Attestations(store.conn)
    store.close()


def test_attestation_copies_and_hashes_evidence(attest: Attestations, tmp_path: Path) -> None:
    src = tmp_path / "policy.txt"
    src.write_text("policy v3", encoding="utf-8")
    a = attest.add("SOC2", "CC5.3", "pass", "Inspected policy", "Priya", "me", tmp_path / "evidence",
                   tested_on=date(2026, 4, 10), evidence=src)  # fmt: skip
    assert a.result == "PASS" and a.valid_until == "2027-04-10"
    stored = Path(a.evidence_path)
    assert stored.read_text(encoding="utf-8") == "policy v3" and stored.parent.name == "attestations"
    assert attest.latest("SOC2", "CC5.3") == a


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"result": "MANUAL_REVIEW"}, "PASS or FAIL"),
        ({"tested_on": date(2099, 1, 1)}, "in the future"),
        ({"tested_on": date(2026, 1, 1), "valid_until": date(2026, 1, 1)}, "after the test date"),
        ({"control_id": "CC99.9"}, "Unknown control"),
    ],
)
def test_attestation_validation(attest: Attestations, tmp_path: Path, kwargs: dict, message: str) -> None:
    args = {"framework": "SOC2", "control_id": "CC5.3", "result": "pass", "procedure": "x", "tested_by": "p",
            "recorded_by": "me", "evidence_root": tmp_path} | kwargs  # fmt: skip
    with pytest.raises(AttestationError, match=message):
        attest.add(**args)


def test_attestations_are_append_only(attest: Attestations, tmp_path: Path) -> None:
    attest.add("SOC2", "CC5.3", "pass", "x", "p", "me", tmp_path)
    for sql in ("UPDATE attestations SET result = 'FAIL'", "DELETE FROM attestations"):
        with pytest.raises(sqlite3.IntegrityError):
            attest.conn.execute(sql)


# --- CLI end to end -------------------------------------------------------------------


def cli(tmp_path: Path, *args: str):
    return runner.invoke(app, [*args, "--db", str(tmp_path / "auditforge.db")])


def test_cli_scope_attest_gap_verify(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    assert runner.invoke(app, ["scope", "init", "--framework", "SOC2", "--out", str(scope)]).exit_code == 0
    assert (
        runner.invoke(app, ["scope", "init", "--framework", "SOC2", "--out", str(scope)]).exit_code == 2
    )  # no overwrite
    evidence = tmp_path / "policy.txt"
    evidence.write_text("policy", encoding="utf-8")
    added = cli(
        tmp_path, "attest", "add", "--control", "SOC2:CC5.3", "--result", "pass", "--procedure",
        "Inspected policy", "--evidence", str(evidence), "--out", str(tmp_path / "evidence"),
    )  # fmt: skip
    assert added.exit_code == 0, added.output
    assert "Recorded A-1" in added.output

    result = cli(tmp_path, "gap", "--scope", str(scope), "--out", str(tmp_path / "gap"))
    assert result.exit_code == 0, result.output  # gaps but nothing failing
    assert "32 gap(s)" in result.output
    (report_path,) = (tmp_path / "gap").glob("*/gap-report.json")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["frameworks"]["SOC2"]["covered"] == 1
    paths = sorted(e["file_path"] for e in report["evidence"])
    assert paths[1] == "raw/scope.yaml"
    assert paths[0].startswith("raw/A-1-") and paths[0].endswith("-policy.txt")  # content-hash prefix kept
    assert (report_path.parent / "gap-report.md").read_text(encoding="utf-8").startswith("# Gap Assessment")

    home_key = Path(tmp_path / "home" / "keys" / "signing_key.pub.pem")
    assert verify_report(report_path, load_public_key(home_key)).ok

    assert cli(tmp_path, "attest", "add", "--control", "SOC2:CC7.4", "--result", "fail",
               "--procedure", "No IR tabletop").exit_code == 0  # fmt: skip
    failing = cli(tmp_path, "gap", "--scope", str(scope), "--out", str(tmp_path / "gap"))
    assert failing.exit_code == 1  # a failing control gates CI


def test_cli_gap_without_scope_explains(tmp_path: Path) -> None:
    result = cli(tmp_path, "gap", "--scope", str(tmp_path / "missing.yaml"))
    assert result.exit_code == 2 and "scope init" in result.output


def test_cli_gap_refuses_changed_attestation_evidence(tmp_path: Path) -> None:
    scope = tmp_path / "scope.yaml"
    runner.invoke(app, ["scope", "init", "--framework", "SOC2", "--out", str(scope)])
    src = tmp_path / "policy.txt"
    src.write_text("policy", encoding="utf-8")
    cli(tmp_path, "attest", "add", "--control", "SOC2:CC5.3", "--result", "pass", "--procedure", "x",
        "--evidence", str(src), "--out", str(tmp_path / "evidence"))  # fmt: skip
    (stored,) = (tmp_path / "evidence" / "attestations").iterdir()
    stored.write_text("tampered", encoding="utf-8")
    result = cli(tmp_path, "gap", "--scope", str(scope), "--out", str(tmp_path / "gap"))
    assert result.exit_code == 2 and "missing or changed" in result.output
