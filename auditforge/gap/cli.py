"""`auditforge scope ...`, `auditforge attest ...` and `auditforge gap`.

Exit codes: gap returns 0 when no control is failing and 1 when at least one is (so CI can
gate on it); 2 means the command could not run (the message says what to fix).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import typer

from auditforge.gap import report as gap_report
from auditforge.gap.attest import AttestationError, Attestations
from auditforge.gap.engine import LABELS, GapMethod, MethodError, assess
from auditforge.gap.scope import Scope, ScopeError, starter_scope
from auditforge.identity import operator
from auditforge.mappings import MappingError, Mappings
from auditforge.paths import default_mappings_dir, key_dir
from auditforge.report import FRAMEWORK_LABELS, new_run_id
from auditforge.risk.cli import parse_control
from auditforge.risk.matrix import MatrixError, RiskMatrix
from auditforge.risk.register import RiskError
from auditforge.signing import PUBLIC_KEY_FILE, load_or_create_key
from auditforge.store import Store

scope_app = typer.Typer(no_args_is_help=True, help="Gap assessment scope (statement of applicability).")
attest_app = typer.Typer(no_args_is_help=True, help="Manual control tests, with hashed evidence.")

DEFAULT_DB = Path("auditforge.db")
DbOpt = Annotated[Path, typer.Option("--db", help="SQLite database")]
MappingsOpt = Annotated[Path | None, typer.Option("--mappings", help="Mappings directory")]


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(2)


def _mappings(mappings_dir: Path | None) -> tuple[Path, Mappings]:
    directory = mappings_dir or default_mappings_dir()
    try:
        return directory, Mappings.load(directory)
    except (MappingError, FileNotFoundError) as exc:
        raise _fail(str(exc)) from None


def _date(value: str | None, name: str) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise _fail(f"{name} must be a date like 2026-10-22, got {value!r}") from None


@scope_app.command("init")
def scope_init(
    framework: Annotated[
        list[str], typer.Option(help="Framework in scope (repeatable), e.g. SOC2, ISO27001:2022")
    ],
    out: Annotated[Path, typer.Option(help="Scope file to write")] = Path("scope.yaml"),
    force: Annotated[bool, typer.Option(help="Overwrite an existing file")] = False,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Write a starter scope.yaml listing every control in the chosen frameworks."""
    _, mappings = _mappings(mappings_dir)
    if out.exists() and not force:
        raise _fail(f"{out} already exists; pass --force to overwrite it")
    try:
        out.write_text(starter_scope(framework, mappings), encoding="utf-8")
    except ScopeError as exc:
        raise _fail(str(exc)) from None
    total = sum(len(mappings.frameworks[f]) for f in framework)
    typer.echo(
        f"Wrote {out}: {len(framework)} framework(s), {total} controls in scope. Add exclusions and owners."
    )


@attest_app.command("add")
def attest_add(
    control: Annotated[str, typer.Option(help="e.g. SOC2:CC1.1 or ISO27001:A.6.3")],
    result: Annotated[str, typer.Option(help="pass | fail")],
    procedure: Annotated[str, typer.Option(help="What was tested and how, so a reviewer can re-perform it")],
    evidence: Annotated[
        Path | None, typer.Option(help="File supporting the test (copied and hashed)")
    ] = None,
    tested_by: Annotated[str | None, typer.Option(help="Who performed the test (default: you)")] = None,
    tested_on: Annotated[str | None, typer.Option(help="Test date, YYYY-MM-DD (default: today)")] = None,
    valid_until: Annotated[
        str | None, typer.Option(help="Rely on the result until, YYYY-MM-DD (default: +1 year)")
    ] = None,
    out: Annotated[Path, typer.Option(help="Evidence folder")] = Path("evidence"),
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Record a manual test of a control."""
    _, mappings = _mappings(mappings_dir)
    try:
        link = parse_control(control)
    except RiskError as exc:
        raise _fail(str(exc)) from None
    with Store(db) as store:
        store.sync_mappings(mappings)
        try:
            a = Attestations(store.conn).add(
                link.framework, link.control_id, result, procedure, tested_by or operator(), operator(), out,
                _date(tested_on, "--tested-on"), _date(valid_until, "--valid-until"), evidence,
            )  # fmt: skip
        except AttestationError as exc:
            raise _fail(str(exc)) from None
    typer.echo(
        f"Recorded A-{a.attestation_id}: {a.framework} {a.control_id} {a.result} on {a.tested_on} "
        f"by {a.tested_by}, valid until {a.valid_until}"
        + (f"; evidence sha256 {a.evidence_sha256[:16]}…" if a.evidence_sha256 else "")
    )


@attest_app.command("list")
def attest_list(db: DbOpt = DEFAULT_DB, mappings_dir: MappingsOpt = None) -> None:
    """List all attestations, oldest first."""
    _, mappings = _mappings(mappings_dir)
    today = datetime.now(UTC).date().isoformat()
    with Store(db) as store:
        store.sync_mappings(mappings)
        for a in Attestations(store.conn).all():
            state = "valid" if a.is_valid_on(today) else "expired"
            typer.echo(
                f"A-{a.attestation_id:<4} {a.framework + ' ' + a.control_id:<26} {a.result:<5} "
                f"{a.tested_on}  "
                f"{state:<8} {a.tested_by:<16} {a.procedure}"
            )


def gap(
    scope_file: Annotated[Path, typer.Option("--scope", help="Scope file")] = Path("scope.yaml"),
    out: Annotated[Path, typer.Option(help="Directory for gap/<run_id>/")] = Path("gap"),
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Assess every in-scope control and write a signed, prioritized, effort-sized gap report."""
    directory, mappings = _mappings(mappings_dir)
    try:
        scope = Scope.load(scope_file, mappings)
        method = GapMethod.load(directory)
        matrix = RiskMatrix.load(directory)
    except (ScopeError, MethodError, MatrixError) as exc:
        raise _fail(str(exc)) from None
    today = datetime.now(UTC).date().isoformat()
    run_id = new_run_id()
    run_dir = out / run_id
    with Store(db) as store:
        store.sync_mappings(mappings)
        inputs, attestations = gap_report.collect(store.conn, scope, mappings, matrix, today)
        results = assess(inputs, method, today)
        try:
            report = gap_report.build(
                results, scope, method, mappings, attestations, run_dir, run_id, operator(), today
            )
        except ValueError as exc:
            raise _fail(str(exc)) from None
    key, created = load_or_create_key(key_dir())
    path = gap_report.write(report, run_dir, key)
    if created:
        typer.echo(
            f"Created signing key in {key_dir()}. Share {PUBLIC_KEY_FILE} with your auditor.", err=True
        )

    s = report["summary"]
    for fw, c in s["frameworks"].items():
        typer.echo(
            f"{FRAMEWORK_LABELS.get(fw, fw):<16} {c['coverage_pct']:>5}% covered  "
            + "  ".join(f"{LABELS[k].lower()} {c[k]}" for k in ("failing", "needs_review", "no_evidence"))
        )
    typer.echo(
        f"Gap report written to {path}: {s['gaps']} gap(s) ("
        + ", ".join(f"{k} {v}" for k, v in s["by_priority"].items())
        + ")"
    )
    failing = sum(c["failing"] for c in s["frameworks"].values())
    raise typer.Exit(1 if failing else 0)
