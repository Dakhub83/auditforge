"""`auditforge asset ...` and `auditforge risk ...`: maintain the local risk register.

Everything is stored in auditforge.db; nothing leaves the machine. Exit codes: 0 = done,
2 = invalid input (the message says what to fix).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Annotated, Any

import typer

from auditforge.identity import operator
from auditforge.mappings import MappingError, Mappings
from auditforge.paths import default_mappings_dir
from auditforge.risk.matrix import MatrixError, RiskMatrix
from auditforge.risk.register import (
    ASSET_TYPES,
    CIA,
    CLASSIFICATIONS,
    MITIGATION_STATUSES,
    RISK_STATUSES,
    TREATMENTS,
    AssetImpact,
    ControlLink,
    Risk,
    RiskError,
    RiskRegister,
)
from auditforge.store import Store

asset_app = typer.Typer(no_args_is_help=True, help="Assets that risks can threaten.")
risk_app = typer.Typer(no_args_is_help=True, help="Risk register: 5x5 scoring, controls, mitigations.")

# Short names accepted in --control, so "ISO27001:A.8.24" works as well as the catalog key.
FRAMEWORK_ALIASES = {
    "ISO27001": "ISO27001:2022",
    "ISO": "ISO27001:2022",
    "NIST": "NIST-800-53r5",
    "SOX": "SOX-ITGC",
}

DbOpt = Annotated[Path, typer.Option("--db", help="SQLite database")]
DEFAULT_DB = Path("auditforge.db")
MappingsOpt = Annotated[Path | None, typer.Option("--mappings", help="Mappings directory")]
Level = Annotated[int | None, typer.Option(min=1, max=5)]


@contextmanager
def open_register(db: Path, mappings_dir: Path | None) -> Iterator[RiskRegister]:
    directory = mappings_dir or default_mappings_dir()
    try:
        mappings = Mappings.load(directory)
        matrix = RiskMatrix.load(directory)
    except (MappingError, MatrixError, FileNotFoundError) as exc:
        raise _fail(str(exc)) from None
    with Store(db) as store:
        store.sync_mappings(mappings)  # risks link to the same controls catalog as checks
        yield RiskRegister(store.conn, matrix)


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(2)


def parse_asset(value: str) -> AssetImpact:
    """'AST-001:CI' or 'AST-001:C,I,A' -> the asset and the properties the risk threatens."""
    asset_id, _, letters = value.partition(":")
    flags = [c for c in letters.upper() if c not in ", "]
    if not flags or any(c not in CIA for c in flags):
        raise RiskError(f"--asset must look like AST-001:CI (C, I and/or A), got {value!r}")
    return AssetImpact(asset_id.strip(), tuple(dict.fromkeys(CIA[c] for c in flags)))


def parse_control(value: str) -> ControlLink:
    """'SOC2:CC6.1' or 'ISO27001:2022:A.8.24' -> framework and control ID."""
    framework, sep, control_id = value.rpartition(":")
    if not sep or not framework or not control_id:
        raise RiskError(f"--control must look like SOC2:CC6.1, got {value!r}")
    return ControlLink(FRAMEWORK_ALIASES.get(framework, framework), control_id)


def _links(
    asset: list[str] | None, control: list[str] | None
) -> tuple[list[AssetImpact] | None, list | None]:
    return (
        None if asset is None else [parse_asset(a) for a in asset],
        None if control is None else [parse_control(c) for c in control],
    )


# --- Formatting ---------------------------------------------------------------------------


def _rating(reg: RiskRegister, likelihood: int | None, impact: int | None) -> str:
    if likelihood is None or impact is None:
        return "not assessed"
    return reg.matrix.describe(likelihood, impact)


def render(reg: RiskRegister, risk: Risk) -> str:
    m = reg.matrix
    residual = _rating(reg, risk.residual_likelihood, risk.residual_impact)
    if risk.residual_score is not None and m.above_appetite(risk.residual_score):
        residual += f"   (above appetite {m.appetite})"
    lines = [
        f"{risk.risk_id}  {risk.title}",
        f"  Category    {risk.category}",
        f"  Owner       {risk.owner}",
        f"  Status      {risk.status}   Treatment {risk.treatment}   Review by {risk.review_date or '-'}",
        f"  Inherent    {_rating(reg, risk.inherent_likelihood, risk.inherent_impact)}",
        f"  Residual    {residual}",
    ]
    if risk.description:
        lines.append(f"  Description {risk.description}")
    names = {a["asset_id"]: a["name"] for a in reg.assets()}
    lines.append("  Assets      " + ("-" if not risk.assets else ""))
    lines += [
        f"    {a.asset_id} {names.get(a.asset_id, '')} ({', '.join(a.impact_types)})" for a in risk.assets
    ]
    lines.append("  Controls    " + ("-" if not risk.controls else ""))
    for c in risk.controls:
        name = f"{c.framework} {c.control_id}"
        health = reg.control_health(c)
        if not health:
            lines.append(f"    {name:<22} no automated check; evidence is manual")
        for i, h in enumerate(health):
            lines.append(
                f"    {name if i == 0 else '':<22} {h['status']:<14} {h['check_id']:<10} "
                f"{h['resource']} ({h['at'][:10]})"
            )
    lines.append("  Mitigations " + ("-" if not risk.mitigations else ""))
    lines += [
        f"    M-{x.mitigation_id} [{x.status}] {x.description} ({x.owner}, due {x.due_date or '-'})"
        for x in risk.mitigations
    ]
    lines += [f"  ! {w}" for w in reg.residual_warnings(risk)]
    return "\n".join(lines)


def heatmap(reg: RiskRegister, risks: list[Risk], residual: bool = True) -> str:
    counts: dict[tuple[int, int], int] = {}
    for r in risks:
        if r.status == "closed":
            continue
        li, im = (r.residual_likelihood, r.residual_impact) if residual and r.residual_score else (
            r.inherent_likelihood, r.inherent_impact)  # fmt: skip
        counts[(li, im)] = counts.get((li, im), 0) + 1
    title = "Residual" if residual else "Inherent"
    lines = [f"{title} risk heat map (open risks; residual falls back to inherent if not assessed)", ""]
    lines.append("                  Impact ->  " + "".join(f"{i:^6}" for i in range(1, 6)))
    for li in range(5, 0, -1):
        label = f"{li} {reg.matrix.likelihood[li]['label']}"
        cells = ""
        for im in range(1, 6):
            n = counts.get((li, im), 0)
            band = reg.matrix.band(li * im)[0]  # L / M / H / C
            cells += f"{(str(n) + band) if n else '.' + band.lower():^6}"
        lines.append(f"  {label:<24} {cells}")
    lines += ["", "  Cell = number of risks + band (L Low, M Medium, H High, C Critical); '.' = none"]
    return "\n".join(lines)


def _as_json(reg: RiskRegister, risk: Risk) -> dict[str, Any]:
    m = reg.matrix
    out = asdict(risk)
    out["inherent_band"] = m.band(risk.inherent_score)
    out["residual_band"] = m.band(risk.residual_score) if risk.residual_score else None
    out["warnings"] = reg.residual_warnings(risk)
    out["control_health"] = {f"{c.framework} {c.control_id}": reg.control_health(c) for c in risk.controls}
    return out


# --- Asset commands -----------------------------------------------------------------------


@asset_app.command("add")
def asset_add(
    asset_id: Annotated[str, typer.Option("--id", help="e.g. AST-001")],
    name: Annotated[str, typer.Option()],
    asset_type: Annotated[str, typer.Option("--type", help=" | ".join(ASSET_TYPES))],
    owner: Annotated[str, typer.Option()],
    classification: Annotated[str, typer.Option(help=" | ".join(CLASSIFICATIONS))],
    description: Annotated[str, typer.Option()] = "",
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Add an asset (application, data set, vendor, ...) that risks can reference."""
    with open_register(db, mappings_dir) as reg:
        try:
            reg.add_asset(asset_id, name, asset_type, owner, classification, description)
        except RiskError as exc:
            raise _fail(str(exc)) from None
    typer.echo(f"Added {asset_id} {name}")


@asset_app.command("list")
def asset_list(db: DbOpt = DEFAULT_DB, mappings_dir: MappingsOpt = None) -> None:
    """List assets."""
    with open_register(db, mappings_dir) as reg:
        for a in reg.assets():
            typer.echo(
                f"{a['asset_id']:<9} {a['name']:<34} {a['asset_type']:<15} "
                f"{a['classification']:<13} {a['owner']}"
            )


# --- Risk commands ------------------------------------------------------------------------


def _fields(**kwargs: Any) -> dict[str, Any]:
    """Only the options the user actually gave."""
    return {k: v for k, v in kwargs.items() if v is not None}


@risk_app.command("add")
def risk_add(
    title: Annotated[str, typer.Option()],
    category: Annotated[str, typer.Option(help="One of the categories in mappings/risk_matrix.yaml")],
    owner: Annotated[str, typer.Option(help="Accountable risk owner")],
    likelihood: Annotated[int, typer.Option(min=1, max=5, help="Inherent likelihood, 1-5")],
    impact: Annotated[int, typer.Option(min=1, max=5, help="Inherent impact, 1-5")],
    risk_id: Annotated[str | None, typer.Option("--id", help="e.g. R-007; default: next free ID")] = None,
    residual_likelihood: Level = None,
    residual_impact: Level = None,
    treatment: Annotated[str, typer.Option(help=" | ".join(TREATMENTS))] = "mitigate",
    status: Annotated[str, typer.Option(help=" | ".join(RISK_STATUSES))] = "identified",
    review_date: Annotated[str | None, typer.Option(help="Next review, YYYY-MM-DD")] = None,
    description: Annotated[str, typer.Option()] = "",
    asset: Annotated[list[str] | None, typer.Option(help="AST-001:CI (repeatable)")] = None,
    control: Annotated[list[str] | None, typer.Option(help="SOC2:CC6.1 (repeatable)")] = None,
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Create a risk. Scores are calculated from likelihood x impact."""
    with open_register(db, mappings_dir) as reg:
        try:
            assets, controls = _links(asset, control)
            fields = _fields(
                title=title, category=category, owner=owner, inherent_likelihood=likelihood,
                inherent_impact=impact, residual_likelihood=residual_likelihood,
                residual_impact=residual_impact, treatment=treatment, status=status,
                review_date=review_date, description=description,
            )  # fmt: skip
            risk = reg.create(fields, operator(), assets, controls, risk_id)
        except RiskError as exc:
            raise _fail(str(exc)) from None
        typer.echo(f"Created {risk.risk_id}\n" + render(reg, risk))


@risk_app.command("update")
def risk_update(
    risk_id: Annotated[str, typer.Argument(help="e.g. R-001")],
    title: Annotated[str | None, typer.Option()] = None,
    category: Annotated[str | None, typer.Option()] = None,
    owner: Annotated[str | None, typer.Option()] = None,
    likelihood: Level = None,
    impact: Level = None,
    residual_likelihood: Level = None,
    residual_impact: Level = None,
    treatment: Annotated[str | None, typer.Option(help=" | ".join(TREATMENTS))] = None,
    status: Annotated[str | None, typer.Option(help=" | ".join(RISK_STATUSES))] = None,
    review_date: Annotated[str | None, typer.Option(help="YYYY-MM-DD")] = None,
    description: Annotated[str | None, typer.Option()] = None,
    asset: Annotated[list[str] | None, typer.Option(help="Replaces all asset links (repeatable)")] = None,
    control: Annotated[list[str] | None, typer.Option(help="Replaces all control links (repeatable)")] = None,
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Change a risk. Only the options given are changed; scores are recalculated."""
    with open_register(db, mappings_dir) as reg:
        try:
            assets, controls = _links(asset, control)
            changes = _fields(
                title=title, category=category, owner=owner, inherent_likelihood=likelihood,
                inherent_impact=impact, residual_likelihood=residual_likelihood,
                residual_impact=residual_impact, treatment=treatment, status=status,
                review_date=review_date, description=description,
            )  # fmt: skip
            before = reg.get(risk_id)
            risk = reg.update(risk_id, changes, operator(), assets, controls)
        except RiskError as exc:
            raise _fail(str(exc)) from None
        moved = []
        if before.inherent_score != risk.inherent_score:
            moved.append(f"inherent {before.inherent_score} -> {risk.inherent_score}")
        if before.residual_score != risk.residual_score:
            moved.append(f"residual {before.residual_score or '-'} -> {risk.residual_score or '-'}")
        typer.echo(
            f"Updated {risk_id}" + (f" ({'; '.join(moved)})" if moved else "") + "\n" + render(reg, risk)
        )


@risk_app.command("show")
def risk_show(
    risk_id: Annotated[str, typer.Argument()],
    history: Annotated[bool, typer.Option(help="Also print the change history")] = False,
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Show one risk with its scores, assets, controls (and their latest evidence) and mitigations."""
    with open_register(db, mappings_dir) as reg:
        try:
            risk = reg.get(risk_id)
        except RiskError as exc:
            raise _fail(str(exc)) from None
        typer.echo(render(reg, risk))
        if history:
            typer.echo("  History")
            for h in reg.history(risk_id):
                s = h["snapshot"]
                typer.echo(
                    f"    {h['changed_at']}  {h['changed_by']:<12} {h['action']:<18} "
                    f"inherent {s['inherent_score']}  residual {s['residual_score'] or '-'}  "
                    f"status {s['status']}"
                )


@risk_app.command("list")
def risk_list(
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output")] = False,
    inherent: Annotated[bool, typer.Option(help="Heat map of inherent instead of residual risk")] = False,
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """List risks, highest current score first, with a 5x5 heat map."""
    with open_register(db, mappings_dir) as reg:
        risks = reg.all()
        if as_json:
            doc = {"matrix_sha256": reg.matrix.file_hash, "appetite": reg.matrix.appetite,
                   "risks": [_as_json(reg, r) for r in risks]}  # fmt: skip
            typer.echo(json.dumps(doc, indent=2, ensure_ascii=False))
            return
        m = reg.matrix
        typer.echo(
            f"{'ID':<7}{'Title':<42}{'Inherent':<15}{'Residual':<15}{'Treatment':<11}{'Status':<23}Owner"
        )
        for r in risks:
            inh = f"{r.inherent_score} {m.band(r.inherent_score)}"
            res = f"{r.residual_score} {m.band(r.residual_score)}" if r.residual_score else "-"
            flag = "!" if reg.residual_warnings(r) else " "
            title = r.title if len(r.title) <= 40 else r.title[:39] + "…"
            typer.echo(
                f"{r.risk_id:<6}{flag}{title:<42}{inh:<15}{res:<15}{r.treatment:<11}{r.status:<23}{r.owner}"
            )
        typer.echo("\n'!' = has warnings (see 'risk show')\n")
        typer.echo(heatmap(reg, risks, residual=not inherent))


@risk_app.command("mitigate")
def risk_mitigate(
    risk_id: Annotated[str, typer.Argument()],
    description: Annotated[str, typer.Option(help="What will be done")],
    owner: Annotated[str, typer.Option(help="Who is accountable for this mitigation")],
    due: Annotated[str | None, typer.Option(help="YYYY-MM-DD")] = None,
    status: Annotated[str, typer.Option(help=" | ".join(MITIGATION_STATUSES))] = "planned",
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Add a mitigation task, with an owner and status, to a risk."""
    with open_register(db, mappings_dir) as reg:
        try:
            mid = reg.add_mitigation(risk_id, description, owner, operator(), due, status)
        except RiskError as exc:
            raise _fail(str(exc)) from None
    typer.echo(f"Added M-{mid} to {risk_id}")


@risk_app.command("mitigation-status")
def risk_mitigation_status(
    mitigation: Annotated[str, typer.Argument(help="e.g. M-3")],
    status: Annotated[str, typer.Option(help=" | ".join(MITIGATION_STATUSES))],
    db: DbOpt = DEFAULT_DB,
    mappings_dir: MappingsOpt = None,
) -> None:
    """Move a mitigation to a new status (e.g. implemented, verified)."""
    number = mitigation.upper().removeprefix("M-")
    if not number.isdigit():
        raise _fail(f"Mitigation must look like M-3, got {mitigation!r}")
    with open_register(db, mappings_dir) as reg:
        try:
            risk_id = reg.set_mitigation_status(int(number), status, operator())
        except RiskError as exc:
            raise _fail(str(exc)) from None
    typer.echo(f"M-{number} on {risk_id} is now {status}")
