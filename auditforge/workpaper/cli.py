"""`auditforge exception ...` and `auditforge signoff ...`. Exit code 2 = invalid input."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Annotated

import typer

from auditforge.identity import operator
from auditforge.paths import default_mappings_dir, key_dir
from auditforge.risk.matrix import RiskMatrix
from auditforge.risk.register import RiskRegister
from auditforge.signing import PUBLIC_KEY_FILE, load_public_key
from auditforge.store import Store
from auditforge.workpaper.exceptions import ExceptionError, Exceptions
from auditforge.workpaper.signoff import ROLES, SignoffError, Signoffs

exception_app = typer.Typer(
    no_args_is_help=True, help="Approved, time-limited acceptance of failing results."
)
signoff_app = typer.Typer(no_args_is_help=True, help="Preparer and reviewer sign-off on signed reports.")

DEFAULT_DB = Path("auditforge.db")
DbOpt = Annotated[Path, typer.Option("--db", help="SQLite database")]


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(2)


def _date(value: str | None, name: str) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise _fail(f"{name} must be a date like 2027-01-31, got {value!r}") from None


def _exceptions(store: Store) -> Exceptions:
    # Risk tables must exist for the optional --risk link, even in a database without risks.
    RiskRegister(store.conn, RiskMatrix.load(default_mappings_dir()))
    return Exceptions(store.conn)


@exception_app.command("add")
def exception_add(
    check: Annotated[str, typer.Option(help="Check ID, e.g. GIT-CM-03")],
    resource: Annotated[
        str, typer.Option(help="Resource exactly as in the report, e.g. payments-api@origin/main")
    ],
    reason: Annotated[str, typer.Option(help="Why the risk is accepted, and any compensating control")],
    approved_by: Annotated[str, typer.Option(help="Who approved it (not you)")],
    expires: Annotated[str, typer.Option(help="YYYY-MM-DD, at most one year after approval")],
    approved_on: Annotated[str | None, typer.Option(help="YYYY-MM-DD (default: today)")] = None,
    risk: Annotated[str | None, typer.Option(help="Risk register entry documenting it, e.g. R-002")] = None,
    db: DbOpt = DEFAULT_DB,
) -> None:
    """Record an approved exception for a failing check on a resource."""
    with Store(db) as store:
        try:
            exc = _exceptions(store).add(
                check, resource, reason, approved_by, _date(expires, "--expires"), operator(),
                _date(approved_on, "--approved-on"), risk,
            )  # fmt: skip
        except ExceptionError as e:
            raise _fail(str(e)) from None
    typer.echo(f"Recorded {exc.describe()}")


@exception_app.command("list")
def exception_list(db: DbOpt = DEFAULT_DB) -> None:
    """List exceptions with their current state."""
    today = datetime.now(UTC).date().isoformat()
    with Store(db) as store:
        for e in _exceptions(store).all():
            state = (
                f"revoked {e.revoked_on}"
                if e.revoked_on
                else "active"
                if e.is_active_on(today)
                else "expired"
            )
            typer.echo(
                f"EXC-{e.exception_id:<4} {e.check_id:<10} {e.resource:<34} {state:<18} {e.describe()}"
            )


@exception_app.command("revoke")
def exception_revoke(
    exception: Annotated[str, typer.Argument(help="e.g. EXC-3")],
    reason: Annotated[str, typer.Option(help="Why it no longer applies")],
    db: DbOpt = DEFAULT_DB,
) -> None:
    """End an exception before it expires."""
    number = exception.upper().removeprefix("EXC-")
    if not number.isdigit():
        raise _fail(f"Exception must look like EXC-3, got {exception!r}")
    with Store(db) as store:
        try:
            exc = _exceptions(store).revoke(int(number), reason, operator())
        except ExceptionError as e:
            raise _fail(str(e)) from None
    typer.echo(f"Revoked EXC-{exc.exception_id} on {exc.revoked_on}")


def _trusted(pubkey: Path | None):
    path = pubkey or key_dir() / PUBLIC_KEY_FILE
    if not path.is_file():
        raise _fail(f"No trusted public key at {path}. Pass --pubkey with the operator's public key.")
    return load_public_key(path)


@signoff_app.command("add")
def signoff_add(
    report: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="report.json or gap-report.json")
    ],
    role: Annotated[str, typer.Option(help=" | ".join(ROLES))],
    note: Annotated[str, typer.Option(help="Review note, e.g. scope of review")] = "",
    pubkey: Annotated[Path | None, typer.Option(help="Trusted key to verify the report first")] = None,
    db: DbOpt = DEFAULT_DB,
) -> None:
    """Sign off a verified report as preparer or reviewer."""
    trusted = _trusted(pubkey)
    with Store(db) as store:
        try:
            s = Signoffs(store.conn).sign(report, role, operator(), trusted, note)
        except SignoffError as e:
            raise _fail(str(e)) from None
    typer.echo(
        f"Signed {s.run_id} as {s.role}: {s.signed_by} at {s.signed_at} (content {s.report_sha256[:16]}…)"
    )


@signoff_app.command("show")
def signoff_show(
    report: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    db: DbOpt = DEFAULT_DB,
) -> None:
    """Show who prepared and reviewed a report."""
    doc = json.loads(report.read_text(encoding="utf-8"))
    with Store(db) as store:
        rows = Signoffs(store.conn).for_report(doc["run_id"], doc["signature"]["payload_sha256"])
    if not rows:
        typer.echo(f"{doc['run_id']}: not signed off")
    for s in rows:
        typer.echo(f"{s.role:<9} {s.signed_by:<16} {s.signed_at}  {s.note}")
