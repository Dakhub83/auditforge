"""AuditForge command line.

Exit codes: 0 = no FAIL findings (or report VALID), 1 = at least one FAIL
(or report INVALID), 2 = could not run (config, auth, or usage error).
"""

from __future__ import annotations

import getpass
import os
from datetime import date
from pathlib import Path
from typing import Annotated, Any

import requests
import typer

from auditforge import __version__
from auditforge.checks import change_management as cm
from auditforge.checks.branch_protection import evaluate
from auditforge.connectors.github import (
    REPO_PATTERN,
    GitHubAuthError,
    GitHubConnector,
    GitHubResponseError,
    utc_now,
)
from auditforge.mappings import MappingError, Mappings
from auditforge.models import Evidence, Finding
from auditforge.paths import default_mappings_dir, key_dir
from auditforge.report import build_report, new_run_id, write_report
from auditforge.signing import (
    PUBLIC_KEY_FILE,
    load_or_create_key,
    load_public_key,
    sign_report,
    verify_report,
)
from auditforge.store import Store

app = typer.Typer(no_args_is_help=True, add_completion=False, help="AuditForge: signed compliance evidence.")
check_app = typer.Typer(no_args_is_help=True, help="Collect evidence and run compliance checks.")
app.add_typer(check_app, name="check")


class RunError(RuntimeError):
    pass


def _operator() -> str:
    try:
        return getpass.getuser()
    except Exception:  # no login name available (some CI containers)
        return "unknown"


def run_branch_protection(
    *,
    token: str,
    repo: str,
    branch: str,
    min_approvals: int,
    out_root: Path,
    db_path: Path,
    mappings_dir: Path,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any], Path, bool]:
    """Collect, check, sign, write and store one run. Returns (report, run_dir, key_created)."""
    mappings = Mappings.load(mappings_dir)  # fail on bad mappings before touching the network
    started_at = utc_now()
    run_id = new_run_id()
    run_dir = out_root / run_id

    gh = GitHubConnector(token, run_dir, session)
    classic, rules = gh.branch_protection(repo, branch)
    if classic.status in (403, 404) and rules.status in (403, 404):
        raise RunError(f"Repo or branch not found, or token lacks access: {repo}@{branch}")
    # The rules endpoint returns 200 [] for a branch that doesn't exist, so a
    # typo would otherwise be reported as five FAILs.
    if (
        classic.status == 404
        and isinstance(classic.body, dict)
        and classic.body.get("message") == "Branch not found"
    ):
        raise RunError(f"Branch not found: {repo}@{branch}")

    findings = evaluate(classic, rules, f"{repo}@{branch}", min_approvals)
    return _finish_run(
        title=f"Branch Protection Compliance Report — `{repo}@{branch}`",
        run_id=run_id,
        run_dir=run_dir,
        started_at=started_at,
        target={"platform": "github", "repo": repo, "branch": branch},
        parameters={"min_approvals": min_approvals},
        findings=findings,
        evidence=gh.evidence,
        mappings=mappings,
        db_path=db_path,
    )


def run_change_management(
    *,
    token: str,
    repo: str,
    branch: str,
    period: cm.AuditPeriod,
    out_root: Path,
    db_path: Path,
    mappings_dir: Path,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any], Path, bool]:
    """Collect the full population of changes in the period, test each one, sign and store the run."""
    mappings = Mappings.load(mappings_dir)
    started_at = utc_now()
    run_id = new_run_id()
    run_dir = out_root / run_id
    gh = GitHubConnector(token, run_dir, session)

    branch_resp = gh.branch(repo, branch)
    if branch_resp.status == 404:
        raise RunError(f"Repo or branch not found, or token lacks access: {repo}@{branch}")
    pull_pages = gh.closed_pulls(repo, branch, since=period.start_iso)
    commit_pages = gh.branch_commits(repo, branch, since=period.start_iso)

    # The connector collects; the check module decides what is in scope, so the
    # population can be re-derived from the saved list pages.
    details: dict[int, cm.PullDetail] = {}
    for pr in cm.population(pull_pages, period):
        number, head = pr["number"], pr["head"]["sha"]
        details[number] = cm.PullDetail(
            reviews=gh.pull_reviews(repo, number),
            check_runs=gh.check_runs(repo, head, f"pr_{number}"),
            status=gh.combined_status(repo, head, f"pr_{number}"),
        )
    commit_pulls = {
        sha: gh.commit_pulls(repo, sha)
        for sha in cm.commits_to_trace(branch_resp, commit_pages, pull_pages, period)
    }

    evidence = cm.ChangeEvidence(pull_pages, details, branch_resp, commit_pages, commit_pulls)
    findings = cm.evaluate(evidence, f"{repo}@{branch}", period)
    return _finish_run(
        title=f"Change Management Integrity Report — `{repo}@{branch}`, {period.label}",
        run_id=run_id,
        run_dir=run_dir,
        started_at=started_at,
        target={"platform": "github", "repo": repo, "branch": branch},
        parameters={"period_start": period.first_day, "period_end_inclusive": period.last_day},
        findings=findings,
        evidence=gh.evidence,
        mappings=mappings,
        db_path=db_path,
    )


def _finish_run(
    *,
    title: str,
    run_id: str,
    run_dir: Path,
    started_at: str,
    target: dict[str, str],
    parameters: dict[str, Any],
    findings: list[Finding],
    evidence: list[Evidence],
    mappings: Mappings,
    db_path: Path,
) -> tuple[dict[str, Any], Path, bool]:
    """Build, sign, write and store a report. Returns (report, run_dir, key_created)."""
    report = build_report(
        title=title,
        run_id=run_id,
        started_at=started_at,
        collected_at=utc_now(),
        operator=_operator(),
        target=target,
        parameters=parameters,
        findings=findings,
        evidence=evidence,
        mappings=mappings,
    )
    key, created = load_or_create_key(key_dir())
    report["signature"] = sign_report(report, key)
    write_report(run_dir, report)
    with Store(db_path) as store:
        store.sync_mappings(mappings)
        store.record_run(report, run_dir)
    return report, run_dir, created


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(2)


@check_app.command("github-branch-protection")
def github_branch_protection(
    repo: Annotated[str, typer.Option(help="owner/repo")],
    branch: Annotated[str, typer.Option()] = "main",
    min_approvals: Annotated[int, typer.Option(min=1)] = 1,
    out: Annotated[Path, typer.Option(help="Directory for evidence/<run_id>/")] = Path("evidence"),
    db: Annotated[Path, typer.Option(help="SQLite database")] = Path("auditforge.db"),
    mappings_dir: Annotated[Path | None, typer.Option("--mappings", help="Mappings directory")] = None,
) -> None:
    """Check branch protection (classic + rulesets) and write a signed report.

    Needs GITHUB_TOKEN: a fine-grained token with read-only 'Administration' access to the repo.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise _fail("Set GITHUB_TOKEN first (fine-grained, read-only 'Administration' on the repo).")
    if not REPO_PATTERN.match(repo):
        raise _fail(f"--repo must be owner/repo, got {repo!r}")
    try:
        report, run_dir, key_created = run_branch_protection(
            token=token,
            repo=repo,
            branch=branch,
            min_approvals=min_approvals,
            out_root=out,
            db_path=db,
            mappings_dir=mappings_dir or default_mappings_dir(),
        )
    except (GitHubAuthError, RunError, MappingError) as exc:
        raise _fail(str(exc)) from None
    except requests.RequestException as exc:
        raise _fail(f"Could not reach GitHub: {type(exc).__name__}") from None
    _announce(report, run_dir, key_created)


@check_app.command("github-change-management")
def github_change_management(
    repo: Annotated[str, typer.Option(help="owner/repo")],
    period_start: Annotated[str, typer.Option(help="First day of the audit period, YYYY-MM-DD (UTC)")],
    period_end: Annotated[str, typer.Option(help="Last day of the audit period, inclusive, YYYY-MM-DD")],
    branch: Annotated[str, typer.Option()] = "main",
    out: Annotated[Path, typer.Option(help="Directory for evidence/<run_id>/")] = Path("evidence"),
    db: Annotated[Path, typer.Option(help="SQLite database")] = Path("auditforge.db"),
    mappings_dir: Annotated[Path | None, typer.Option("--mappings", help="Mappings directory")] = None,
) -> None:
    """Test every PR merged in the audit period: independent approval, CI passed, no direct pushes.

    Needs GITHUB_TOKEN: a fine-grained token with read-only 'Pull requests', 'Contents', 'Checks'
    and 'Commit statuses' access to the repo.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise _fail(
            "Set GITHUB_TOKEN first (fine-grained, read-only 'Pull requests', 'Contents', 'Checks' "
            "and 'Commit statuses' on the repo)."
        )
    if not REPO_PATTERN.match(repo):
        raise _fail(f"--repo must be owner/repo, got {repo!r}")
    try:
        period = cm.AuditPeriod.from_dates(date.fromisoformat(period_start), date.fromisoformat(period_end))
    except ValueError as exc:
        raise _fail(f"Bad audit period: {exc}") from None
    try:
        report, run_dir, key_created = run_change_management(
            token=token,
            repo=repo,
            branch=branch,
            period=period,
            out_root=out,
            db_path=db,
            mappings_dir=mappings_dir or default_mappings_dir(),
        )
    except (GitHubAuthError, GitHubResponseError, RunError, MappingError) as exc:
        raise _fail(str(exc)) from None
    except requests.RequestException as exc:
        raise _fail(f"Could not reach GitHub: {type(exc).__name__}") from None
    _announce(report, run_dir, key_created)


def _announce(report: dict[str, Any], run_dir: Path, key_created: bool) -> None:
    if key_created:
        typer.echo(
            f"Created signing key in {key_dir()}. Share {PUBLIC_KEY_FILE} with your auditor.", err=True
        )
    s = report["summary"]
    typer.echo(
        f"Report written to {run_dir}: {s['pass']} pass, {s['fail']} fail, {s['manual_review']} manual review"
    )
    raise typer.Exit(1 if s["fail"] else 0)  # non-zero lets CI gate on failures


@app.command()
def verify(
    report: Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Path to report.json")],
    pubkey: Annotated[
        Path | None, typer.Option(help="Trusted public key PEM. Defaults to your own key in AUDITFORGE_HOME.")
    ] = None,
) -> None:
    """Verify a report's signature against a trusted key and re-hash every evidence file."""
    key_path = pubkey or key_dir() / PUBLIC_KEY_FILE
    if not key_path.is_file():
        raise _fail(f"No trusted public key at {key_path}. Pass --pubkey with the operator's public key.")
    try:
        trusted = load_public_key(key_path)
    except ValueError as exc:
        raise _fail(str(exc)) from None
    result = verify_report(report, trusted)
    typer.echo(result.message)
    raise typer.Exit(0 if result.ok else 1)


@app.command()
def version() -> None:
    """Print the AuditForge version."""
    typer.echo(__version__)
